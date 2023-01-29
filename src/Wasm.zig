//! Wasm represents the final binary
const Wasm = @This();

const std = @import("std");
const Zld = @import("Zld.zig");
const Atom = @import("Wasm/Atom.zig");
const Object = @import("Wasm/Object.zig");
const Archive = @import("Wasm/Archive.zig");
const Symbol = @import("Wasm/Symbol.zig");
const sections = @import("Wasm/sections.zig");
const types = @import("Wasm/types.zig");
pub const Options = @import("Wasm/Options.zig");
const ThreadPool = @import("ThreadPool.zig");

const leb = std.leb;
const fs = std.fs;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const mem = std.mem;

const log = std.log.scoped(.wasm);

base: Zld,
/// Configuration of the linker provided by the user
options: Options,
/// A list with references to objects we link to during `flush()`
objects: std.ArrayListUnmanaged(Object) = .{},
/// A list of archive files which are lazily linked with the final binary.
/// Referencing a Symbol from any of its object files will cause the object
/// file to be linked into the final binary.
archives: std.ArrayListUnmanaged(Archive) = .{},
/// A map of global names to their symbol location in an object file
global_symbols: std.AutoHashMapUnmanaged(u32, SymbolWithLoc) = .{},
/// Contains all atoms that have been created, used to clean up
managed_atoms: std.ArrayListUnmanaged(*Atom) = .{},
/// Maps atoms to their segment index
atoms: std.AutoHashMapUnmanaged(u32, *Atom) = .{},
/// Maps a symbol's location to an atom. This can be used to find meta
/// data of a symbol, such as its size, or its offset to perform a relocation.
/// Undefined (and synthetic) symbols do not have an Atom and therefore cannot be mapped.
symbol_atom: std.AutoHashMapUnmanaged(SymbolWithLoc, *Atom) = .{},
/// All symbols created by the linker, rather than through
/// object files will be inserted in this list to manage them.
synthetic_symbols: std.StringArrayHashMapUnmanaged(Symbol) = .{},
/// List of all symbol locations which have been resolved by the linker
/// and will be emit into the final binary.
resolved_symbols: std.AutoArrayHashMapUnmanaged(SymbolWithLoc, void) = .{},
/// Maps discarded symbols and their positions to the location of the symbol
/// it was resolved to.
discarded: std.AutoHashMapUnmanaged(SymbolWithLoc, SymbolWithLoc) = .{},
/// Symbols that remain undefined after symbol resolution.
undefs: std.StringArrayHashMapUnmanaged(SymbolWithLoc) = .{},

/// String table, used to deduplicate all symbol names
string_table: StringTable = .{},

// OUTPUT SECTIONS //
/// Output function signature types
func_types: sections.Types = .{},
/// Output import section
imports: sections.Imports = .{},
/// Output function section
functions: sections.Functions = .{},
/// Output table section
tables: sections.Tables = .{},
/// Output memory section, this will only be used when `options.import_memory`
/// is set to false. The limits will be set, based on the total data section size
/// and other configuration options.
memories: types.Memory = .{ .limits = .{
    .flags = 0,
    .min = 0,
    .max = null,
} },
/// Output global section
globals: sections.Globals = .{},
/// Output export section
exports: sections.Exports = .{},
/// Output element section
elements: sections.Elements = .{},
/// Features which are used by the resulting binary
used_features: FeatureSet = .{},
/// Index to a function defining the entry of the wasm file
entry: ?u32 = null,
/// Output data section, keyed by the segment name
/// Represents non-synthetic section entries
/// Used for code, data and custom sections.
segments: std.ArrayListUnmanaged(Segment) = .{},
/// Maps a data segment key (such as .rodata) to the index into `segments`
data_segments: std.StringArrayHashMapUnmanaged(u32) = .{},

/// Index into `atoms` that represents the code section
code_section_index: ?u32 = null,
/// The index of the segment representing the custom '.debug_info' section.
debug_info_index: ?u32 = null,
/// The index of the segment representing the custom '.debug_line' section.
debug_line_index: ?u32 = null,
/// The index of the segment representing the custom '.debug_loc' section.
debug_loc_index: ?u32 = null,
/// The index of the segment representing the custom '.debug_ranges' section.
debug_ranges_index: ?u32 = null,
/// The index of the segment representing the custom '.debug_pubnames' section.
debug_pubnames_index: ?u32 = null,
/// The index of the segment representing the custom '.debug_pubtypes' section.
debug_pubtypes_index: ?u32 = null,
/// The index of the segment representing the custom '.debug_pubtypes' section.
debug_str_index: ?u32 = null,
/// The index of the segment representing the custom '.debug_pubtypes' section.
debug_abbrev_index: ?u32 = null,

/// List of initialization functions, these must be called in order of priority
/// by the synthetic __wasm_call_ctors function.
init_funcs: std.ArrayListUnmanaged(InitFuncLoc) = .{},

pub const Segment = struct {
    alignment: u32,
    size: u32,
    offset: u32,
    flags: u32,

    pub const Flag = enum(u32) {
        WASM_DATA_SEGMENT_IS_PASSIVE = 0x01,
        WASM_DATA_SEGMENT_HAS_MEMINDEX = 0x02,
    };

    /// For a given segment, determines if it needs passive initialization
    fn needsPassiveInitialization(segment: Segment, import_mem: bool, name: []const u8) bool {
        if (import_mem and !std.mem.eql(u8, name, ".bss")) {
            return true;
        }
        return segment.isPassive();
    }

    pub inline fn isPassive(segment: Segment) bool {
        return segment.flags & @enumToInt(Flag.WASM_DATA_SEGMENT_IS_PASSIVE) != 0;
    }
};

/// Contains the location of the function symbol, as well as
/// the priority itself of the initialization function.
pub const InitFuncLoc = struct {
    file: u16,
    index: u32,
    priority: u32,

    /// From a given `InitFuncLoc` returns the corresponding function symbol
    pub fn getSymbol(loc: InitFuncLoc, wasm: *const Wasm) *Symbol {
        return getSymbolLoc(loc).getSymbol(wasm);
    }

    /// Turns the given `InitFuncLoc` into a `SymbolWithLoc`
    pub fn getSymbolLoc(loc: InitFuncLoc) SymbolWithLoc {
        return .{ .file = loc.file, .sym_index = loc.index };
    }
};

/// Describes the location of a symbol
pub const SymbolWithLoc = struct {
    /// Symbol entry index within the object/binary file
    sym_index: u32,
    /// When file is `null`, this symbol refers to a synthetic symbol.
    file: ?u16,

    /// From a given location, find the corresponding symbol in the wasm binary.
    pub fn getSymbol(loc: SymbolWithLoc, wasm: *const Wasm) *Symbol {
        if (wasm.discarded.get(loc)) |new_loc| return new_loc.getSymbol(wasm);

        if (loc.file) |file_index| {
            const object = wasm.objects.items[file_index];
            return &object.symtable[loc.sym_index];
        }
        return &wasm.synthetic_symbols.values()[loc.sym_index];
    }

    /// From a given location, returns the name of the symbol.
    pub fn getName(loc: SymbolWithLoc, wasm_bin: *const Wasm) []const u8 {
        if (wasm_bin.discarded.get(loc)) |new_loc| {
            return new_loc.getName(wasm_bin);
        }
        if (loc.file) |object_index| {
            const object: Object = wasm_bin.objects.items[object_index];
            return object.string_table.get(object.symtable[loc.sym_index].name);
        }
        return wasm_bin.string_table.get(wasm_bin.synthetic_symbols.values()[loc.sym_index].name);
    }

    /// From a given symbol location, returns the final location.
    /// e.g. when a symbol was resolved and replaced by the symbol
    /// in a different file, this will return said location.
    /// If the symbol wasn't replaced by another, this will return
    /// the given location itwasm.
    pub fn finalLoc(loc: SymbolWithLoc, wasm_bin: *const Wasm) SymbolWithLoc {
        if (wasm_bin.discarded.get(loc)) |new_loc| {
            return new_loc.finalLoc(wasm_bin);
        }
        return loc;
    }
};

const FeatureSet = struct {
    set: SetType = .{ .mask = 0 }, // everything disabled by default

    const SetType = std.bit_set.IntegerBitSet(types.known_features.kvs.len);

    const Iterator = struct {
        /// The iterator that will return the index of the next feature
        /// This should never be used directly, unless the index of a feature
        /// is required directly.
        inner: SetType.Iterator(.{}),

        /// Returns the next feature in the set
        pub fn next(it: *Iterator) ?types.Feature.Tag {
            const index = it.inner.next() orelse return null;
            return @intToEnum(types.Feature.Tag, index);
        }
    };

    /// Returns true when a given `feature` is enabled
    pub fn isEnabled(set: FeatureSet, feature: types.Feature.Tag) bool {
        return set.set.isSet(@enumToInt(feature));
    }

    /// Enables the given `feature`
    pub fn enable(set: *FeatureSet, feature: types.Feature.Tag) void {
        set.set.set(@enumToInt(feature));
    }

    /// The amount of features that have been set
    pub fn count(set: FeatureSet) u32 {
        return @intCast(u32, set.set.count());
    }

    /// Returns an iterator through the features in the set by its index
    pub fn iterator(set: *const FeatureSet) Iterator {
        return .{ .inner = set.set.iterator(.{}) };
    }
};

/// Initializes a new wasm binary file at the given path.
/// Will overwrite any existing file at said path.
pub fn openPath(gpa: Allocator, options: Options, thread_pool: *ThreadPool) !*Wasm {
    const file = try options.emit.directory.createFile(options.emit.sub_path, .{
        .truncate = true,
        .read = true,
    });
    errdefer file.close();

    const wasm = try createEmpty(gpa, options, thread_pool);
    errdefer gpa.destroy(wasm);
    wasm.base.file = file;
    return wasm;
}

fn createEmpty(gpa: Allocator, options: Options, thread_pool: *ThreadPool) !*Wasm {
    const wasm = try gpa.create(Wasm);
    wasm.* = .{
        .base = .{
            .tag = .wasm,
            .allocator = gpa,
            .file = undefined,
            .thread_pool = thread_pool,
        },
        .options = options,
    };
    return wasm;
}

/// Releases any resources that is owned by `Wasm`,
/// usage after calling deinit is illegal behaviour.
pub fn deinit(wasm: *Wasm) void {
    const gpa = wasm.base.allocator;
    for (wasm.objects.items) |*object| {
        object.deinit(gpa);
    }
    for (wasm.archives.items) |*archive| {
        archive.deinit(gpa);
    }
    for (wasm.managed_atoms.items) |atom| {
        atom.deinit(gpa);
    }
    wasm.synthetic_symbols.deinit(gpa);
    wasm.symbol_atom.deinit(gpa);
    wasm.discarded.deinit(gpa);
    wasm.resolved_symbols.deinit(gpa);
    wasm.managed_atoms.deinit(gpa);
    wasm.atoms.deinit(gpa);
    wasm.data_segments.deinit(gpa);
    wasm.segments.deinit(gpa);
    wasm.global_symbols.deinit(gpa);
    wasm.objects.deinit(gpa);
    wasm.archives.deinit(gpa);
    wasm.functions.deinit(gpa);
    wasm.func_types.deinit(gpa);
    wasm.imports.deinit(gpa);
    wasm.globals.deinit(gpa);
    wasm.exports.deinit(gpa);
    wasm.elements.deinit(gpa);
    wasm.tables.deinit(gpa);
    wasm.string_table.deinit(gpa);
    wasm.undefs.deinit(gpa);
}

fn hasPassiveInitializationSegments(wasm: *const Wasm) bool {
    var it = wasm.data_segments.iterator();
    while (it.next()) |entry| {
        const segment: Segment = wasm.segments.items[entry.value_ptr.*];
        if (segment.needsPassiveInitialization(wasm.options.import_memory, entry.key_ptr.*)) {
            return true;
        }
    }
    return false;
}

pub fn closeFiles(wasm: *const Wasm) void {
    _ = wasm;
}

fn parsePositionals(wasm: *Wasm, files: []const []const u8) !void {
    for (files) |path| {
        if (try wasm.parseObjectFile(wasm.base.allocator, path)) continue;
        if (try wasm.parseArchive(wasm.base.allocator, path, false)) continue; // load archives lazily
        log.warn("Unexpected file format at path: '{s}'", .{path});
    }
}

/// Attempts to parse an object file. Returns `false` when given path
/// does not represent an object file.
fn parseObjectFile(wasm: *Wasm, gpa: Allocator, path: []const u8) !bool {
    const file = try fs.cwd().openFile(path, .{});
    var object = Object.create(gpa, file, path, null) catch |err| switch (err) {
        error.InvalidMagicByte, error.NotObjectFile => {
            return false;
        },
        else => |e| return e,
    };
    errdefer object.deinit(gpa);
    try wasm.objects.append(gpa, object);
    return true;
}

/// Parses an archive file and will then parse each object file
/// that was found in the archive file.
/// Returns false when the file is not an archive file.
/// May return an error instead when parsing failed.
///
/// When `force_load` is `true`, it will for link all object files in the archive.
/// When false, it will only link with object files that contain symbols that
/// are referenced by other object files or Zig code.
fn parseArchive(wasm: *Wasm, gpa: Allocator, path: []const u8, force_load: bool) !bool {
    const file = try fs.cwd().openFile(path, .{});
    errdefer file.close();

    var archive: Archive = .{
        .file = file,
        .name = path,
    };
    archive.parse(gpa) catch |err| switch (err) {
        error.EndOfStream, error.NotArchive => {
            archive.deinit(gpa);
            return false;
        },
        else => |e| return e,
    };

    if (!force_load) {
        errdefer archive.deinit(gpa);
        try wasm.archives.append(gpa, archive);
        return true;
    }
    defer archive.deinit(gpa);

    // In this case we must force link all embedded object files within the archive
    // We loop over all symbols, and then group them by offset as the offset
    // notates where the object file starts.
    var offsets = std.AutoArrayHashMap(u32, void).init(gpa);
    defer offsets.deinit();
    for (archive.toc.values()) |symbol_offsets| {
        for (symbol_offsets.items) |sym_offset| {
            try offsets.put(sym_offset, {});
        }
    }

    for (offsets.keys()) |file_offset| {
        const object = try wasm.objects.addOne(gpa);
        object.* = try archive.parseObject(gpa, file_offset);
    }

    return true;
}

/// Returns the data section entry count, skipping the .bss section
pub fn dataCount(wasm: Wasm) u32 {
    var i: u32 = 0;
    for (wasm.data_segments.keys()) |key| {
        if (std.mem.eql(u8, key, ".bss") and !wasm.options.import_memory) continue;
        i += 1;
    }
    return i;
}

/// Flushes the `Wasm` construct into a final wasm binary by linking
/// the objects, ensuring the final binary file has no collisions.
pub fn flush(wasm: *Wasm) !void {
    try wasm.parsePositionals(wasm.options.positionals);
    try wasm.setupLinkerSymbols();
    for (wasm.objects.items) |_, obj_idx| {
        try wasm.resolveSymbolsInObject(@intCast(u16, obj_idx));
    }
    try wasm.resolveSymbolsInArchives();
    try wasm.resolveLazySymbols();
    try wasm.setupInitFunctions();
    try wasm.checkUndefinedSymbols();
    for (wasm.objects.items) |*object, obj_idx| {
        try object.parseIntoAtoms(@intCast(u16, obj_idx), wasm);
    }
    try wasm.validateFeatures();
    try wasm.setupInitMemoryFunction();
    try wasm.setupTLSRelocationsFunction();
    try wasm.setupStart();
    try wasm.mergeImports();
    try wasm.allocateAtoms();
    try wasm.setupMemory();
    wasm.mapFunctionTable();
    try wasm.mergeSections();
    try wasm.mergeTypes();
    try wasm.initializeCallCtorsFunction();
    try wasm.initializeTLSFunction();
    try wasm.setupExports();

    try @import("Wasm/emit_wasm.zig").emit(wasm);
}

/// Generic string table that duplicates strings
/// and converts them into offsets instead.
pub const StringTable = struct {
    /// Table that maps string offsets, which is used to de-duplicate strings.
    /// Rather than having the offset map to the data, the `StringContext` holds all bytes of the string.
    /// The strings are stored as a contigious array where each string is zero-terminated.
    string_table: std.HashMapUnmanaged(
        u32,
        void,
        std.hash_map.StringIndexContext,
        std.hash_map.default_max_load_percentage,
    ) = .{},
    /// Holds the actual data of the string table.
    string_data: std.ArrayListUnmanaged(u8) = .{},

    /// Accepts a string and searches for a corresponding string.
    /// When found, de-duplicates the string and returns the existing offset instead.
    /// When the string is not found in the `string_table`, a new entry will be inserted
    /// and the new offset to its data will be returned.
    pub fn put(table: *StringTable, allocator: Allocator, string: []const u8) !u32 {
        const gop = try table.string_table.getOrPutContextAdapted(
            allocator,
            string,
            std.hash_map.StringIndexAdapter{ .bytes = &table.string_data },
            .{ .bytes = &table.string_data },
        );
        if (gop.found_existing) {
            const off = gop.key_ptr.*;
            log.debug("reusing string '{s}' at offset 0x{x}", .{ string, off });
            return off;
        }

        try table.string_data.ensureUnusedCapacity(allocator, string.len + 1);
        const offset = @intCast(u32, table.string_data.items.len);

        log.debug("writing new string '{s}' at offset 0x{x}", .{ string, offset });

        table.string_data.appendSliceAssumeCapacity(string);
        table.string_data.appendAssumeCapacity(0);

        gop.key_ptr.* = offset;

        return offset;
    }

    /// From a given offset, returns its corresponding string value.
    /// Asserts offset does not exceed bounds.
    pub fn get(table: StringTable, off: u32) []const u8 {
        assert(off < table.string_data.items.len);
        return mem.sliceTo(@ptrCast([*:0]const u8, table.string_data.items.ptr + off), 0);
    }

    /// Returns the offset of a given string when it exists.
    /// Will return null if the given string does not yet exist within the string table.
    pub fn getOffset(table: *StringTable, string: []const u8) ?u32 {
        return table.string_table.getKeyAdapted(
            string,
            std.hash_map.StringIndexAdapter{ .bytes = &table.string_data },
        );
    }

    /// Frees all resources of the string table. Any references pointing
    /// to the strings will be invalid.
    pub fn deinit(table: *StringTable, allocator: Allocator) void {
        table.string_data.deinit(allocator);
        table.string_table.deinit(allocator);
        table.* = undefined;
    }
};

fn resolveSymbolsInObject(wasm: *Wasm, object_index: u16) !void {
    const object: Object = wasm.objects.items[object_index];
    log.debug("Resolving symbols in object: '{s}'", .{object.name});

    for (object.symtable) |symbol, i| {
        const sym_index = @intCast(u32, i);
        const location: SymbolWithLoc = .{
            .file = object_index,
            .sym_index = sym_index,
        };
        const sym_name = object.string_table.get(symbol.name);
        const sym_name_index = try wasm.string_table.put(wasm.base.allocator, sym_name);

        if (symbol.isLocal()) {
            if (symbol.isUndefined()) {
                log.err("Local symbols are not allowed to reference imports", .{});
                log.err("  symbol '{s}' defined in '{s}'", .{ sym_name, object.name });
                return error.UndefinedLocal;
            }
            try wasm.resolved_symbols.putNoClobber(wasm.base.allocator, location, {});
            continue;
        }

        const maybe_existing = try wasm.global_symbols.getOrPut(wasm.base.allocator, sym_name_index);
        if (!maybe_existing.found_existing) {
            maybe_existing.value_ptr.* = location;
            try wasm.resolved_symbols.putNoClobber(wasm.base.allocator, location, {});

            if (symbol.isUndefined()) {
                try wasm.undefs.putNoClobber(wasm.base.allocator, sym_name, location);
            }
            continue;
        }

        const existing_loc = maybe_existing.value_ptr.*;
        const existing_sym: *Symbol = existing_loc.getSymbol(wasm);

        const existing_file_path = if (existing_loc.file) |file| blk: {
            break :blk wasm.objects.items[file].name;
        } else wasm.options.emit.sub_path;

        if (!existing_sym.isUndefined()) outer: {
            if (!symbol.isUndefined()) inner: {
                if (symbol.isWeak()) {
                    break :inner; // ignore the new symbol (discard it)
                }
                if (existing_sym.isWeak()) {
                    break :outer; // existing is weak, while new one isn't. Replace it.
                }
                // both are defined and weak, we have a symbol collision.
                log.err("symbol '{s}' defined multiple times", .{sym_name});
                log.err("  first definition in '{s}'", .{existing_file_path});
                log.err("  next definition in '{s}'", .{object.name});
                return error.SymbolCollision;
            }

            try wasm.discarded.put(wasm.base.allocator, location, existing_loc);
            continue; // Do not overwrite defined symbols with undefined symbols
        }

        if (symbol.tag != existing_sym.tag) {
            log.err("symbol '{s}' mismatching type '{s}", .{ sym_name, @tagName(symbol.tag) });
            log.err("  first definition in '{s}'", .{existing_file_path});
            log.err("  next definition in '{s}'", .{object.name});
            return error.SymbolMismatchingType;
        }

        // only verify module/import name for function symbols
        if (existing_sym.isUndefined() and symbol.isUndefined()) {
            if (symbol.tag == .function) {
                const file_index = existing_loc.file.?;
                const obj = wasm.objects.items[file_index];
                const name_index = obj.findImport(symbol.tag.externalType(), existing_sym.index).module_name;
                const existing_name = obj.string_table.get(name_index);

                const module_index = object.findImport(symbol.tag.externalType(), symbol.index).module_name;
                const module_name = object.string_table.get(module_index);
                if (!mem.eql(u8, existing_name, module_name)) {
                    log.err("symbol '{s}' module name mismatch. Expected '{s}', but found '{s}'", .{
                        sym_name,
                        existing_name,
                        module_name,
                    });
                    log.err("  first definition in '{s}'", .{existing_file_path});
                    log.err("  next definition in '{s}'", .{object.name});
                    return error.ModuleNameMismatch;
                }
            }

            try wasm.discarded.put(wasm.base.allocator, location, existing_loc);
            continue; // both undefined so skip overwriting existing symbol and discard the new symbol
        }

        if (existing_sym.tag == .global) {
            const existing_ty = wasm.getGlobalType(existing_loc);
            const new_ty = wasm.getGlobalType(location);
            if (existing_ty.mutable != new_ty.mutable or existing_ty.valtype != new_ty.valtype) {
                log.err("symbol '{s}' mismatching global types", .{sym_name});
                log.err("  first definition in '{s}'", .{existing_file_path});
                log.err("  next definition in '{s}'", .{object.name});
                return error.GlobalTypeMismatch;
            }
        }

        if (existing_sym.tag == .function) {
            const existing_ty = wasm.getFunctionSignature(existing_loc);
            const new_ty = wasm.getFunctionSignature(location);
            if (!existing_ty.eql(new_ty)) {
                log.err("symbol '{s}' mismatching function signatures.", .{sym_name});
                log.err("  expected signature {}, but found signature {}", .{ existing_ty, new_ty });
                log.err("  first definition in '{s}'", .{existing_file_path});
                log.err("  next definition in '{s}'", .{object.name});
                return error.FunctionSignatureMismatch;
            }
        }

        // when both symbols are weak, we skip overwriting unless the existing
        // symbol is weak and the new one isn't, in which case we *do* overwrite it.
        if (existing_sym.isWeak() and symbol.isWeak()) blk: {
            if (existing_sym.isUndefined() and !symbol.isUndefined()) break :blk;
            try wasm.discarded.put(wasm.base.allocator, location, existing_loc);
            continue;
        }

        // simply overwrite with the new symbol
        log.debug("Overwriting symbol '{s}'", .{sym_name});
        log.debug("  old definition in '{s}'", .{existing_file_path});
        log.debug("  new definition in '{s}'", .{object.name});
        try wasm.discarded.putNoClobber(wasm.base.allocator, existing_loc, location);
        maybe_existing.value_ptr.* = location;
        try wasm.global_symbols.put(wasm.base.allocator, sym_name_index, location);
        try wasm.resolved_symbols.put(wasm.base.allocator, location, {});
        assert(wasm.resolved_symbols.swapRemove(existing_loc));
        if (existing_sym.isUndefined()) {
            _ = wasm.undefs.swapRemove(sym_name);
        }
    }
}

/// Resolves the symbols in each archive file.
/// When resolved to a symbol from an object file,
/// this will result into loading the object file within
/// the archive file and linking with it.
fn resolveSymbolsInArchives(wasm: *Wasm) !void {
    if (wasm.archives.items.len == 0) return;

    log.debug("Resolving symbols in archives", .{});
    var index: u32 = 0;
    undef_loop: while (index < wasm.undefs.count()) {
        const sym_name = wasm.undefs.keys()[index];

        for (wasm.archives.items) |archive| {
            const offset = archive.toc.get(sym_name) orelse {
                // symbol does not exist in this archive
                continue;
            };

            log.debug("Detected symbol '{s}' in archive '{s}', parsing objects..", .{ sym_name, archive.name });
            // Symbol is found in unparsed object file within current archive.
            // Parse object and and resolve symbols again before we check remaining
            // undefined symbols.
            const object_file_index = @intCast(u16, wasm.objects.items.len);
            var object = try archive.parseObject(wasm.base.allocator, offset.items[0]);
            try wasm.objects.append(wasm.base.allocator, object);
            try wasm.resolveSymbolsInObject(object_file_index);

            // continue loop for any remaining undefined symbols that still exist
            // after resolving last object file
            continue :undef_loop;
        }
        index += 1;
    }
}

/// Creates synthetic linker-symbols, but only if they are being referenced from
/// any object file. For instance, the `__heap_base` symbol will only be created,
/// if one or multiple undefined references exist. When none exist, the symbol will
/// not be created, ensuring we don't unneccesarily emit unreferenced symbols.
fn resolveLazySymbols(wasm: *Wasm) !void {
    if (wasm.undefs.fetchSwapRemove("__heap_base")) |kv| {
        const loc = try wasm.createSyntheticSymbol("__heap_base", .data);
        try wasm.discarded.putNoClobber(wasm.base.allocator, kv.value, loc);
        _ = wasm.resolved_symbols.swapRemove(loc); // we don't want to emit this symbol, only use it for relocations.

        const atom = try Atom.create(wasm.base.allocator);
        atom.size = 0;
        atom.sym_index = loc.sym_index;
        atom.file = null;
        // va/offset will be set during `setupMemory`
        try wasm.symbol_atom.put(wasm.base.allocator, loc, atom);
    }

    if (wasm.undefs.fetchSwapRemove("__heap_end")) |kv| {
        const loc = try wasm.createSyntheticSymbol("__heap_end", .data);
        try wasm.discarded.putNoClobber(wasm.base.allocator, kv.value, loc);
        _ = wasm.resolved_symbols.swapRemove(loc);

        const atom = try Atom.create(wasm.base.allocator);
        atom.size = 0;
        atom.sym_index = loc.sym_index;
        atom.file = null;
        try wasm.symbol_atom.put(wasm.base.allocator, loc, atom);
    }

    if (!wasm.options.shared_memory) {
        if (wasm.undefs.fetchSwapRemove("__tls_base")) |kv| {
            const loc = try wasm.createSyntheticSymbol("__tls_base", .global);
            try wasm.discarded.putNoClobber(wasm.base.allocator, kv.value, loc);
        }
    }
}

/// From a given symbol location, returns its `wasm.GlobalType`.
/// Asserts the Symbol represents a global.
fn getGlobalType(wasm: *const Wasm, loc: SymbolWithLoc) std.wasm.GlobalType {
    const symbol = loc.getSymbol(wasm);
    assert(symbol.tag == .global);
    const is_undefined = symbol.isUndefined();
    if (loc.file) |file_index| {
        const obj: Object = wasm.objects.items[file_index];
        if (is_undefined) {
            return obj.findImport(.global, symbol.index).kind.global;
        }
        const import_global_count = obj.importedCountByKind(.global);
        return obj.globals[symbol.index - import_global_count].global_type;
    }
    assert(!is_undefined);
    return wasm.globals.items.items[symbol.index].global_type;
}

/// From a given symbol location, returns its `wasm.Type`.
/// Asserts the Symbol represents a function.
fn getFunctionSignature(wasm: *const Wasm, loc: SymbolWithLoc) std.wasm.Type {
    const symbol = loc.getSymbol(wasm);
    assert(symbol.tag == .function);
    const is_undefined = symbol.isUndefined();
    if (loc.file) |file_index| {
        const obj: Object = wasm.objects.items[file_index];
        if (is_undefined) {
            const ty_index = obj.findImport(.function, symbol.index).kind.function;
            return obj.func_types[ty_index];
        }
        const import_function_count = obj.importedCountByKind(.function);
        const type_index = obj.functions[symbol.index - import_function_count].type_index;
        return obj.func_types[type_index];
    }
    assert(!is_undefined);
    return wasm.func_types.get(wasm.functions.items.values()[symbol.index].type_index).*;
}

/// Assigns indexes to all indirect functions.
/// Starts at offset 1, where the value `0` represents an unresolved function pointer
/// or null-pointer
fn mapFunctionTable(wasm: *Wasm) void {
    var it = wasm.elements.indirect_functions.valueIterator();
    var index: u32 = 1;
    while (it.next()) |value_ptr| : (index += 1) {
        value_ptr.* = index;
    }
}

/// Calculates the new indexes for symbols and their respective symbols
fn mergeSections(wasm: *Wasm) !void {
    // first append the indirect function table if initialized
    const function_pointers = wasm.elements.functionCount();
    if (function_pointers > 0 and !wasm.options.import_table) {
        log.debug("Appending indirect function table", .{});
        const loc = wasm.findGlobalSymbol("__indirect_function_table").?;
        const symbol = loc.getSymbol(wasm);
        symbol.index = try wasm.tables.append(
            wasm.base.allocator,
            wasm.imports.tableCount(),
            .{
                // index starts at 1, so add 1 extra element
                .limits = .{ .flags = 0x1, .min = function_pointers + 1, .max = function_pointers + 1 },
                .reftype = .funcref,
            },
        );
    }

    log.debug("Merging sections", .{});
    for (wasm.resolved_symbols.keys()) |sym_with_loc| {
        const file_index = sym_with_loc.file orelse continue; // synthetic symbols do not need to be merged
        const object = wasm.objects.items[file_index];
        const symbol: *Symbol = &object.symtable[sym_with_loc.sym_index];
        if (symbol.isUndefined() or (symbol.tag != .function and symbol.tag != .global and symbol.tag != .table)) {
            // Skip undefined symbols as they go in the `import` section
            // Also skip symbols that do not need to have a section merged.
            continue;
        }

        const offset = object.importedCountByKind(symbol.tag.externalType());
        const index = symbol.index - offset;
        switch (symbol.tag) {
            .function => {
                const original_func = object.functions[index];
                symbol.index = try wasm.functions.append(
                    wasm.base.allocator,
                    .{ .file = file_index, .index = symbol.index },
                    wasm.imports.functionCount(),
                    original_func,
                );
            },
            .global => {
                const original_global = object.globals[index];
                symbol.index = try wasm.globals.append(
                    wasm.base.allocator,
                    wasm.imports.globalCount(),
                    original_global,
                );
            },
            .table => {
                const original_table = object.tables[index];
                symbol.index = try wasm.tables.append(
                    wasm.base.allocator,
                    wasm.imports.tableCount(),
                    original_table,
                );
            },
            else => unreachable,
        }
    }
    log.debug("Merged ({d}) functions", .{wasm.functions.count()});
    log.debug("Merged ({d}) globals", .{wasm.globals.count()});
    log.debug("Merged ({d}) tables", .{wasm.tables.count()});
}

/// Merges function types of all object files into the final
/// 'types' section, while assigning the type index to the representing
/// section (import, export, function).
fn mergeTypes(wasm: *Wasm) !void {
    log.debug("Merging types", .{});
    // A map to track which functions have already had their
    // type inserted. If we do this for the same function multiple times,
    // it will be overwritten with the incorrect type.
    var dirty = std.AutoHashMap(u32, void).init(wasm.base.allocator);
    try dirty.ensureUnusedCapacity(wasm.functions.count());
    defer dirty.deinit();

    for (wasm.resolved_symbols.keys()) |sym_with_loc| {
        const object = wasm.objects.items[sym_with_loc.file orelse continue]; // synthetic symbols do not need to be merged
        const symbol: Symbol = object.symtable[sym_with_loc.sym_index];
        if (symbol.tag == .function) {
            if (symbol.isUndefined()) {
                log.debug("Adding type from extern function '{s}'", .{object.string_table.get(symbol.name)});
                const value = &wasm.imports.imported_functions.values()[symbol.index];
                value.type = try wasm.func_types.append(wasm.base.allocator, object.func_types[value.type]);
                continue;
            } else if (!dirty.contains(symbol.index)) {
                log.debug("Adding type from function '{s}'", .{object.string_table.get(symbol.name)});
                const func = &wasm.functions.items.values()[symbol.index - wasm.imports.functionCount()];
                func.type_index = try wasm.func_types.append(wasm.base.allocator, object.func_types[func.type_index]);
                dirty.putAssumeCapacity(symbol.index, {});
            }
        }
    }
    log.debug("Completed merging and deduplicating types. Total count: ({d})", .{wasm.func_types.count()});
}

fn setupExports(wasm: *Wasm) !void {
    log.debug("Building exports from symbols", .{});

    // When importing memory option is false,
    // we export the memory.
    if (!wasm.options.import_memory) {
        try wasm.exports.append(wasm.base.allocator, .{ .name = "memory", .kind = .memory, .index = 0 });
    }

    if (wasm.options.exports.len > 0) {
        var failed_exports = try std.ArrayList([]const u8).initCapacity(wasm.base.allocator, wasm.options.exports.len);
        defer failed_exports.deinit();

        for (wasm.options.exports) |export_name| {
            const loc = wasm.findGlobalSymbol(export_name) orelse {
                failed_exports.appendAssumeCapacity(export_name);
                continue;
            };
            const symbol = loc.getSymbol(wasm);
            symbol.setFlag(.WASM_SYM_EXPORTED);
        }

        if (failed_exports.items.len > 0) {
            for (failed_exports.items) |export_name| {
                log.err("Failed to export symbol '{s}' using `--export`, symbol was not found", .{export_name});
            }

            return error.ExportedSymbolNotFound;
        }
    }

    for (wasm.resolved_symbols.keys()) |sym_loc| {
        const symbol = sym_loc.getSymbol(wasm);
        if (!symbol.isExported(wasm.options.export_dynamic)) continue;

        const name = sym_loc.getName(wasm);
        const exported: std.wasm.Export = if (symbol.tag == .data) exp: {
            const atom = wasm.symbol_atom.get(sym_loc).?;
            const va = atom.getVA(wasm, symbol);
            const offset = wasm.imports.globalCount();
            const global_index = try wasm.globals.append(wasm.base.allocator, offset, .{
                .global_type = .{ .valtype = .i32, .mutable = false },
                .init = .{ .i32_const = @intCast(i32, va) },
            });
            break :exp .{
                .name = name,
                .kind = .global,
                .index = global_index,
            };
        } else .{
            .name = name,
            .kind = symbol.tag.externalType(),
            .index = symbol.index,
        };

        log.debug("Appending export from symbol '{s}' using name: '{s}' index: {d}", .{
            name, name, symbol.index,
        });
        try wasm.exports.append(wasm.base.allocator, exported);
    }
    log.debug("Completed building exports. Total count: ({d})", .{wasm.exports.count()});
}

/// Creates symbols that are made by the linker, rather than the compiler/object file
/// TODO: We should support re-merging synthetic symbols so we can create the corresponding
/// symbol objects initially here and later update them. It makes them safer to use, for
/// insignificant performance degredation.
fn setupLinkerSymbols(wasm: *Wasm) !void {
    // stack pointer symbol
    {
        const loc = try wasm.createSyntheticSymbol("__stack_pointer", .global);
        const symbol = loc.getSymbol(wasm);
        symbol.setFlag(.WASM_SYM_VISIBILITY_HIDDEN);
        const global: std.wasm.Global = .{
            .init = .{ .i32_const = 0 },
            .global_type = .{ .valtype = .i32, .mutable = true },
        };
        symbol.index = try wasm.globals.append(wasm.base.allocator, 0, global);
    }

    // indirect function table symbol
    {
        const loc = try wasm.createSyntheticSymbol("__indirect_function_table", .table);
        const symbol = loc.getSymbol(wasm);
        if (wasm.options.export_table) {
            symbol.setFlag(.WASM_SYM_EXPORTED);
        } else if (wasm.options.import_table) {
            symbol.setUndefined(true);
        } else {
            symbol.setFlag(.WASM_SYM_VISIBILITY_HIDDEN);
        }
        // do need to create table here, as we only create it if there's any
        // function pointers to be stored. This is done in `mergeSections`
    }

    // __wasm_call_ctors
    {
        const loc = try wasm.createSyntheticSymbol("__wasm_call_ctors", .function);
        const symbol = loc.getSymbol(wasm);
        symbol.setFlag(.WASM_SYM_VISIBILITY_HIDDEN);
        // We set the type and function index later so we do not need to merge them later.
    }

    // shared-memory symbols for TLS support
    if (wasm.options.shared_memory) {
        // __tls_base
        {
            const loc = try wasm.createSyntheticSymbol("__tls_base", .global);
            const symbol = loc.getSymbol(wasm);
            symbol.setFlag(.WASM_SYM_VISIBILITY_HIDDEN);
        }
        // __tls_size
        {
            const loc = try wasm.createSyntheticSymbol("__tls_size", .global);
            const symbol = loc.getSymbol(wasm);
            symbol.setFlag(.WASM_SYM_VISIBILITY_HIDDEN);
        }
        // __tls_align
        {
            const loc = try wasm.createSyntheticSymbol("__tls_align", .global);
            const symbol = loc.getSymbol(wasm);
            symbol.setFlag(.WASM_SYM_VISIBILITY_HIDDEN);
        }

        // __tls_init
        {
            const loc = try wasm.createSyntheticSymbol("__wasm_init_tls", .function);
            const symbol = loc.getSymbol(wasm);
            symbol.setFlag(.WASM_SYM_VISIBILITY_HIDDEN);
        }
    }
}

/// For a given name, creates a new global synthetic symbol.
/// Leaves index undefined and the default flags (0).
fn createSyntheticSymbol(wasm: *Wasm, name: []const u8, tag: Symbol.Tag) !SymbolWithLoc {
    const name_offset = try wasm.string_table.put(wasm.base.allocator, name);
    const sym_index = @intCast(u32, wasm.synthetic_symbols.count());
    const loc: SymbolWithLoc = .{ .sym_index = sym_index, .file = null };
    try wasm.synthetic_symbols.putNoClobber(wasm.base.allocator, name, .{
        .name = name_offset,
        .flags = 0,
        .tag = tag,
        .index = undefined,
    });
    try wasm.resolved_symbols.putNoClobber(wasm.base.allocator, loc, {});
    try wasm.global_symbols.put(wasm.base.allocator, name_offset, loc);
    return loc;
}

/// Tries to find a global symbol by its name. Returns null when not found,
/// and its location when it is found.
fn findGlobalSymbol(wasm: *Wasm, name: []const u8) ?SymbolWithLoc {
    const offset = wasm.string_table.getOffset(name) orelse return null;
    return wasm.global_symbols.get(offset);
}

/// Verifies if we have any undefined, non-function symbols left.
/// Emits an error if one or multiple undefined references are found.
/// This will be disabled when the user passes `--import-symbols`
fn checkUndefinedSymbols(wasm: *const Wasm) !void {
    if (wasm.options.import_symbols) return;

    var found_undefined_symbols = false;
    for (wasm.undefs.values()) |undef| {
        const symbol = undef.getSymbol(wasm);
        if (symbol.tag == .data) {
            found_undefined_symbols = true;
            const file_name = wasm.objects.items[undef.file.?].name;
            const obj = wasm.objects.items[undef.file.?];
            const name_index = if (symbol.tag == .function) name_index: {
                break :name_index obj.findImport(symbol.tag.externalType(), symbol.index).name;
            } else symbol.name;
            const import_name = obj.string_table.get(name_index);
            log.err("could not resolve undefined symbol '{s}'", .{import_name});
            log.err("  defined in '{s}'", .{file_name});
        }
    }
    if (found_undefined_symbols) {
        return error.UndefinedSymbol;
    }
}

/// Obtains all initfuncs from each object file, verifies its function signature,
/// and then appends it to our final `init_funcs` list.
/// After all functions have been inserted, the functions will be ordered based
/// on their priority.
fn setupInitFunctions(wasm: *Wasm) !void {
    for (wasm.objects.items) |object, file_index| {
        try wasm.init_funcs.ensureUnusedCapacity(wasm.base.allocator, object.init_funcs.len);
        for (object.init_funcs) |init_func| {
            const symbol = object.symtable[init_func.symbol_index];
            const func_index = symbol.index - object.importedCountByKind(.function);
            const func = object.functions[func_index];
            const ty = object.func_types[func.type_index];

            if (ty.params.len != 0) {
                log.err("constructor functions cannot take arguments: '{s}'", .{object.string_table.get(symbol.name)});
                return error.InvalidInitFunc;
            }
            log.debug("appended init func '{s}'\n", .{object.string_table.get(symbol.name)});
            wasm.init_funcs.appendAssumeCapacity(.{
                .index = init_func.symbol_index,
                .file = @intCast(u16, file_index),
                .priority = init_func.priority,
            });
        }
    }

    // sort the initfunctions based on their priority
    std.sort.sort(InitFuncLoc, wasm.init_funcs.items, {}, struct {
        fn lessThan(ctx: void, lhs: InitFuncLoc, rhs: InitFuncLoc) bool {
            _ = ctx;
            return lhs.priority < rhs.priority;
        }
    }.lessThan);
}

fn setupInitMemoryFunction(wasm: *Wasm) !void {
    // Passive segments are used to avoid memory being reinitialized on each
    // thread's instantiation. These passive segments are initialized and
    // dropped in __wasm_init_memory, which is registered as the start function
    // We also initialize bss segments (using memory.fill) as part of this
    // function.
    if (!wasm.hasPassiveInitializationSegments()) {
        return;
    }

    const flag_address: u32 = if (wasm.options.shared_memory) address: {
        // when we have passive initialization segments and shared memory
        // `setupMemory` will create this symbol and set its virtual address.
        const loc = wasm.findGlobalSymbol("__wasm_init_memory_flag").?;
        const atom = wasm.symbol_atom.get(loc).?;
        break :address atom.getVA(wasm, loc.getSymbol(wasm));
    } else 0;

    var function_body = std.ArrayList(u8).init(wasm.base.allocator);
    defer function_body.deinit();
    const writer = function_body.writer();

    // we have 0 locals
    try leb.writeULEB128(writer, @as(u32, 0));

    if (wasm.options.shared_memory) {
        // destination blocks
        // based on values we jump to corresponding label
        try writer.writeByte(std.wasm.opcode(.block)); // $drop
        try writer.writeByte(std.wasm.block_empty); // block type

        try writer.writeByte(std.wasm.opcode(.block)); // $wait
        try writer.writeByte(std.wasm.block_empty); // block type

        try writer.writeByte(std.wasm.opcode(.block)); // $init
        try writer.writeByte(std.wasm.block_empty); // block type

        // atomically check
        try writer.writeByte(std.wasm.opcode(.i32_const));
        try leb.writeULEB128(writer, flag_address);
        try writer.writeByte(std.wasm.opcode(.i32_const));
        try leb.writeULEB128(writer, @as(u32, 0));
        try writer.writeByte(std.wasm.opcode(.i32_const));
        try leb.writeULEB128(writer, @as(u32, 1));
        try writer.writeByte(0xfe); // atomic prefix (TODO: Add this to zig's std)
        try leb.writeULEB128(writer, @as(u32, 0x48)); // i32.atomic.rmw.cmpxchg
        try leb.writeULEB128(writer, @as(u32, 2)); // alignment
        try leb.writeULEB128(writer, @as(u32, 0)); // offset

        // based on the value from the atomic check, jump to the label.
        try writer.writeByte(std.wasm.opcode(.br_table));
        try leb.writeULEB128(writer, @as(u32, 2)); // length of the table (we have 3 blocks but because of the mandatory default the length is 2).
        try leb.writeULEB128(writer, @as(u32, 0)); // $init
        try leb.writeULEB128(writer, @as(u32, 1)); // $wait
        try leb.writeULEB128(writer, @as(u32, 2)); // $drop
        try writer.writeByte(std.wasm.opcode(.end));
    }

    var it = wasm.data_segments.iterator();
    var segment_index: u32 = 0;
    while (it.next()) |entry| : (segment_index += 1) {
        const segment: Segment = wasm.segments.items[entry.value_ptr.*];
        if (segment.needsPassiveInitialization(wasm.options.import_memory, entry.key_ptr.*)) {
            // For passive BSS segments we can simple issue a memory.fill(0).
            // For non-BSS segments we do a memory.init.  Both these
            // instructions take as their first argument the destination
            // address.
            try writer.writeByte(std.wasm.opcode(.i32_const));
            try leb.writeULEB128(writer, segment.offset);

            if (wasm.options.shared_memory and std.mem.eql(u8, entry.key_ptr.*, ".tdata")) {
                // When we initialize the TLS segment we also set the `__tls_base`
                // global.  This allows the runtime to use this static copy of the
                // TLS data for the first/main thread.
                try writer.writeByte(std.wasm.opcode(.i32_const));
                try leb.writeULEB128(writer, segment.offset);
                try writer.writeByte(std.wasm.opcode(.global_set));
                const loc = wasm.findGlobalSymbol("__tls_base").?;
                try leb.writeULEB128(writer, loc.getSymbol(wasm).index);
            }

            try writer.writeByte(std.wasm.opcode(.i32_const));
            try leb.writeULEB128(writer, @as(u32, 0));
            try writer.writeByte(std.wasm.opcode(.i32_const));
            try leb.writeULEB128(writer, segment.size);
            try writer.writeByte(std.wasm.opcode(.prefixed));
            if (std.mem.eql(u8, entry.key_ptr.*, ".bss")) {
                // fill bss segment with zeroes
                try leb.writeULEB128(writer, @enumToInt(std.wasm.PrefixedOpcode.memory_fill));
            } else {
                // initialize the segment
                try leb.writeULEB128(writer, @enumToInt(std.wasm.PrefixedOpcode.memory_init));
                try leb.writeULEB128(writer, segment_index);
            }
            try writer.writeByte(0); // memory index immediate
        }
    }

    if (wasm.options.shared_memory) {
        // we set the init memory flag to value '2'
        try writer.writeByte(std.wasm.opcode(.i32_const));
        try leb.writeULEB128(writer, flag_address);
        try writer.writeByte(std.wasm.opcode(.i32_const));
        try leb.writeULEB128(writer, @as(u32, 2));
        try writer.writeByte(0xfe); // atomics prefix
        try leb.writeULEB128(writer, @as(u32, 0x17)); // i32.atomic.store
        try leb.writeULEB128(writer, @as(u32, 2)); // alignment
        try leb.writeULEB128(writer, @as(u32, 0)); // offset

        // notify any waiters for segment initialization completion
        try writer.writeByte(std.wasm.opcode(.i32_const));
        try leb.writeULEB128(writer, flag_address);
        try writer.writeByte(std.wasm.opcode(.i32_const));
        try leb.writeILEB128(writer, @as(i32, -1)); // number of waiters
        try writer.writeByte(0xfe); // atomics prefix
        try leb.writeULEB128(writer, @as(u32, 0x0)); // memory.atomic.notify
        try leb.writeULEB128(writer, @as(u32, 2)); // alignment
        try leb.writeULEB128(writer, @as(u32, 0)); // offset
        try writer.writeByte(std.wasm.opcode(.drop));

        // branch and drop segments
        try writer.writeByte(std.wasm.opcode(.br));
        try leb.writeULEB128(writer, @as(u32, 1));

        // wait for thread to initialize memory segments
        try writer.writeByte(std.wasm.opcode(.end)); // end $wait
        try writer.writeByte(std.wasm.opcode(.i32_const));
        try leb.writeULEB128(writer, flag_address);
        try writer.writeByte(std.wasm.opcode(.i32_const));
        try leb.writeULEB128(writer, @as(u32, 1)); // expected flag value
        try writer.writeByte(std.wasm.opcode(.i32_const));
        try leb.writeILEB128(writer, @as(i32, -1)); // timeout
        try writer.writeByte(0xfe); // atomics prefix
        try leb.writeULEB128(writer, @as(u32, 0x1)); // memory.atomic.wait32
        try leb.writeULEB128(writer, @as(u32, 2)); // alignment
        try leb.writeULEB128(writer, @as(u32, 0)); // offset
        try writer.writeByte(std.wasm.opcode(.drop));

        try writer.writeByte(std.wasm.opcode(.end)); // end $drop
    }

    it.reset();
    segment_index = 0;
    while (it.next()) |entry| : (segment_index += 1) {
        const name = entry.key_ptr.*;
        const segment: Segment = wasm.segments.items[entry.value_ptr.*];
        if (segment.needsPassiveInitialization(wasm.options.import_memory, name) and
            !std.mem.eql(u8, name, ".bss"))
        {
            // The TLS region should not be dropped since its is needed
            // during the initialization of each thread (__wasm_init_tls).
            if (wasm.options.shared_memory and std.mem.eql(u8, name, ".tdata")) {
                continue;
            }

            try writer.writeByte(std.wasm.opcode(.prefixed));
            try leb.writeULEB128(writer, @enumToInt(std.wasm.PrefixedOpcode.data_drop));
            try leb.writeULEB128(writer, segment_index);
        }
    }

    // End of the function body
    try writer.writeByte(std.wasm.opcode(.end));

    try wasm.createSyntheticFunction(
        "__wasm_init_memory",
        std.wasm.Type{ .params = &.{}, .returns = &.{} },
        &function_body,
    );
}

/// Constructs a synthetic function that performs runtime relocations for
/// TLS symbols. This function is called by `__wasm_init_tls`.
fn setupTLSRelocationsFunction(wasm: *Wasm) !void {
    // When we have TLS GOT entries and shared memory is enabled,
    // we must perform runtime relocations or else we don't create the function.
    if (!(wasm.options.shared_memory and wasm.globals.requiresTLSReloc(wasm))) {
        return;
    }

    var function_body = std.ArrayList(u8).init(wasm.base.allocator);
    defer function_body.deinit();
    const writer = function_body.writer();

    // locals (we have none)
    try writer.writeByte(0);
    for (wasm.globals.got_symbols.items) |got_loc, got_index| {
        const sym: *Symbol = got_loc.getSymbol(wasm);
        if (!sym.isTLS()) continue; // only relocate TLS symbols
        if (sym.tag == .data and sym.isDefined()) {
            // get __tls_base
            try writer.writeByte(std.wasm.opcode(.global_get));
            try leb.writeULEB128(writer, wasm.findGlobalSymbol("__tls_base").?.getSymbol(wasm).index);

            // add the virtual address of the symbol
            try writer.writeByte(std.wasm.opcode(.i32_const));
            const va = wasm.symbol_atom.get(got_loc).?.getVA(wasm, sym);
            try leb.writeULEB128(writer, va);
        } else if (sym.tag == .function) {
            @panic("TODO: relocate GOT entry of function");
        } else continue;

        try writer.writeByte(std.wasm.opcode(.i32_add));
        try writer.writeByte(std.wasm.opcode(.global_set));
        try leb.writeULEB128(writer, wasm.imports.globalCount() + wasm.globals.count() + @intCast(u32, got_index));
    }
    try writer.writeByte(std.wasm.opcode(.end));

    try wasm.createSyntheticFunction(
        "__wasm_apply_global_tls_relocs",
        std.wasm.Type{ .params = &.{}, .returns = &.{} },
        &function_body,
    );
}

fn initializeCallCtorsFunction(wasm: *Wasm) !void {
    var function_body = std.ArrayList(u8).init(wasm.base.allocator);
    defer function_body.deinit();
    const writer = function_body.writer();

    // Write locals count (we have none)
    try leb.writeULEB128(writer, @as(u32, 0));

    // call constructors
    const import_count = wasm.imports.functionCount();
    for (wasm.init_funcs.items) |init_func_loc| {
        const symbol = init_func_loc.getSymbol(wasm);
        const func = wasm.functions.items.values()[symbol.index - import_count];
        const ty = wasm.func_types.items.items[func.type_index];

        // Call function by its function index
        try writer.writeByte(std.wasm.opcode(.call));
        try leb.writeULEB128(writer, symbol.index);

        // drop all returned values from the stack as __wasm_call_ctors has no return value
        for (ty.returns) |_| {
            try writer.writeByte(std.wasm.opcode(.drop));
        }
    }

    // End function body
    try writer.writeByte(std.wasm.opcode(.end));

    try wasm.createSyntheticFunction(
        "__wasm_call_ctors",
        std.wasm.Type{ .params = &.{}, .returns = &.{} },
        &function_body,
    );
}

fn createSyntheticFunction(
    wasm: *Wasm,
    symbol_name: []const u8,
    func_ty: std.wasm.Type,
    function_body: *std.ArrayList(u8),
) !void {
    const loc = wasm.findGlobalSymbol(symbol_name) orelse
        try wasm.createSyntheticSymbol(symbol_name, .function);

    // Update the symbol
    const symbol = loc.getSymbol(wasm);
    // create type (() -> nil)
    const ty_index = try wasm.func_types.append(wasm.base.allocator, func_ty);
    // create function with above type
    symbol.index = try wasm.functions.append(
        wasm.base.allocator,
        .{ .file = null, .index = loc.sym_index },
        wasm.imports.functionCount(),
        .{ .type_index = ty_index },
    );

    // create the atom that will be output into the final binary
    const atom = try wasm.base.allocator.create(Atom);
    errdefer wasm.base.allocator.destroy(atom);
    atom.* = .{
        .size = @intCast(u32, function_body.items.len),
        .offset = 0,
        .sym_index = loc.sym_index,
        .file = null,
        .alignment = 1,
        .next = null,
        .prev = null,
        .code = function_body.moveToUnmanaged(),
    };
    try wasm.managed_atoms.append(wasm.base.allocator, atom);
    try wasm.appendAtomAtIndex(wasm.base.allocator, wasm.code_section_index.?, atom);
    try wasm.symbol_atom.putNoClobber(wasm.base.allocator, loc, atom);
    atom.offset = atom.prev.?.offset + atom.prev.?.size;
}

fn initializeTLSFunction(wasm: *Wasm) !void {
    if (!wasm.options.shared_memory) return;

    var function_body = std.ArrayList(u8).init(wasm.base.allocator);
    defer function_body.deinit();
    const writer = function_body.writer();

    // locals
    try writer.writeByte(0);

    // If there's a TLS segment, initialize it during runtime using the bulk-memory feature
    if (wasm.data_segments.getIndex(".tdata")) |data_index| {
        const segment_index = wasm.data_segments.entries.items(.value)[data_index];
        const segment = wasm.segments.items[segment_index];

        const param_local: u32 = 0;

        try writer.writeByte(std.wasm.opcode(.local_get));
        try leb.writeULEB128(writer, param_local);

        const tls_base_loc = wasm.findGlobalSymbol("__tls_base").?;
        try writer.writeByte(std.wasm.opcode(.global_get));
        try leb.writeULEB128(writer, tls_base_loc.getSymbol(wasm).index);

        // load stack values for the bulk-memory operation
        {
            try writer.writeByte(std.wasm.opcode(.local_get));
            try leb.writeULEB128(writer, param_local);

            try writer.writeByte(std.wasm.opcode(.i32_const));
            try leb.writeULEB128(writer, @as(u32, 0)); //segment offset

            try writer.writeByte(std.wasm.opcode(.i32_const));
            try leb.writeULEB128(writer, @as(u32, segment.size)); //segment offset
        }

        // perform the bulk-memory operation to initialize the data segment
        try writer.writeByte(std.wasm.opcode(.prefixed));
        try leb.writeULEB128(writer, @enumToInt(std.wasm.PrefixedOpcode.memory_init));
        // segment immediate
        try leb.writeULEB128(writer, @intCast(u32, data_index));
        // memory index immediate (always 0)
        try writer.writeByte(@as(u32, 0));
    }

    // If we have to perform any TLS relocations, call the corresponding function
    // which performs all runtime TLS relocations. This is a synthetic function,
    // generated by the linker.
    if (wasm.findGlobalSymbol("__wasm_apply_global_tls_relocs")) |loc| {
        try writer.writeByte(std.wasm.opcode(.call));
        try leb.writeULEB128(writer, loc.getSymbol(wasm).index);
    }

    try writer.writeByte(std.wasm.opcode(.end));

    try wasm.createSyntheticFunction(
        "__wasm_init_tls",
        std.wasm.Type{ .params = &.{.i32}, .returns = &.{} },
        &function_body,
    );
}

fn mergeImports(wasm: *Wasm) !void {
    if (wasm.options.import_table and wasm.elements.functionCount() > 0) {
        const loc = wasm.findGlobalSymbol("__indirect_function_table").?;
        const symbol = loc.getSymbol(wasm);
        symbol.index = wasm.imports.tableCount();
        try wasm.imports.imported_tables.putNoClobber(wasm.base.allocator, .{
            .module_name = "env",
            .name = "__indirect_function_table",
        }, .{ .index = symbol.index, .table = .{
            .limits = .{ .min = wasm.elements.functionCount(), .max = null },
            .reftype = .funcref,
        } });
        try wasm.imports.imported_symbols.append(wasm.base.allocator, loc);
    }

    for (wasm.resolved_symbols.keys()) |sym_with_loc| {
        const symbol = sym_with_loc.getSymbol(wasm);
        if (symbol.tag != .data) {
            if (!symbol.requiresImport()) {
                continue;
            }
            if (std.mem.eql(u8, sym_with_loc.getName(wasm), "__indirect_function_table")) {
                continue;
            }
            log.debug("Symbol '{s}' will be imported", .{sym_with_loc.getName(wasm)});
            try wasm.imports.appendSymbol(wasm.base.allocator, wasm, sym_with_loc);
        }
    }
}

/// Sets up the memory section of the wasm module, as well as the stack.
fn setupMemory(wasm: *Wasm) !void {
    log.debug("Setting up memory layout", .{});
    const page_size = std.wasm.page_size;
    const stack_size = wasm.options.stack_size orelse page_size;
    const stack_alignment = 16; // wasm's stack alignment as specified by tool-convention
    const heap_alignment = 16; // wasm's heap alignment as specified by tool-convention

    // Always place the stack at the start by default
    // unless the user specified the global-base flag
    var place_stack_first = true;
    var memory_ptr: u64 = if (wasm.options.global_base) |base| blk: {
        place_stack_first = false;
        break :blk base;
    } else 0;

    if (place_stack_first) {
        memory_ptr = std.mem.alignForwardGeneric(u64, memory_ptr, stack_alignment);
        memory_ptr += stack_size;
        // We always put the stack pointer global at index 0
        wasm.globals.items.items[0].init.i32_const = @bitCast(i32, @intCast(u32, memory_ptr));
    }

    var offset: u32 = @intCast(u32, memory_ptr);
    var seg_it = wasm.data_segments.iterator();
    while (seg_it.next()) |entry| {
        const segment: *Segment = &wasm.segments.items[entry.value_ptr.*];
        memory_ptr = std.mem.alignForwardGeneric(u64, memory_ptr, segment.alignment);

        // set TLS-related symbols
        if (mem.eql(u8, entry.key_ptr.*, ".tdata")) {
            const global_count = wasm.imports.globalCount();
            if (wasm.findGlobalSymbol("__tls_size")) |loc| {
                const sym = loc.getSymbol(wasm);
                sym.index = try wasm.globals.append(wasm.base.allocator, global_count, .{
                    .global_type = .{ .valtype = .i32, .mutable = false },
                    .init = .{ .i32_const = @intCast(i32, segment.size) },
                });
            }
            if (wasm.findGlobalSymbol("__tls_align")) |loc| {
                const sym = loc.getSymbol(wasm);
                sym.index = try wasm.globals.append(wasm.base.allocator, global_count, .{
                    .global_type = .{ .valtype = .i32, .mutable = false },
                    .init = .{ .i32_const = @intCast(i32, segment.alignment) },
                });
            }
            if (wasm.findGlobalSymbol("__tls_base")) |loc| {
                const sym = loc.getSymbol(wasm);
                sym.index = try wasm.globals.append(wasm.base.allocator, wasm.imports.globalCount(), .{
                    .global_type = .{ .valtype = .i32, .mutable = wasm.options.shared_memory },
                    .init = .{ .i32_const = if (wasm.options.shared_memory) @as(i32, 0) else @intCast(i32, memory_ptr) },
                });
            }
        }

        memory_ptr += segment.size;
        segment.offset = offset;
        offset += segment.size;
    }

    if (!place_stack_first) {
        memory_ptr = std.mem.alignForwardGeneric(u64, memory_ptr, stack_alignment);
        memory_ptr += stack_size;
        wasm.globals.items.items[0].init.i32_const = @bitCast(i32, @intCast(u32, memory_ptr));
    }

    if (wasm.findGlobalSymbol("__heap_base")) |loc| {
        const atom = wasm.symbol_atom.get(loc).?;
        atom.offset = @intCast(u32, mem.alignForwardGeneric(u64, memory_ptr, heap_alignment));
    }

    // Setup the max amount of pages
    // For now we only support wasm32 by setting the maximum allowed memory size 2^32-1
    const max_memory_allowed: u64 = (1 << 32) - 1;

    if (wasm.options.initial_memory) |initial_memory| {
        if (!std.mem.isAlignedGeneric(u64, initial_memory, page_size)) {
            log.err("Initial memory must be {d}-byte aligned", .{page_size});
            return error.MissAlignment;
        }
        if (memory_ptr > initial_memory) {
            log.err("Initial memory too small, must be at least {d} bytes", .{memory_ptr});
            return error.MemoryTooSmall;
        }
        if (initial_memory > max_memory_allowed) {
            log.err("Initial memory exceeds maximum memory {d}", .{max_memory_allowed});
            return error.MemoryTooBig;
        }
        memory_ptr = initial_memory;
    }

    memory_ptr = std.mem.alignForwardGeneric(u64, memory_ptr, page_size);

    // In case we do not import memory, but define it ourselves,
    // set the minimum amount of pages on the memory section.
    wasm.memories.limits.min = @intCast(u32, memory_ptr / page_size);
    log.debug("Total memory pages: {d}", .{wasm.memories.limits.min});

    if (wasm.findGlobalSymbol("__heap_end")) |loc| {
        const atom = wasm.symbol_atom.get(loc).?;
        atom.offset = @intCast(u32, memory_ptr);
    }

    if (wasm.options.max_memory != null or wasm.options.shared_memory) {
        const max_memory = wasm.options.max_memory orelse memory_ptr;
        if (!std.mem.isAlignedGeneric(u64, max_memory, page_size)) {
            log.err("Maximum memory must be {d}-byte aligned", .{page_size});
            return error.MissAlignment;
        }
        if (memory_ptr > max_memory) {
            log.err("Maxmimum memory too small, must be at least {d} bytes", .{memory_ptr});
            return error.MemoryTooSmall;
        }
        if (max_memory > max_memory_allowed) {
            log.err("Maximum memory exceeds maxmium amount {d}", .{max_memory_allowed});
            return error.MemoryTooBig;
        }
        wasm.memories.limits.max = @intCast(u32, max_memory / page_size);
        wasm.memories.limits.setFlag(.WASM_LIMITS_FLAG_HAS_MAX);
        if (wasm.options.shared_memory) {
            wasm.memories.limits.setFlag(.WASM_LIMITS_FLAG_IS_SHARED);
        }
        log.debug("Maximum memory pages: {?d}", .{wasm.memories.limits.max});
    }
}

/// From a given object's index and the index of the segment, returns the corresponding
/// index of the segment within the final data section. When the segment does not yet
/// exist, a new one will be initialized and appended. The new index will be returned in that case.
pub fn getMatchingSegment(wasm: *Wasm, gpa: Allocator, object_index: u16, relocatable_index: u32) !?u32 {
    const object: Object = wasm.objects.items[object_index];
    const relocatable_data = object.relocatable_data[relocatable_index];
    const index = @intCast(u32, wasm.segments.items.len);

    switch (relocatable_data.type) {
        .data => {
            const segment_info = object.segment_info[relocatable_data.index];
            const segment_name = segment_info.outputName(wasm.options.merge_data_segments);
            const result = try wasm.data_segments.getOrPut(gpa, segment_name);
            if (!result.found_existing) {
                result.value_ptr.* = index;
                var flags: u32 = 0;
                if (wasm.options.shared_memory) {
                    flags |= @enumToInt(Segment.Flag.WASM_DATA_SEGMENT_IS_PASSIVE);
                }
                try wasm.segments.append(gpa, .{
                    .alignment = 1,
                    .size = 0,
                    .offset = 0,
                    .flags = flags,
                });
                return index;
            } else return result.value_ptr.*;
        },
        .code => return wasm.code_section_index orelse blk: {
            wasm.code_section_index = index;
            try wasm.appendDummySegment(gpa);
            break :blk index;
        },
        .debug => {
            const debug_name = object.getDebugName(relocatable_data);
            if (mem.eql(u8, debug_name, ".debug_info")) {
                return wasm.debug_info_index orelse blk: {
                    wasm.debug_info_index = index;
                    try wasm.appendDummySegment(gpa);
                    break :blk index;
                };
            } else if (mem.eql(u8, debug_name, ".debug_line")) {
                return wasm.debug_line_index orelse blk: {
                    wasm.debug_line_index = index;
                    try wasm.appendDummySegment(gpa);
                    break :blk index;
                };
            } else if (mem.eql(u8, debug_name, ".debug_loc")) {
                return wasm.debug_loc_index orelse blk: {
                    wasm.debug_loc_index = index;
                    try wasm.appendDummySegment(gpa);
                    break :blk index;
                };
            } else if (mem.eql(u8, debug_name, ".debug_ranges")) {
                return wasm.debug_line_index orelse blk: {
                    wasm.debug_ranges_index = index;
                    try wasm.appendDummySegment(gpa);
                    break :blk index;
                };
            } else if (mem.eql(u8, debug_name, ".debug_pubnames")) {
                return wasm.debug_pubnames_index orelse blk: {
                    wasm.debug_pubnames_index = index;
                    try wasm.appendDummySegment(gpa);
                    break :blk index;
                };
            } else if (mem.eql(u8, debug_name, ".debug_pubtypes")) {
                return wasm.debug_pubtypes_index orelse blk: {
                    wasm.debug_pubtypes_index = index;
                    try wasm.appendDummySegment(gpa);
                    break :blk index;
                };
            } else if (mem.eql(u8, debug_name, ".debug_abbrev")) {
                return wasm.debug_abbrev_index orelse blk: {
                    wasm.debug_abbrev_index = index;
                    try wasm.appendDummySegment(gpa);
                    break :blk index;
                };
            } else if (mem.eql(u8, debug_name, ".debug_str")) {
                return wasm.debug_str_index orelse blk: {
                    wasm.debug_str_index = index;
                    try wasm.appendDummySegment(gpa);
                    break :blk index;
                };
            } else {
                log.warn("found unknown debug section '{s}'", .{debug_name});
                log.warn("  debug section will be skipped", .{});
                return null;
            }
        },
    }
}

/// Appends a new segment with default field values
fn appendDummySegment(wasm: *Wasm, gpa: Allocator) !void {
    try wasm.segments.append(gpa, .{
        .alignment = 1,
        .size = 0,
        .offset = 0,
        .flags = 0,
    });
}

/// From a given index, append the given `Atom` at the back of the linked list.
/// Simply inserts it into the map of atoms when it doesn't exist yet.
pub fn appendAtomAtIndex(wasm: *Wasm, gpa: Allocator, index: u32, atom: *Atom) !void {
    if (wasm.atoms.getPtr(index)) |last| {
        last.*.next = atom;
        atom.prev = last.*;
        last.* = atom;
    } else {
        try wasm.atoms.putNoClobber(gpa, index, atom);
    }
}

/// Sorts the data segments into the preferred order of:
/// - .rodata
/// - .data
/// - .text
/// - <others> (.bss)
fn sortDataSegments(wasm: *Wasm, gpa: Allocator) !void {
    var new_mapping: std.StringArrayHashMapUnmanaged(u32) = .{};
    try new_mapping.ensureUnusedCapacity(gpa, wasm.data_segments.count());
    errdefer new_mapping.deinit(gpa);

    const keys = try gpa.dupe([]const u8, wasm.data_segments.keys());
    defer gpa.free(keys);

    const SortContext = struct {
        fn sort(_: void, lhs: []const u8, rhs: []const u8) bool {
            return order(lhs) <= order(rhs);
        }

        fn order(name: []const u8) u8 {
            if (mem.startsWith(u8, name, ".rodata")) return 0;
            if (mem.startsWith(u8, name, ".data")) return 1;
            if (mem.startsWith(u8, name, ".text")) return 2;
            return 3;
        }
    };

    std.sort.sort([]const u8, keys, {}, SortContext.sort);
    for (keys) |key| {
        const segment_index = wasm.data_segments.get(key).?;
        new_mapping.putAssumeCapacity(key, segment_index);
    }
    wasm.data_segments.deinit(gpa);
    wasm.data_segments = new_mapping;
}

fn allocateAtoms(wasm: *Wasm) !void {
    // first sort the data segments
    try wasm.sortDataSegments(wasm.base.allocator);

    var it = wasm.atoms.iterator();
    while (it.next()) |entry| {
        const segment = &wasm.segments.items[entry.key_ptr.*];
        var atom: *Atom = entry.value_ptr.*.getFirst();
        var offset: u32 = 0;
        while (true) {
            const symbol_loc = atom.symbolLoc();
            if (wasm.code_section_index) |index| {
                if (entry.key_ptr.* == index) {
                    if (!wasm.resolved_symbols.contains(symbol_loc)) {
                        atom = atom.next orelse break;
                        continue;
                    }
                }
            }
            offset = std.mem.alignForwardGeneric(u32, offset, atom.alignment);
            atom.offset = offset;
            offset += atom.size;
            atom = atom.next orelse break;
        }
        segment.size = std.mem.alignForwardGeneric(u32, offset, segment.alignment);
    }
}

fn setupStart(wasm: *Wasm) !void {
    if (wasm.options.no_entry) return;
    const entry_name = wasm.options.entry_name orelse "_start";
    const entry_loc = wasm.findGlobalSymbol(entry_name) orelse {
        log.err("Entry symbol '{s}' does not exist, use '--no-entry' to suppress", .{entry_name});
        return error.MissingSymbol;
    };

    const symbol = entry_loc.getSymbol(wasm);
    if (symbol.tag != .function) {
        log.err("Entry symbol '{s}' is not a function", .{entry_name});
        return error.InvalidEntryKind;
    }
    // Simply export the symbol as the start function is reserved
    // for synthetic symbols such as __wasm_start, __wasm_init_memory, and
    // __wasm_apply_global_relocs
    symbol.setFlag(.WASM_SYM_EXPORTED);
}

fn validateFeatures(wasm: *Wasm) !void {
    const infer = wasm.options.features.len == 0; // when the user did not define any features, we infer them from linked objects.
    const known_features_count = types.known_features.kvs.len;

    var allowed: FeatureSet = .{};
    var used = [_]u17{0} ** known_features_count;
    var disallowed = [_]u17{0} ** known_features_count;
    var required = [_]u17{0} ** known_features_count;

    // when false, we fail linking. We only verify this after a loop to catch all invalid features.
    var valid_feature_set = true;

    // When the user has given an explicit list of features to enable,
    // we extract them and insert each into the 'allowed' list.
    if (!infer) {
        var it = std.mem.split(u8, wasm.options.features, ",");
        while (it.next()) |feature_name| {
            const feature = types.known_features.get(feature_name) orelse {
                log.err("Unknown feature name '{s}' passed as option", .{feature_name});
                return error.UnknownFeature;
            };
            allowed.enable(feature);
        }
    }

    // will be set to true when there's any TLS segment found in any of the object files
    var has_tls = false;

    // extract all the used, disallowed and required features from each
    // linked object file so we can test them.
    for (wasm.objects.items) |object, object_index| {
        for (object.features) |feature| {
            const value = @intCast(u16, object_index) << 1 | @as(u1, 1);
            switch (feature.prefix) {
                .used => {
                    used[@enumToInt(feature.tag)] = value;
                },
                .disallowed => {
                    disallowed[@enumToInt(feature.tag)] = value;
                },
                .required => {
                    required[@enumToInt(feature.tag)] = value;
                    used[@enumToInt(feature.tag)] = value;
                },
            }
        }

        for (object.segment_info) |segment| {
            if (segment.isTLS()) {
                has_tls = true;
            }
        }
    }

    // when we infer the features, we allow each feature found in the 'used' set
    // and insert it into the 'allowed' set. When features are not inferred,
    // we validate that a used feature is allowed.
    for (used) |used_set, used_index| {
        const is_enabled = @truncate(u1, used_set) != 0;
        if (!is_enabled) continue;
        const feature = @intToEnum(types.Feature.Tag, used_index);
        if (infer) {
            allowed.enable(feature);
        } else if (!allowed.isEnabled(feature)) {
            log.err("feature '{}' not allowed, but used by linked object", .{feature});
            log.err("  defined in '{s}'", .{wasm.objects.items[used_set >> 1].name});
            valid_feature_set = false;
        }
    }

    if (!valid_feature_set) {
        return error.InvalidFeatureSet;
    }

    if (wasm.options.shared_memory) {
        const disallowed_feature = disallowed[@enumToInt(types.Feature.Tag.shared_mem)];
        if (@truncate(u1, disallowed_feature) != 0) {
            log.err(
                "--shared-memory is disallowed by '{s}' because it wasn't compiled with 'atomics' and 'bulk-memory' features enabled",
                .{wasm.objects.items[disallowed_feature >> 1].name},
            );
            valid_feature_set = false;
        }

        for ([_]types.Feature.Tag{ .atomics, .bulk_memory }) |feature| {
            if (!allowed.isEnabled(feature)) {
                log.err("feature '{}' is not used but is required for --shared-memory", .{feature});
            }
        }
    }

    if (has_tls) {
        for ([_]types.Feature.Tag{ .atomics, .bulk_memory }) |feature| {
            if (!allowed.isEnabled(feature)) {
                log.err("feature '{}' is not used but is required for thread-local storage", .{feature});
            }
        }
    }

    // For each linked object, validate the required and disallowed features
    for (wasm.objects.items) |object| {
        var object_used_features = [_]bool{false} ** known_features_count;
        for (object.features) |feature| {
            if (feature.prefix == .disallowed) continue; // already defined in 'disallowed' set.
            // from here a feature is always used
            const disallowed_feature = disallowed[@enumToInt(feature.tag)];
            if (@truncate(u1, disallowed_feature) != 0) {
                log.err("feature '{}' is disallowed, but used by linked object", .{feature.tag});
                log.err("  disallowed by '{s}'", .{wasm.objects.items[disallowed_feature >> 1].name});
                log.err("  used in '{s}'", .{object.name});
                valid_feature_set = false;
            }

            object_used_features[@enumToInt(feature.tag)] = true;
        }

        // validate the linked object file has each required feature
        for (required) |required_feature, feature_index| {
            const is_required = @truncate(u1, required_feature) != 0;
            if (is_required and !object_used_features[feature_index]) {
                log.err("feature '{}' is required but not used in linked object", .{(@intToEnum(types.Feature.Tag, feature_index))});
                log.err("  required by '{s}'", .{wasm.objects.items[required_feature >> 1].name});
                log.err("  missing in '{s}'", .{object.name});
                valid_feature_set = false;
            }
        }
    }

    if (!valid_feature_set) {
        return error.InvalidFeatureSet;
    }

    wasm.used_features = allowed;
}

/// From a given unsigned integer, returns the size it takes
/// in bytes to store the integer using leb128-encoding.
pub fn getULEB128Size(uint_value: anytype) u32 {
    const T = @TypeOf(uint_value);
    const U = if (@typeInfo(T).Int.bits < 8) u8 else T;
    var value = @intCast(U, uint_value);

    var size: u32 = 0;
    while (value != 0) : (size += 1) {
        value >>= 7;
    }
    return size;
}
