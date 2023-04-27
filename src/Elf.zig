const Elf = @This();

const std = @import("std");
const build_options = @import("build_options");
const builtin = @import("builtin");
const assert = std.debug.assert;
const elf = std.elf;
const fs = std.fs;
const gc = @import("Elf/gc.zig");
const log = std.log.scoped(.elf);
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const Archive = @import("Elf/Archive.zig");
const Atom = @import("Elf/Atom.zig");
const InternalObject = @import("Elf/InternalObject.zig");
const Object = @import("Elf/Object.zig");
pub const Options = @import("Elf/Options.zig");
const StringTable = @import("strtab.zig").StringTable;
const Symbol = @import("Elf/Symbol.zig");
const SyntheticSection = @import("synthetic_section.zig").SyntheticSection;
const ThreadPool = @import("ThreadPool.zig");
const Zld = @import("Zld.zig");

pub const base_tag = Zld.Tag.elf;

base: Zld,
options: Options,
cpu_arch: ?std.Target.Cpu.Arch = null,
entry: ?u64 = 0,
shoff: ?u64 = 0,

archives: std.ArrayListUnmanaged(Archive) = .{},
objects: std.ArrayListUnmanaged(Object) = .{},

phdrs: std.ArrayListUnmanaged(elf.Elf64_Phdr) = .{},
sections: std.MultiArrayList(Section) = .{},

phdr_seg_index: ?u16 = null,
load_r_seg_index: ?u16 = null,
load_re_seg_index: ?u16 = null,
load_rw_seg_index: ?u16 = null,
tls_seg_index: ?u16 = null,
gnu_stack_phdr_index: ?u16 = null,

text_sect_index: ?u16 = null,
got_sect_index: ?u16 = null,
symtab_sect_index: ?u16 = null,
strtab_sect_index: ?u16 = null,
shstrtab_sect_index: ?u16 = null,

/// Internal linker state for coordinating symbol resolution and synthetics
internal_object: ?InternalObject = null,
dynamic_sym_index: ?u32 = null,
init_array_start_sym_index: ?u32 = null,
init_array_end_sym_index: ?u32 = null,
fini_array_start_sym_index: ?u32 = null,
fini_array_end_sym_index: ?u32 = null,

entry_index: ?u32 = null,

globals: std.ArrayListUnmanaged(Symbol) = .{},
// TODO convert to context-adapted
globals_table: std.StringHashMapUnmanaged(u32) = .{},
strtab: StringTable(.strtab) = .{},

got_section: SyntheticSection(SymbolWithLoc, *Elf, .{
    .log_scope = .got_section,
    .entry_size = @sizeOf(u64),
    .baseAddrFn = Elf.getGotBaseAddress,
    .writeFn = Elf.writeGotEntry,
}) = .{},

atoms: std.ArrayListUnmanaged(Atom) = .{},

const Section = struct {
    shdr: elf.Elf64_Shdr,
    phdr: u8,
    last_atom: ?Atom.Index,
};

pub const SymbolWithLoc = struct {
    /// Index in the respective symbol table.
    sym_index: u32,

    /// null means it's a synthetic global.
    file: ?u32,
};

const default_base_addr: u64 = 0x200000;

pub fn openPath(allocator: Allocator, options: Options, thread_pool: *ThreadPool) !*Elf {
    const file = try options.emit.directory.createFile(options.emit.sub_path, .{
        .truncate = true,
        .read = true,
        .mode = if (builtin.os.tag == .windows) 0 else 0o777,
    });
    errdefer file.close();

    const self = try createEmpty(allocator, options, thread_pool);
    errdefer allocator.destroy(self);

    self.base.file = file;

    return self;
}

fn createEmpty(gpa: Allocator, options: Options, thread_pool: *ThreadPool) !*Elf {
    const self = try gpa.create(Elf);

    self.* = .{
        .base = .{
            .tag = .elf,
            .allocator = gpa,
            .file = undefined,
            .thread_pool = thread_pool,
        },
        .options = options,
    };

    return self;
}

pub fn deinit(self: *Elf) void {
    const gpa = self.base.allocator;
    self.strtab.deinit(gpa);
    self.atoms.deinit(gpa);
    self.globals.deinit(gpa);
    self.got_section.deinit(gpa);
    self.phdrs.deinit(gpa);
    self.sections.deinit(gpa);
    for (self.objects.items) |*object| {
        object.deinit(gpa);
    }
    self.objects.deinit(gpa);
    for (self.archives.items) |*archive| {
        archive.deinit(gpa);
    }
    self.archives.deinit(gpa);
    if (self.internal_object) |*object| {
        object.deinit(gpa);
    }
}

pub fn closeFiles(self: *const Elf) void {
    for (self.archives.items) |archive| {
        archive.file.close();
    }
}

fn resolveLib(
    arena: Allocator,
    search_dirs: []const []const u8,
    name: []const u8,
    ext: []const u8,
) !?[]const u8 {
    const search_name = try std.fmt.allocPrint(arena, "lib{s}{s}", .{ name, ext });

    for (search_dirs) |dir| {
        const full_path = try fs.path.join(arena, &[_][]const u8{ dir, search_name });

        // Check if the file exists.
        const tmp = fs.cwd().openFile(full_path, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        defer tmp.close();

        return full_path;
    }

    return null;
}

pub fn flush(self: *Elf) !void {
    var arena_allocator = std.heap.ArenaAllocator.init(self.base.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var lib_dirs = std.ArrayList([]const u8).init(arena);
    for (self.options.lib_dirs) |dir| {
        // Verify that search path actually exists
        var tmp = fs.cwd().openDir(dir, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        defer tmp.close();

        try lib_dirs.append(dir);
    }

    var libs = std.StringArrayHashMap(Zld.SystemLib).init(arena);
    var lib_not_found = false;
    for (self.options.libs.keys()) |lib_name| {
        for (&[_][]const u8{ ".dylib", ".a" }) |ext| {
            if (try resolveLib(arena, lib_dirs.items, lib_name, ext)) |full_path| {
                try libs.put(full_path, self.options.libs.get(lib_name).?);
                break;
            }
        } else {
            log.warn("library not found for '-l{s}'", .{lib_name});
            lib_not_found = true;
        }
    }
    if (lib_not_found) {
        log.warn("Library search paths:", .{});
        for (lib_dirs.items) |dir| {
            log.warn("  {s}", .{dir});
        }
    }

    var positionals = std.ArrayList([]const u8).init(arena);
    try positionals.ensureTotalCapacity(self.options.positionals.len);
    for (self.options.positionals) |obj| {
        positionals.appendAssumeCapacity(obj.path);
    }

    try self.strtab.buffer.append(self.base.allocator, 0);
    try self.atoms.append(self.base.allocator, Atom.empty); // null atom

    try self.parsePositionals(positionals.items);
    try self.parseLibs(libs.keys());

    self.internal_object = InternalObject{};

    try self.resolveSymbols();

    if (!self.options.allow_multiple_definition) {
        self.checkDuplicates();
    }

    try self.resolveSyntheticSymbols();

    self.checkUndefined();

    // Set the entrypoint if found
    self.entry_index = blk: {
        if (self.options.output_mode != .exe) break :blk null;
        const entry_name = self.options.entry orelse "_start";
        break :blk self.globals_table.get(entry_name) orelse null;
    };

    if (self.options.gc_sections) {
        try gc.gcAtoms(self);
    }

    for (self.objects.items, 0..) |object, object_id| {
        log.debug(">>>{d} : {s}", .{ object_id, object.name });
        log.debug("{}{}", .{ object.fmtAtoms(self), object.fmtSymtab(self) });
    }
    if (self.internal_object) |object| {
        log.debug("linker-defined", .{});
        log.debug("{}", .{object.fmtSymtab(self)});
    }

    return error.Todo;

    // for (self.objects.items) |object| {
    //     for (object.atoms.items) |atom_index| {
    //         const atom = self.getAtom(atom_index);
    //         try atom.scanRelocs(self);
    //     }
    // }

    // try self.setStackSize();
    // try self.setSyntheticSections();
    // try self.allocateLoadRSeg();
    // try self.allocateLoadRESeg();
    // try self.allocateLoadRWSeg();
    // try self.allocateNonAllocSections();
    // try self.allocateAtoms();
    // try self.setEntryPoint();

    // {
    //     // TODO this should be put in its own logic but probably is linked to
    //     // C++ handling so leaving it here until I gather more knowledge on
    //     // those special symbols.
    //     if (self.getSectionByName(".init_array") == null) {
    //         if (self.globals.get("__init_array_start")) |global| {
    //             assert(global.file == null);
    //             const sym = &self.locals.items[global.sym_index];
    //             sym.st_value = self.entry.?;
    //             sym.st_shndx = self.text_sect_index.?;
    //         }
    //         if (self.globals.get("__init_array_end")) |global| {
    //             assert(global.file == null);
    //             const sym = &self.locals.items[global.sym_index];
    //             sym.st_value = self.entry.?;
    //             sym.st_shndx = self.text_sect_index.?;
    //         }
    //     }
    //     if (self.getSectionByName(".fini_array") == null) {
    //         if (self.globals.get("__fini_array_start")) |global| {
    //             assert(global.file == null);
    //             const sym = &self.locals.items[global.sym_index];
    //             sym.st_value = self.entry.?;
    //             sym.st_shndx = self.text_sect_index.?;
    //         }
    //         if (self.globals.get("__fini_array_end")) |global| {
    //             assert(global.file == null);
    //             const sym = &self.locals.items[global.sym_index];
    //             sym.st_value = self.entry.?;
    //             sym.st_shndx = self.text_sect_index.?;
    //         }
    //     }
    // }

    // if (build_options.enable_logging) {
    //     self.logObjects();
    //     self.logSymtab();
    //     log.debug("{}", .{self.got_section});
    //     self.logSections();
    //     self.logAtoms();
    // }

    // try self.writeAtoms();
    // try self.writeSyntheticSections();
    // try self.writePhdrs();
    // try self.writeSymtab();
    // try self.writeStrtab();
    // try self.writeShStrtab();
    // try self.writeShdrs();
    // try self.writeHeader();
}

fn getSectionPrecedence(shdr: elf.Elf64_Shdr, shdr_name: []const u8) u4 {
    const flags = shdr.sh_flags;
    switch (shdr.sh_type) {
        elf.SHT_NULL => return 0,
        elf.SHT_PREINIT_ARRAY,
        elf.SHT_INIT_ARRAY,
        elf.SHT_FINI_ARRAY,
        => return 2,
        elf.SHT_PROGBITS => if (flags & elf.SHF_ALLOC != 0) {
            if (flags & elf.SHF_EXECINSTR != 0) {
                return 2;
            } else if (flags & elf.SHF_WRITE != 0) {
                return if (flags & elf.SHF_TLS != 0) 3 else 5;
            } else {
                return 1;
            }
        } else {
            if (mem.startsWith(u8, shdr_name, ".debug")) {
                return 7;
            } else {
                return 8;
            }
        },
        elf.SHT_NOBITS => return if (flags & elf.SHF_TLS != 0) 4 else 6,
        elf.SHT_SYMTAB => return 0xa,
        elf.SHT_STRTAB => return 0xb,
        else => return 0xf,
    }
}

fn insertSection(self: *Elf, shdr: elf.Elf64_Shdr, shdr_name: []const u8) !u16 {
    const precedence = getSectionPrecedence(shdr, shdr_name);
    // Actually, the order doesn't really matter as long as the sections are correctly
    // allocated within each respective segment. Of course, it is good practice to have
    // the sections sorted, but it's a useful hack we can use for the debug builds in
    // self-hosted Zig compiler.
    const insertion_index = for (self.sections.items(.shdr), 0..) |oshdr, i| {
        const oshdr_name = self.shstrtab.getAssumeExists(oshdr.sh_name);
        if (getSectionPrecedence(oshdr, oshdr_name) > precedence) break @intCast(u16, i);
    } else @intCast(u16, self.sections.items(.shdr).len);
    log.debug("inserting section '{s}' at index {d}", .{
        shdr_name,
        insertion_index,
    });
    for (&[_]*?u16{
        &self.text_sect_index,
        &self.got_sect_index,
        &self.symtab_sect_index,
        &self.strtab_sect_index,
        &self.shstrtab_sect_index,
    }) |maybe_index| {
        const index = maybe_index.* orelse continue;
        if (insertion_index <= index) maybe_index.* = index + 1;
    }
    try self.sections.insert(self.base.allocator, insertion_index, .{
        .shdr = .{
            .sh_name = try self.shstrtab.insert(self.base.allocator, shdr_name),
            .sh_type = shdr.sh_type,
            .sh_flags = shdr.sh_flags,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = 0,
            .sh_link = 0,
            .sh_info = shdr.sh_info,
            .sh_addralign = shdr.sh_addralign,
            .sh_entsize = shdr.sh_entsize,
        },
        .last_atom = null,
    });
    return insertion_index;
}

pub fn getOutputSection(self: *Elf, shdr: elf.Elf64_Shdr, shdr_name: []const u8) !?u16 {
    const flags = shdr.sh_flags;
    const res: ?u16 = blk: {
        if (flags & elf.SHF_EXCLUDE != 0) break :blk null;
        const out_name: []const u8 = name: {
            switch (shdr.sh_type) {
                elf.SHT_NULL => break :blk 0,
                elf.SHT_PROGBITS => {
                    if (flags & elf.SHF_ALLOC == 0) break :name shdr_name;
                    if (flags & elf.SHF_EXECINSTR != 0) {
                        if (mem.startsWith(u8, shdr_name, ".init")) {
                            break :name ".init";
                        } else if (mem.startsWith(u8, shdr_name, ".fini")) {
                            break :name ".fini";
                        } else if (mem.startsWith(u8, shdr_name, ".init_array")) {
                            break :name ".init_array";
                        } else if (mem.startsWith(u8, shdr_name, ".fini_array")) {
                            break :name ".fini_array";
                        } else {
                            break :name ".text";
                        }
                    }
                    if (flags & elf.SHF_WRITE != 0) {
                        if (flags & elf.SHF_TLS != 0) {
                            if (self.tls_seg_index == null) {
                                self.tls_seg_index = @intCast(u16, self.phdrs.items.len);
                                try self.phdrs.append(self.base.allocator, .{
                                    .p_type = elf.PT_TLS,
                                    .p_flags = elf.PF_R,
                                    .p_offset = 0,
                                    .p_vaddr = default_base_addr,
                                    .p_paddr = default_base_addr,
                                    .p_filesz = 0,
                                    .p_memsz = 0,
                                    .p_align = 0,
                                });
                            }
                            break :name ".tdata";
                        } else if (mem.startsWith(u8, shdr_name, ".data.rel.ro")) {
                            break :name ".data.rel.ro";
                        } else {
                            break :name ".data";
                        }
                    }
                    break :name ".rodata";
                },
                elf.SHT_NOBITS => {
                    if (flags & elf.SHF_TLS != 0) {
                        if (self.tls_seg_index == null) {
                            self.tls_seg_index = @intCast(u16, self.phdrs.items.len);
                            try self.phdrs.append(self.base.allocator, .{
                                .p_type = elf.PT_TLS,
                                .p_flags = elf.PF_R,
                                .p_offset = 0,
                                .p_vaddr = default_base_addr,
                                .p_paddr = default_base_addr,
                                .p_filesz = 0,
                                .p_memsz = 0,
                                .p_align = 0,
                            });
                        }
                        break :name ".tbss";
                    } else {
                        break :name ".bss";
                    }
                },
                else => break :name shdr_name,
            }
        };
        const res = self.getSectionByName(out_name) orelse try self.insertSection(shdr, out_name);
        if (mem.eql(u8, out_name, ".text")) {
            if (self.text_sect_index == null) {
                self.text_sect_index = res;
            }
        }
        break :blk res;
    };
    return res;
}

fn parsePositionals(self: *Elf, files: []const []const u8) !void {
    for (files) |file_name| {
        const full_path = full_path: {
            var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
            const path = try std.fs.realpath(file_name, &buffer);
            break :full_path try self.base.allocator.dupe(u8, path);
        };
        defer self.base.allocator.free(full_path);
        log.debug("parsing input file path '{s}'", .{full_path});

        if (try self.parseObject(full_path)) continue;
        if (try self.parseArchive(full_path)) continue;

        log.warn("unknown filetype for positional input file: '{s}'", .{file_name});
    }
}

fn parseLibs(self: *Elf, libs: []const []const u8) !void {
    for (libs) |lib| {
        log.debug("parsing lib path '{s}'", .{lib});
        if (try self.parseArchive(lib)) continue;

        log.warn("unknown filetype for a library: '{s}'", .{lib});
    }
}

fn parseObject(self: *Elf, path: []const u8) !bool {
    const gpa = self.base.allocator;
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    defer file.close();

    const name = try gpa.dupe(u8, path);
    const file_stat = try file.stat();
    const file_size = math.cast(usize, file_stat.size) orelse return error.Overflow;
    const data = try file.readToEndAlloc(gpa, file_size);

    const candidate = Object{
        .name = name,
        .data = data,
        .object_id = undefined,
    };
    if (!candidate.isValid()) return false;

    const object_id = @intCast(u32, self.objects.items.len);
    const object = try self.objects.addOne(gpa);
    object.* = candidate;
    object.object_id = object_id;
    try object.parse(self);

    if (self.cpu_arch == null) {
        self.cpu_arch = object.header.?.e_machine.toTargetCpuArch().?;
    }
    const cpu_arch = self.cpu_arch.?;
    if (cpu_arch != object.header.?.e_machine.toTargetCpuArch().?) {
        log.err("Invalid architecture {any}, expected {any}", .{
            object.header.?.e_machine,
            cpu_arch.toElfMachine(),
        });
        return error.InvalidCpuArch;
    }

    return true;
}

fn parseArchive(self: *Elf, path: []const u8) !bool {
    const gpa = self.base.allocator;
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    errdefer file.close();

    const name = try gpa.dupe(u8, path);
    const reader = file.reader();

    var archive = Archive{
        .name = name,
        .file = file,
    };

    archive.parse(gpa, reader) catch |err| switch (err) {
        error.EndOfStream, error.NotArchive => {
            archive.deinit(gpa);
            return false;
        },
        else => |e| return e,
    };

    try self.archives.append(gpa, archive);

    return true;
}

fn resolveSymbols(self: *Elf) !void {
    for (self.objects.items) |object| {
        try object.resolveSymbols(self);
    }
    try self.resolveSymbolsInArchives();
}

fn resolveSymbolsInArchives(self: *Elf) !void {
    if (self.archives.items.len == 0) return;

    var next_sym: usize = 0;
    loop: while (next_sym < self.globals.items.len) {
        const global = self.globals.items[next_sym];
        const global_name = global.getName(self);
        if (global.isUndef(self)) for (self.archives.items) |archive| {
            // Check if the entry exists in a static archive.
            const offsets = archive.toc.get(global_name) orelse {
                // No hit.
                continue;
            };
            assert(offsets.items.len > 0);

            const object_id = @intCast(u16, self.objects.items.len);
            const object = try archive.parseObject(offsets.items[0], object_id, self);
            try object.resolveSymbols(self);

            continue :loop;
        };

        next_sym += 1;
    }
}

fn resolveSyntheticSymbols(self: *Elf) !void {
    const object = &(self.internal_object orelse return);
    self.dynamic_sym_index = try object.addSyntheticGlobal("_DYNAMIC", self);
    self.init_array_start_sym_index = try object.addSyntheticGlobal("__init_array_start", self);
    self.init_array_end_sym_index = try object.addSyntheticGlobal("__init_array_end", self);
    self.fini_array_start_sym_index = try object.addSyntheticGlobal("__fini_array_start", self);
    self.fini_array_end_sym_index = try object.addSyntheticGlobal("__fini_array_end", self);
    try object.resolveSymbols(self);
}

fn checkDuplicates(self: *Elf) void {
    for (self.objects.items) |object| {
        object.checkDuplicates(self);
    }
}

fn checkUndefined(self: *Elf) void {
    for (self.objects.items) |object| {
        object.checkUndefined(self);
    }
}

pub fn addAtomToSection(self: *Elf, atom_index: Atom.Index, sect_id: u16) !void {
    const atom = self.getAtom(atom_index);
    atom.out_shndx = sect_id;
    var section = self.sections.get(sect_id);
    if (section.shdr.sh_size > 0) {
        const last_atom = self.getAtom(section.last_atom.?);
        last_atom.next = atom_index;
        atom.prev = section.last_atom.?;
    }
    section.last_atom = atom_index;
    const aligned_end_addr = mem.alignForwardGeneric(u64, section.shdr.sh_size, atom.alignment);
    const padding = aligned_end_addr - section.shdr.sh_size;
    section.shdr.sh_size += padding + atom.size;
    section.shdr.sh_addralign = @max(section.shdr.sh_addralign, atom.alignment);
    self.sections.set(sect_id, section);
}

fn allocateSection(self: *Elf, shdr: *elf.Elf64_Shdr, phdr: *elf.Elf64_Phdr) !void {
    const base_addr = phdr.p_vaddr + phdr.p_memsz;
    shdr.sh_addr = mem.alignForwardGeneric(u64, base_addr, shdr.sh_addralign);
    const p_memsz = shdr.sh_addr + shdr.sh_size - base_addr;

    const base_offset = phdr.p_offset + phdr.p_filesz;
    shdr.sh_offset = mem.alignForwardGeneric(u64, base_offset, shdr.sh_addralign);
    const p_filesz = shdr.sh_offset + shdr.sh_size - base_offset;

    if (shdr.sh_type == elf.SHT_NOBITS) {
        log.debug("allocating section '{s}' from 0x{x} to 0x{x} (no physical size)", .{
            self.shstrtab.getAssumeExists(shdr.sh_name),
            shdr.sh_addr,
            shdr.sh_addr + shdr.sh_size,
        });
    } else {
        log.debug("allocating section '{s}' from 0x{x} to 0x{x} (0x{x} - 0x{x})", .{
            self.shstrtab.getAssumeExists(shdr.sh_name),
            shdr.sh_addr,
            shdr.sh_addr + shdr.sh_size,
            shdr.sh_offset,
            shdr.sh_offset + shdr.sh_size,
        });
        phdr.p_filesz += p_filesz;
    }

    phdr.p_memsz += p_memsz;
}

const SegmentBase = struct {
    offset: u64,
    vaddr: u64,
    init_size: u64 = 0,
    alignment: ?u32 = null,
};

fn allocateSegment(self: *Elf, phdr_ndx: u16, shdr_ndxs: []const ?u16, base: SegmentBase) !void {
    const phdr = &self.phdrs.items[phdr_ndx];

    var min_align: u64 = 0;
    for (shdr_ndxs) |maybe_shdr_ndx| {
        const shdr_ndx = maybe_shdr_ndx orelse continue;
        const shdr = self.sections.items(.shdr)[shdr_ndx];
        min_align = @max(min_align, shdr.sh_addralign);
    }

    const p_align = base.alignment orelse min_align;
    const p_offset = mem.alignForwardGeneric(u64, base.offset, min_align);
    const p_vaddr = mem.alignForwardGeneric(u64, base.vaddr, p_align) + @rem(p_offset, p_align);

    phdr.p_offset = p_offset;
    phdr.p_vaddr = p_vaddr;
    phdr.p_paddr = p_vaddr;
    phdr.p_filesz = base.init_size;
    phdr.p_memsz = base.init_size;
    phdr.p_align = p_align;

    // This assumes ordering of section headers matches ordering of sections in file
    // so that the segments are contiguous in memory.
    for (shdr_ndxs) |maybe_shdr_ndx| {
        const shdr_ndx = maybe_shdr_ndx orelse continue;
        const shdr = &self.sections.items(.shdr)[shdr_ndx];
        try self.allocateSection(shdr, phdr);
    }

    log.debug("allocating segment of type {x} and flags {x}:", .{ phdr.p_type, phdr.p_flags });
    log.debug("  in file from 0x{x} to 0x{x}", .{ phdr.p_offset, phdr.p_offset + phdr.p_filesz });
    log.debug("  in memory from 0x{x} to 0x{x}", .{ phdr.p_vaddr, phdr.p_vaddr + phdr.p_memsz });
}

fn allocateLoadRSeg(self: *Elf) !void {
    const init_size = @sizeOf(elf.Elf64_Ehdr) + self.phdrs.items.len * @sizeOf(elf.Elf64_Phdr);
    try self.allocateSegment(self.load_r_seg_index.?, &.{
        self.getSectionByName(".rodata"),
    }, .{
        .offset = 0,
        .vaddr = default_base_addr,
        .init_size = init_size,
        .alignment = 0x1000,
    });
}

fn allocateLoadRESeg(self: *Elf) !void {
    const prev_seg = self.phdrs.items[self.load_r_seg_index.?];
    try self.allocateSegment(self.load_re_seg_index.?, &.{
        self.getSectionByName(".text"),
        self.getSectionByName(".init"),
        self.getSectionByName(".init_array"),
        self.getSectionByName(".fini"),
        self.getSectionByName(".fini_array"),
    }, .{
        .offset = prev_seg.p_offset + prev_seg.p_filesz,
        .vaddr = prev_seg.p_vaddr + prev_seg.p_memsz,
        .alignment = 0x1000,
    });

    if (self.tls_seg_index) |tls_seg_index| blk: {
        if (self.getSectionByName(".tdata")) |_| break :blk; // TLS segment contains tdata section, hence it will be part of RW
        const phdr = self.phdrs.items[self.load_re_seg_index.?];
        try self.allocateSegment(tls_seg_index, &.{
            self.getSectionByName(".tdata"),
            self.getSectionByName(".tbss"),
        }, .{
            .offset = phdr.p_offset + phdr.p_filesz,
            .vaddr = phdr.p_vaddr + phdr.p_memsz,
        });
    }
}

fn allocateLoadRWSeg(self: *Elf) !void {
    const base: SegmentBase = base: {
        if (self.tls_seg_index) |tls_seg_index| blk: {
            if (self.getSectionByName(".tdata")) |_| break :blk;
            const prev_seg = self.phdrs.items[tls_seg_index];
            break :base .{
                .offset = prev_seg.p_offset + prev_seg.p_filesz,
                .vaddr = prev_seg.p_vaddr + prev_seg.p_memsz,
                .alignment = 0x1000,
            };
        }
        const prev_seg = self.phdrs.items[self.load_re_seg_index.?];
        break :base .{
            .offset = prev_seg.p_offset + prev_seg.p_filesz,
            .vaddr = prev_seg.p_vaddr + prev_seg.p_memsz,
            .alignment = 0x1000,
        };
    };
    try self.allocateSegment(self.load_rw_seg_index.?, &.{
        self.getSectionByName(".tdata"),
        self.getSectionByName(".data.rel.ro"),
        self.getSectionByName(".got"),
        self.getSectionByName(".data"),
        self.getSectionByName(".bss"),
    }, base);

    const phdr = self.phdrs.items[self.load_rw_seg_index.?];

    if (self.getSectionByName(".tdata")) |_| {
        try self.allocateSegment(self.tls_seg_index.?, &.{
            self.getSectionByName(".tdata"),
            self.getSectionByName(".tbss"),
        }, .{
            .offset = phdr.p_offset,
            .vaddr = phdr.p_vaddr,
        });
    }
}

fn allocateNonAllocSections(self: *Elf) !void {
    var offset: u64 = 0;
    for (self.sections.items(.shdr)) |*shdr| {
        defer {
            offset = shdr.sh_offset + shdr.sh_size;
        }

        if (shdr.sh_type == elf.SHT_NULL) continue;
        if (shdr.sh_flags & elf.SHF_ALLOC != 0) continue;

        shdr.sh_offset = mem.alignForwardGeneric(u64, offset, shdr.sh_addralign);
        log.debug("setting '{s}' non-alloc section's offsets from 0x{x} to 0x{x}", .{
            self.shstrtab.getAssumeExists(shdr.sh_name),
            shdr.sh_offset,
            shdr.sh_offset + shdr.sh_size,
        });
    }
}

fn allocateAtoms(self: *Elf) !void {
    const slice = self.sections.slice();
    for (slice.items(.last_atom), 0..) |last_atom, i| {
        var atom_index = last_atom orelse continue;
        const shdr_ndx = @intCast(u16, i);
        const shdr = slice.items(.shdr)[shdr_ndx];

        // Find the first atom
        while (true) {
            const atom = self.getAtom(atom_index);
            if (atom.prev) |prev| {
                atom_index = prev;
            } else break;
        }

        log.debug("allocating atoms in '{s}' section", .{self.shstrtab.getAssumeExists(shdr.sh_name)});

        var base_addr: u64 = shdr.sh_addr;
        while (true) {
            const atom = self.getAtom(atom_index);
            base_addr = mem.alignForwardGeneric(u64, base_addr, atom.alignment);

            atom.value = base_addr;
            atom.out_shndx = shdr_ndx;

            log.debug("  ATOM(%{d},'{s}') allocated from 0x{x} to 0x{x}", .{
                atom_index,
                atom.getName(self),
                base_addr,
                base_addr + atom.size,
            });

            // Update each symbol contained within the Atom
            // Do it the long way for now until we get rid of synthetic sections first...
            const object = &self.objects.items[atom.file];
            for (object.symtab.items, 0..) |*inner_sym, inner_sym_i| {
                const inner_sym_index = @intCast(u32, inner_sym_i);
                const other_atom_index = object.atom_table.get(inner_sym_index) orelse continue;
                if (other_atom_index != atom_index) continue;
                inner_sym.st_value += base_addr;
                inner_sym.st_shndx = shdr_ndx;
            }

            base_addr += atom.size;

            if (atom.next) |next| {
                atom_index = next;
            } else break;
        }
    }
}

fn writeAtoms(self: *Elf) !void {
    const slice = self.sections.slice();
    for (slice.items(.last_atom), 0..) |last_atom, i| {
        var atom_index = last_atom orelse continue;
        const shdr_ndx = @intCast(u16, i);
        const shdr = slice.items(.shdr)[shdr_ndx];

        // TODO zero prefill .bss and .tbss if have presence in file
        if (shdr.sh_type == elf.SHT_NOBITS) continue;

        // Find the first atom
        while (true) {
            const atom = self.getAtom(atom_index);
            if (atom.prev) |prev| {
                atom_index = prev;
            } else break;
        }

        log.debug("writing atoms in '{s}' section", .{self.shstrtab.getAssumeExists(shdr.sh_name)});

        var buffer = try self.base.allocator.alloc(u8, shdr.sh_size);
        defer self.base.allocator.free(buffer);
        mem.set(u8, buffer, 0);

        var stream = std.io.fixedBufferStream(buffer);

        while (true) {
            const atom = self.getAtom(atom_index);
            const off = atom.value - shdr.sh_addr;
            log.debug("  writing ATOM(%{d},'{s}') at offset 0x{x}", .{
                atom_index,
                atom.getName(self),
                shdr.sh_offset + off,
            });
            try stream.seekTo(off);
            try atom.resolveRelocs(self, stream.writer());

            if (atom.next) |next| {
                atom_index = next;
            } else break;
        }

        try self.base.file.pwriteAll(buffer, shdr.sh_offset);
    }
}

fn setEntryPoint(self: *Elf) !void {
    if (self.options.output_mode != .exe) return;
    const global = try self.getEntryPoint();
    const sym = self.getSymbol(global);
    self.entry = sym.st_value;
}

fn setStackSize(self: *Elf) !void {
    const stack_size = self.options.stack_size orelse return;
    const gnu_stack_phdr_index = self.gnu_stack_phdr_index orelse blk: {
        const gnu_stack_phdr_index = @intCast(u16, self.phdrs.items.len);
        try self.phdrs.append(self.base.allocator, .{
            .p_type = elf.PT_GNU_STACK,
            .p_flags = elf.PF_R | elf.PF_W,
            .p_offset = 0,
            .p_vaddr = 0,
            .p_paddr = 0,
            .p_filesz = 0,
            .p_memsz = 0,
            .p_align = 0,
        });
        self.gnu_stack_phdr_index = gnu_stack_phdr_index;
        break :blk gnu_stack_phdr_index;
    };
    const phdr = &self.phdrs.items[gnu_stack_phdr_index];
    phdr.p_memsz = stack_size;
}

fn setSyntheticSections(self: *Elf) !void {
    // Currently, we only have .got to worry about.
    if (self.got_sect_index) |shndx| {
        const shdr = &self.sections.items(.shdr)[shndx];
        shdr.sh_size = self.got_section.size();
        shdr.sh_addralign = @sizeOf(u64);
    }
}

fn writeSyntheticSections(self: *Elf) !void {
    const gpa = self.base.allocator;
    // Currently, we only have .got to worry about.
    if (self.got_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, self.got_section.size());
        defer buffer.deinit();
        try self.got_section.write(self, buffer.writer());
        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
    }
}

fn writeSymtab(self: *Elf) !void {
    const offset: u64 = blk: {
        const shdr = self.sections.items(.shdr)[self.symtab_sect_index.? - 1];
        break :blk shdr.sh_offset + shdr.sh_size;
    };
    const shdr = &self.sections.items(.shdr)[self.symtab_sect_index.?];

    var symtab = std.ArrayList(elf.Elf64_Sym).init(self.base.allocator);
    defer symtab.deinit();
    try symtab.ensureUnusedCapacity(1);
    symtab.appendAssumeCapacity(.{
        .st_name = 0,
        .st_info = 0,
        .st_other = 0,
        .st_shndx = 0,
        .st_value = 0,
        .st_size = 0,
    });

    for (self.objects.items) |object| {
        for (object.symtab.items, 0..) |sym, sym_id| {
            if (sym.st_name == 0) continue;
            const st_bind = sym.st_info >> 4;
            const st_type = sym.st_info & 0xf;
            if (st_bind != elf.STB_LOCAL) continue;
            if (st_type == elf.STT_SECTION) continue;
            if (st_type == elf.STT_NOTYPE) continue;
            if (sym.st_other == @enumToInt(elf.STV.INTERNAL)) continue;
            if (sym.st_other == @enumToInt(elf.STV.HIDDEN)) continue;

            const sym_name = object.getSymbolName(@intCast(u32, sym_id));
            var out_sym = sym;
            out_sym.st_name = try self.strtab.insert(self.base.allocator, sym_name);
            try symtab.append(out_sym);
        }
    }

    for (self.locals.items) |sym| {
        const st_bind = sym.st_info >> 4;
        if (st_bind != elf.STB_LOCAL) continue;
        if (sym.st_other == @enumToInt(elf.STV.INTERNAL)) continue;
        if (sym.st_other == @enumToInt(elf.STV.HIDDEN)) continue;
        try symtab.append(sym);
    }

    // Denote start of globals
    shdr.sh_info = @intCast(u32, symtab.items.len);
    try symtab.ensureUnusedCapacity(self.globals.count());
    for (self.globals.values()) |global| {
        var sym = self.getSymbol(global);
        assert(sym.st_name > 0);
        // TODO refactor
        if (sym.st_info >> 4 == elf.STB_LOCAL) continue;
        const sym_name = self.getSymbolName(global);
        sym.st_name = try self.strtab.insert(self.base.allocator, sym_name);
        symtab.appendAssumeCapacity(sym);
    }

    shdr.sh_offset = mem.alignForwardGeneric(u64, offset, @alignOf(elf.Elf64_Sym));
    shdr.sh_size = symtab.items.len * @sizeOf(elf.Elf64_Sym);
    log.debug("writing '{s}' contents from 0x{x} to 0x{x}", .{
        self.shstrtab.getAssumeExists(shdr.sh_name),
        shdr.sh_offset,
        shdr.sh_offset + shdr.sh_size,
    });
    try self.base.file.pwriteAll(mem.sliceAsBytes(symtab.items), shdr.sh_offset);
}

fn writeStrtab(self: *Elf) !void {
    const offset: u64 = blk: {
        const shdr = self.sections.items(.shdr)[self.strtab_sect_index.? - 1];
        break :blk shdr.sh_offset + shdr.sh_size;
    };
    const buffer = try self.strtab.toOwnedSlice(self.base.allocator);
    defer self.base.allocator.free(buffer);
    const shdr = &self.sections.items(.shdr)[self.strtab_sect_index.?];
    shdr.sh_offset = offset;
    shdr.sh_size = buffer.len;
    log.debug("writing '{s}' contents from 0x{x} to 0x{x}", .{
        self.shstrtab.getAssumeExists(shdr.sh_name),
        shdr.sh_offset,
        shdr.sh_offset + shdr.sh_size,
    });
    try self.base.file.pwriteAll(buffer, shdr.sh_offset);
}

fn writeShStrtab(self: *Elf) !void {
    const offset: u64 = blk: {
        const shdr = self.sections.items(.shdr)[self.shstrtab_sect_index.? - 1];
        break :blk shdr.sh_offset + shdr.sh_size;
    };
    const buffer = try self.shstrtab.toOwnedSlice(self.base.allocator);
    defer self.base.allocator.free(buffer);
    const shdr = &self.sections.items(.shdr)[self.shstrtab_sect_index.?];
    shdr.sh_offset = offset;
    shdr.sh_size = buffer.len;
    log.debug("writing '.shstrtab' contents from 0x{x} to 0x{x}", .{
        shdr.sh_offset,
        shdr.sh_offset + shdr.sh_size,
    });
    try self.base.file.pwriteAll(buffer, shdr.sh_offset);
}

fn writePhdrs(self: *Elf) !void {
    const phoff = @sizeOf(elf.Elf64_Ehdr);
    const phdrs_size = self.phdrs.items.len * @sizeOf(elf.Elf64_Phdr);
    log.debug("writing program headers from 0x{x} to 0x{x}", .{ phoff, phoff + phdrs_size });
    try self.base.file.pwriteAll(mem.sliceAsBytes(self.phdrs.items), phoff);
}

fn writeShdrs(self: *Elf) !void {
    self.sections.items(.shdr)[self.symtab_sect_index.?].sh_link = self.strtab_sect_index.?;
    const offset: u64 = blk: {
        const shdr = self.sections.items(.shdr)[self.sections.len - 1];
        break :blk shdr.sh_offset + shdr.sh_size;
    };
    const shdrs_size = self.sections.items(.shdr).len * @sizeOf(elf.Elf64_Shdr);
    const shoff = mem.alignForwardGeneric(u64, offset, @alignOf(elf.Elf64_Shdr));
    log.debug("writing section headers from 0x{x} to 0x{x}", .{ shoff, shoff + shdrs_size });
    try self.base.file.pwriteAll(mem.sliceAsBytes(self.sections.items(.shdr)), shoff);
    self.shoff = shoff;
}

fn writeHeader(self: *Elf) !void {
    var header = elf.Elf64_Ehdr{
        .e_ident = undefined,
        .e_type = switch (self.options.output_mode) {
            .exe => elf.ET.EXEC,
            .lib => elf.ET.DYN,
        },
        .e_machine = self.cpu_arch.?.toElfMachine(),
        .e_version = 1,
        .e_entry = self.entry.?,
        .e_phoff = @sizeOf(elf.Elf64_Ehdr),
        .e_shoff = self.shoff.?,
        .e_flags = 0,
        .e_ehsize = @sizeOf(elf.Elf64_Ehdr),
        .e_phentsize = @sizeOf(elf.Elf64_Phdr),
        .e_phnum = @intCast(u16, self.phdrs.items.len),
        .e_shentsize = @sizeOf(elf.Elf64_Shdr),
        .e_shnum = @intCast(u16, self.sections.items(.shdr).len),
        .e_shstrndx = self.shstrtab_sect_index.?,
    };
    // Magic
    mem.copy(u8, header.e_ident[0..4], "\x7fELF");
    // Class
    header.e_ident[4] = elf.ELFCLASS64;
    // Endianness
    header.e_ident[5] = elf.ELFDATA2LSB;
    // ELF version
    header.e_ident[6] = 1;
    // OS ABI, often set to 0 regardless of target platform
    // ABI Version, possibly used by glibc but not by static executables
    // padding
    mem.set(u8, header.e_ident[7..][0..9], 0);
    log.debug("writing ELF header {} at 0x{x}", .{ header, 0 });
    try self.base.file.pwriteAll(mem.asBytes(&header), 0);
}

pub fn getSectionByName(self: *Elf, name: []const u8) ?u16 {
    for (self.sections.items(.shdr), 0..) |shdr, i| {
        const this_name = self.shstrtab.getAssumeExists(shdr.sh_name);
        if (mem.eql(u8, this_name, name)) return @intCast(u16, i);
    } else return null;
}

fn getGotBaseAddress(self: *Elf) u64 {
    const shndx = self.got_sect_index orelse return 0;
    const shdr = self.sections.items(.shdr)[shndx];
    return shdr.sh_addr;
}

fn writeGotEntry(self: *Elf, entry: SymbolWithLoc, writer: anytype) !void {
    if (self.got_sect_index == null) return;
    const sym = self.getSymbol(entry);
    try writer.writeIntLittle(u64, sym.st_value);
}

pub inline fn getString(self: *Elf, off: u32) [:0]const u8 {
    assert(off < self.strtab.buffer.items.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, self.strtab.buffer.items.ptr + off), 0);
}

/// Returns symbol localtion corresponding to the set entry point.
/// Asserts output mode is executable.
pub fn getEntryPoint(self: Elf) ?Symbol {
    assert(self.options.output_mode == .exe);
    const entry_name = self.options.entry orelse "_start";
    return self.globals.get(entry_name) orelse null;
}

pub fn addAtom(self: *Elf) !Atom.Index {
    const index = @intCast(u32, self.atoms.items.len);
    const atom = try self.atoms.addOne(self.base.allocator);
    atom.* = Atom.empty;
    return index;
}

pub fn getAtom(self: Elf, atom_index: Atom.Index) ?*Atom {
    if (atom_index == 0) return null;
    assert(atom_index < self.atoms.items.len);
    return &self.atoms.items[atom_index];
}

const GetOrCreateGlobalResult = struct {
    found_existing: bool,
    index: u32,
};

pub fn getOrCreateGlobal(self: *Elf, name: [:0]const u8) !GetOrCreateGlobalResult {
    const gpa = self.base.allocator;
    const gop = try self.globals_table.getOrPut(gpa, name);
    if (!gop.found_existing) {
        const index = @intCast(u32, self.globals.items.len);
        const global = try self.globals.addOne(gpa);
        global.* = .{ .name = try self.strtab.insert(gpa, name) };
        gop.value_ptr.* = index;
    }
    return .{
        .found_existing = gop.found_existing,
        .index = gop.value_ptr.*,
    };
}

pub fn getGlobal(self: *Elf, index: u32) *Symbol {
    assert(index < self.globals.items.len);
    return &self.globals.items[index];
}

fn logSections(self: Elf) void {
    log.debug("sections:", .{});
    for (self.sections.items(.shdr), 0..) |shdr, i| {
        log.debug("  sect({d}): {s} @{x}, sizeof({x})", .{
            i,
            self.shstrtab.getAssumeExists(shdr.sh_name),
            shdr.sh_offset,
            shdr.sh_size,
        });
    }
}
