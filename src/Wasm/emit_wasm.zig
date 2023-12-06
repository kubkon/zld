//! Writes all the wasm sections that are valid
//! to the final binary file that was passed to the `Wasm` object.
//! When a section contains no entries, the section will not be emitted.

const Object = @import("Object.zig");
const std = @import("std");
const Symbol = @import("Symbol.zig");
const types = @import("types.zig");
const Wasm = @import("../Wasm.zig");
const Atom = @import("Atom.zig");
const trace = @import("../tracy.zig").trace;

const fs = std.fs;
const leb = std.leb;
const log = std.log.scoped(.wasm);

/// Writes the given `Wasm` object into a binary file as-is.
pub fn emit(wasm: *Wasm) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const header_size = 5 + 1;

    var binary_bytes = std.ArrayList(u8).init(wasm.base.allocator);
    defer binary_bytes.deinit();
    const writer = binary_bytes.writer();

    // We write the magic bytes at the end so they will only be written
    // if everything succeeded as expected. So populate with 0's for now.
    try writer.writeAll(&[_]u8{0} ** 8);

    // emit sections
    if (wasm.func_types.count() != 0) {
        log.debug("Writing 'Types' section ({d})", .{wasm.func_types.count()});
        const offset = try reserveSectionHeader(&binary_bytes);
        for (wasm.func_types.items.items) |type_entry| {
            try emitType(type_entry, writer);
        }
        try emitSectionHeader(
            binary_bytes.items,
            offset,
            .type,
            @intCast(binary_bytes.items.len - offset - header_size),
            wasm.func_types.count(),
        );
    }
    if (wasm.imports.symbolCount() != 0 or wasm.options.import_memory) {
        const count = wasm.imports.symbolCount() + @intFromBool(wasm.options.import_memory);
        log.debug("Writing 'Imports' section ({d})", .{count});
        const offset = try reserveSectionHeader(&binary_bytes);

        if (wasm.options.import_memory) {
            const mem_import: std.wasm.Import = .{
                .module_name = "env",
                .name = "memory",
                .kind = .{ .memory = wasm.memories.limits },
            };
            try emitImport(mem_import, writer);
        }

        for (wasm.imports.symbols()) |sym_with_loc| {
            try emitImportSymbol(wasm, sym_with_loc, writer);
        }

        // TODO: Also emit GOT symbols
        try emitSectionHeader(
            binary_bytes.items,
            offset,
            .import,
            @intCast(binary_bytes.items.len - offset - header_size),
            count,
        );
    }
    if (wasm.functions.count() != 0) {
        log.debug("Writing 'Functions' section ({d})", .{wasm.functions.count()});
        const offset = try reserveSectionHeader(&binary_bytes);
        for (wasm.functions.items.values()) |func| {
            try emitFunction(func.func, writer);
        }
        try emitSectionHeader(
            binary_bytes.items,
            offset,
            .function,
            @intCast(binary_bytes.items.len - offset - header_size),
            wasm.functions.count(),
        );
    }
    if (wasm.tables.count() != 0) {
        log.debug("Writing 'Tables' section ({d})", .{wasm.tables.count()});
        const offset = try reserveSectionHeader(&binary_bytes);
        for (wasm.tables.items.items) |table| {
            try emitTable(table, writer);
        }
        try emitSectionHeader(
            binary_bytes.items,
            offset,
            .table,
            @intCast(binary_bytes.items.len - offset - header_size),
            wasm.tables.count(),
        );
    }
    if (!wasm.options.import_memory) {
        log.debug("Writing 'Memory' section", .{});
        const offset = try reserveSectionHeader(&binary_bytes);
        try emitLimits(wasm.memories.limits, writer);
        try emitSectionHeader(
            binary_bytes.items,
            offset,
            .memory,
            @intCast(binary_bytes.items.len - offset - header_size),
            1,
        );
    }
    if (wasm.globals.count() != 0) {
        log.debug("Writing 'Globals' section ({d})", .{wasm.globals.count()});
        const offset = try reserveSectionHeader(&binary_bytes);
        for (wasm.globals.items.items) |global| {
            try emitGlobal(global, writer);
        }
        try emitSectionHeader(
            binary_bytes.items,
            offset,
            .global,
            @intCast(binary_bytes.items.len - offset - header_size),
            wasm.globals.count(),
        );
    }
    if (wasm.exports.count() != 0) {
        log.debug("Writing 'Exports' section ({d})", .{wasm.exports.count()});
        const offset = try reserveSectionHeader(&binary_bytes);
        for (wasm.exports.items.items) |exported| {
            try emitExport(exported, writer);
        }
        try emitSectionHeader(
            binary_bytes.items,
            offset,
            .@"export",
            @intCast(binary_bytes.items.len - offset - header_size),
            wasm.exports.count(),
        );
    }

    if (wasm.entry) |entry_index| {
        const offset = try reserveSectionHeader(&binary_bytes);
        try emitSectionHeader(
            binary_bytes.items,
            offset,
            .start,
            @intCast(binary_bytes.items.len - offset - header_size),
            entry_index,
        );
    }

    if (wasm.elements.functionCount() != 0) {
        log.debug("Writing 'Element' section (1)", .{});
        const offset = try reserveSectionHeader(&binary_bytes);
        try emitElement(wasm, writer);
        try emitSectionHeader(
            binary_bytes.items,
            offset,
            .element,
            @intCast(binary_bytes.items.len - offset - header_size),
            1,
        );
    }

    const data_count = wasm.dataCount();
    if (data_count > 0 and wasm.options.shared_memory) {
        const offset = try reserveSectionHeader(&binary_bytes);
        try emitSectionHeader(
            binary_bytes.items,
            offset,
            .data_count,
            @intCast(binary_bytes.items.len - offset - header_size),
            data_count,
        );
    }

    if (wasm.code_section_index) |index| {
        log.debug("Writing 'Code' section ({d})", .{wasm.functions.count()});
        const offset = try reserveSectionHeader(&binary_bytes);
        var atom_index = wasm.atoms.get(index).?;
        atom_index = Atom.firstAtom(atom_index, wasm);

        // The code section must be sorted in line with the function order.
        var sorted_atoms = try std.ArrayList(*Atom).initCapacity(wasm.base.allocator, wasm.functions.count());
        defer sorted_atoms.deinit();

        while (atom_index != .none) {
            const atom = Atom.ptrFromIndex(wasm, atom_index);
            std.debug.assert(atom.symbolLoc().getSymbol(wasm).isAlive());
            atom.resolveRelocs(wasm);
            sorted_atoms.appendAssumeCapacity(atom);
            atom_index = atom.next;
        }

        const atom_sort_fn = struct {
            fn sort(ctx: *const Wasm, lhs: *const Atom, rhs: *const Atom) bool {
                const lhs_sym = lhs.symbolLoc().getSymbol(ctx);
                const rhs_sym = rhs.symbolLoc().getSymbol(ctx);
                return lhs_sym.index < rhs_sym.index;
            }
        }.sort;

        std.mem.sort(*Atom, sorted_atoms.items, wasm, atom_sort_fn);
        for (sorted_atoms.items) |sorted_atom| {
            try leb.writeULEB128(writer, sorted_atom.size);
            try writer.writeAll(sorted_atom.data[0..sorted_atom.size]);
        }
        std.debug.assert(sorted_atoms.items.len == wasm.functions.count()); // must have equal amount of bodies as functions
        try emitSectionHeader(
            binary_bytes.items,
            offset,
            .code,
            @intCast(binary_bytes.items.len - offset - header_size),
            wasm.functions.count(),
        );
    }

    if (data_count != 0) {
        log.debug("Writing 'Data' section ({d})", .{data_count});
        const offset = try reserveSectionHeader(&binary_bytes);

        var it = wasm.data_segments.iterator();
        while (it.next()) |entry| {
            // do not output the 'bss' section
            if (std.mem.eql(u8, entry.key_ptr.*, ".bss") and !wasm.options.import_memory) continue;
            var atom_index = wasm.atoms.get(entry.value_ptr.*).?;
            atom_index = Atom.firstAtom(atom_index, wasm);
            const segment: Wasm.Segment = wasm.segments.items[entry.value_ptr.*];

            try leb.writeULEB128(writer, segment.flags);
            if (segment.flags & @intFromEnum(Wasm.Segment.Flag.WASM_DATA_SEGMENT_HAS_MEMINDEX) != 0) {
                try leb.writeULEB128(writer, @as(u32, 0)); // memory is always index 0 as we only have 1 memory entry
            }
            if (!segment.isPassive()) {
                try emitInitExpression(.{ .i32_const = @as(i32, @bitCast(segment.offset)) }, writer);
            }
            try leb.writeULEB128(writer, segment.size);

            var current_offset: u32 = 0;
            while (atom_index != .none) {
                const atom = Atom.ptrFromIndex(wasm, atom_index);
                atom.resolveRelocs(wasm);
                // TODO: Verify if this is faster than allocating segment's size
                // Setting all zeroes, memcopy all segments and then writing.
                if (current_offset != atom.offset) {
                    const diff = atom.offset - current_offset;
                    try writer.writeByteNTimes(0, diff);
                    current_offset += diff;
                }
                std.debug.assert(current_offset == atom.offset);
                try writer.writeAll(atom.data[0..atom.size]);

                current_offset += atom.size;
                if (atom.next != .none) {
                    atom_index = atom.next;
                } else {
                    // Also make sure that if the last atom has extra bytes, we write 0's.
                    if (current_offset != segment.size) {
                        try writer.writeByteNTimes(0, segment.size - current_offset);
                        current_offset += segment.size - current_offset;
                    }
                    break;
                }
            }
            // when the last atom was unresolved and we skipped writing last few 0's so do it now
            if (current_offset != segment.size) {
                try writer.writeByteNTimes(0, segment.size - current_offset);
                current_offset += segment.size - current_offset;
            }
        }

        try emitSectionHeader(
            binary_bytes.items,
            offset,
            .data,
            @intCast(binary_bytes.items.len - offset - header_size),
            data_count,
        );
    }

    if (!wasm.options.strip) {
        // names section
        const func_count: u32 = wasm.functions.count() + wasm.imports.functionCount();
        const global_count: u32 = wasm.globals.count() + wasm.imports.globalCount();
        // we must de-duplicate symbols that point to the same function
        var funcs = std.AutoArrayHashMap(u32, Wasm.SymbolWithLoc).init(wasm.base.allocator);
        defer funcs.deinit();
        try funcs.ensureUnusedCapacity(func_count);
        var globals = try std.ArrayList(Wasm.SymbolWithLoc).initCapacity(wasm.base.allocator, global_count);
        defer globals.deinit();

        for (wasm.resolved_symbols.keys()) |sym_with_loc| {
            const symbol = sym_with_loc.getSymbol(wasm);
            if (symbol.isDead()) {
                continue;
            }
            switch (symbol.tag) {
                .function => {
                    const gop = try funcs.getOrPut(symbol.index);
                    if (!gop.found_existing) {
                        gop.value_ptr.* = sym_with_loc;
                    }
                },
                .global => globals.appendAssumeCapacity(sym_with_loc),
                else => {}, // do not emit 'names' section for other symbols
            }
        }

        std.mem.sort(Wasm.SymbolWithLoc, funcs.values(), wasm, lessThan);
        std.mem.sort(Wasm.SymbolWithLoc, globals.items, wasm, lessThan);

        const offset = try reserveCustomSectionHeader(&binary_bytes);
        try leb.writeULEB128(writer, @as(u32, @intCast("name".len)));
        try writer.writeAll("name");

        try emitNameSection(wasm, .function, funcs.values(), writer);
        try emitNameSection(wasm, .global, globals.items, writer);
        try emitDataNamesSection(wasm, writer);
        try emitCustomHeader(binary_bytes.items, offset, @intCast(binary_bytes.items.len - offset - 6));

        try emitDebugSections(wasm, &binary_bytes);
        try emitProducerSection(wasm, &binary_bytes);
    }
    try emitFeaturesSection(wasm, &binary_bytes);

    // Only when writing all sections executed properly we write the magic
    // bytes. This allows us to easily detect what went wrong while generating
    // the final binary.
    {
        const src = std.wasm.magic ++ std.wasm.version;
        binary_bytes.items[0..src.len].* = src;
    }

    // finally, write the entire binary into the file.
    var iovec = [_]std.os.iovec_const{.{
        .iov_base = binary_bytes.items.ptr,
        .iov_len = binary_bytes.items.len,
    }};
    try wasm.base.file.writevAll(&iovec);
}

/// Sorts symbols based on the index of the object they target
fn lessThan(wasm: *const Wasm, lhs: Wasm.SymbolWithLoc, rhs: Wasm.SymbolWithLoc) bool {
    const lhs_sym = lhs.getSymbol(wasm);
    const rhs_sym = rhs.getSymbol(wasm);
    return lhs_sym.index < rhs_sym.index;
}

fn emitSymbol(wasm: *const Wasm, loc: Wasm.SymbolWithLoc, writer: anytype) !void {
    const symbol = loc.getSymbol(wasm);
    const name = loc.getName(wasm);
    try leb.writeULEB128(writer, symbol.index);
    try leb.writeULEB128(writer, @as(u32, @intCast(name.len)));
    try writer.writeAll(name);
}

fn emitNameSection(
    wasm: *const Wasm,
    name_type: std.wasm.NameSubsection,
    items: []const Wasm.SymbolWithLoc,
    writer: anytype,
) !void {
    var section_list = std.ArrayList(u8).init(wasm.base.allocator);
    defer section_list.deinit();
    const sec_writer = section_list.writer();

    try leb.writeULEB128(sec_writer, @as(u32, @intCast(items.len)));
    for (items) |sym_loc| try emitSymbol(wasm, sym_loc, sec_writer);
    try leb.writeULEB128(writer, @intFromEnum(name_type));
    try leb.writeULEB128(writer, @as(u32, @intCast(section_list.items.len)));
    try writer.writeAll(section_list.items);
}

fn emitDataNamesSection(wasm: *Wasm, writer: anytype) !void {
    var section_list = std.ArrayList(u8).init(wasm.base.allocator);
    defer section_list.deinit();
    const sec_writer = section_list.writer();

    try leb.writeULEB128(sec_writer, wasm.dataCount());
    for (wasm.data_segments.keys(), 0..) |key, index| {
        if (std.mem.eql(u8, key, ".bss") and !wasm.options.import_memory) continue;
        try leb.writeULEB128(sec_writer, @as(u32, @intCast(index)));
        try leb.writeULEB128(sec_writer, @as(u32, @intCast(key.len)));
        try sec_writer.writeAll(key);
    }
    try leb.writeULEB128(writer, @as(u8, 0x09));
    try leb.writeULEB128(writer, @as(u32, @intCast(section_list.items.len)));
    try writer.writeAll(section_list.items);
}

/// Reserves enough space within the file to write our section header.
/// Returns the offset into the file where the header will be written.
fn reserveSectionHeader(bytes: *std.ArrayList(u8)) !u32 {
    // section id, section byte size, section entry count
    const header_size = 1 + 5 + 5;
    const offset: u32 = @intCast(bytes.items.len);
    try bytes.appendSlice(&[_]u8{0} ** header_size);
    return offset;
}

fn reserveCustomSectionHeader(bytes: *std.ArrayList(u8)) !u32 {
    // unlike regular section, we don't emit the count
    const header_size = 1 + 5;
    const offset: u32 = @intCast(bytes.items.len);
    try bytes.appendSlice(&[_]u8{0} ** header_size);
    return offset;
}

/// Emits the actual section header at the given `offset`.
/// Will write the section id, the section byte length, as well as the section entry count.
/// The amount of bytes is calculated using the current position, minus the offset (and reserved header bytes).
fn emitSectionHeader(buffer: []u8, offset: u32, section: std.wasm.Section, size: u32, items: u32) !void {
    // section id, section byte size, section entry count
    var buf: [1 + 5 + 5]u8 = undefined;
    buf[0] = @intFromEnum(section);
    leb.writeUnsignedFixed(5, buf[1..6], size);
    leb.writeUnsignedFixed(5, buf[6..], items);
    buffer[offset..][0..buf.len].* = buf;
    log.debug("Written section '{s}' offset=0x{x:0>8} size={d} count={d}", .{
        @tagName(section),
        offset,
        size,
        items,
    });
}

fn emitCustomHeader(buffer: []u8, offset: u32, size: u32) !void {
    var buf: [1 + 5]u8 = undefined;
    buf[0] = 0; // 0 = 'custom' section
    leb.writeUnsignedFixed(5, buf[1..6], size);
    buffer[offset..][0..buf.len].* = buf;
}

fn emitType(type_entry: std.wasm.Type, writer: anytype) !void {
    log.debug("Writing type {}", .{type_entry});
    try leb.writeULEB128(writer, @as(u8, 0x60)); //functype
    try leb.writeULEB128(writer, @as(u32, @intCast(type_entry.params.len)));
    for (type_entry.params) |para_ty| {
        try leb.writeULEB128(writer, @intFromEnum(para_ty));
    }
    try leb.writeULEB128(writer, @as(u32, @intCast(type_entry.returns.len)));
    for (type_entry.returns) |ret_ty| {
        try leb.writeULEB128(writer, @intFromEnum(ret_ty));
    }
}

fn emitImportSymbol(wasm: *Wasm, sym_loc: Wasm.SymbolWithLoc, writer: anytype) !void {
    const symbol = sym_loc.getSymbol(wasm).*;

    const import: std.wasm.Import = switch (symbol.tag) {
        .function => import: {
            const value = wasm.imports.imported_functions.values()[symbol.index];
            const key = wasm.imports.imported_functions.keys()[symbol.index];
            std.debug.assert(value.index == symbol.index);
            break :import .{
                .kind = .{ .function = value.type },
                .module_name = key.module_name,
                .name = key.name,
            };
        },
        .global => import: {
            const value = wasm.imports.imported_globals.values()[symbol.index];
            const key = wasm.imports.imported_globals.keys()[symbol.index];
            std.debug.assert(value.index == symbol.index);
            break :import .{
                .kind = .{ .global = value.global },
                .module_name = key.module_name,
                .name = key.name,
            };
        },
        .table => import: {
            const value = wasm.imports.imported_tables.values()[symbol.index];
            const key = wasm.imports.imported_tables.keys()[symbol.index];
            std.debug.assert(value.index == symbol.index);
            break :import .{
                .kind = .{ .table = value.table },
                .module_name = key.module_name,
                .name = key.name,
            };
        },
        else => unreachable,
    };

    try emitImport(import, writer);
}

fn emitImport(import_entry: std.wasm.Import, writer: anytype) !void {
    const module_name = import_entry.module_name;
    try leb.writeULEB128(writer, @as(u32, @intCast(module_name.len)));
    try writer.writeAll(module_name);

    const name = import_entry.name;
    try leb.writeULEB128(writer, @as(u32, @intCast(name.len)));
    try writer.writeAll(name);

    try leb.writeULEB128(writer, @intFromEnum(import_entry.kind));
    switch (import_entry.kind) {
        .function => |type_index| try leb.writeULEB128(writer, type_index),
        .table => |table| try emitTable(table, writer),
        .global => |global| {
            try leb.writeULEB128(writer, @intFromEnum(global.valtype));
            try leb.writeULEB128(writer, @intFromBool(global.mutable));
        },
        .memory => |mem| try emitLimits(mem, writer),
    }
}

fn emitFunction(func: std.wasm.Func, writer: anytype) !void {
    try leb.writeULEB128(writer, func.type_index);
}

fn emitTable(table: std.wasm.Table, writer: anytype) !void {
    try leb.writeULEB128(writer, @intFromEnum(table.reftype));
    try emitLimits(table.limits, writer);
}

fn emitLimits(limits: std.wasm.Limits, writer: anytype) !void {
    try leb.writeULEB128(writer, limits.flags);
    try leb.writeULEB128(writer, limits.min);
    if (limits.hasFlag(.WASM_LIMITS_FLAG_HAS_MAX)) {
        try leb.writeULEB128(writer, limits.max);
    }
}

fn emitGlobal(global: std.wasm.Global, writer: anytype) !void {
    try leb.writeULEB128(writer, @intFromEnum(global.global_type.valtype));
    try leb.writeULEB128(writer, @intFromBool(global.global_type.mutable));
    try emitInitExpression(global.init, writer);
}

fn emitInitExpression(init: std.wasm.InitExpression, writer: anytype) !void {
    switch (init) {
        .i32_const => |val| {
            try leb.writeULEB128(writer, std.wasm.opcode(.i32_const));
            try leb.writeILEB128(writer, val);
        },
        .global_get => |index| {
            try leb.writeULEB128(writer, std.wasm.opcode(.global_get));
            try leb.writeULEB128(writer, index);
        },
        else => @panic("TODO: Other init expression emission"),
    }
    try leb.writeULEB128(writer, std.wasm.opcode(.end));
}

fn emitExport(exported: std.wasm.Export, writer: anytype) !void {
    try leb.writeULEB128(writer, @as(u32, @intCast(exported.name.len)));
    try writer.writeAll(exported.name);
    try leb.writeULEB128(writer, @intFromEnum(exported.kind));
    try leb.writeULEB128(writer, exported.index);
}

fn emitElement(wasm: *Wasm, writer: anytype) !void {
    // passive, with implicit 0-index table
    const flags: u32 = 0;
    try leb.writeULEB128(writer, flags);
    // Start the function table at index 1
    try emitInitExpression(.{ .i32_const = 1 }, writer);
    try leb.writeULEB128(writer, wasm.elements.functionCount());
    var it = wasm.elements.indirect_functions.keyIterator();
    while (it.next()) |key_ptr| {
        try leb.writeULEB128(writer, key_ptr.*.getSymbol(wasm).index);
    }
}

const ProducerField = struct {
    value: []const u8,
    version: []const u8,

    const Context = struct {
        pub fn hash(ctx: Context, field: ProducerField) u32 {
            _ = ctx;
            var hasher = std.hash.Wyhash.init(0);
            hasher.update(field.value);
            hasher.update(field.version);
            return @as(u32, @truncate(hasher.final()));
        }

        pub fn eql(ctx: Context, lhs: ProducerField, rhs: ProducerField, index: usize) bool {
            _ = ctx;
            _ = index;
            return std.mem.eql(u8, lhs.value, rhs.value) and std.mem.eql(u8, lhs.version, rhs.version);
        }
    };
};

fn emitProducerSection(wasm: *const Wasm, bytes: *std.ArrayList(u8)) !void {
    const offset = try reserveCustomSectionHeader(bytes);
    const writer = bytes.writer();

    var languages_map = std.ArrayHashMap(ProducerField, void, ProducerField.Context, false).init(wasm.base.allocator);
    defer for (languages_map.keys()) |key| {
        wasm.base.allocator.free(key.value);
        wasm.base.allocator.free(key.version);
    } else languages_map.deinit();

    var processed_map = std.ArrayHashMap(ProducerField, void, ProducerField.Context, false).init(wasm.base.allocator);
    defer for (processed_map.keys()) |key| {
        wasm.base.allocator.free(key.value);
        wasm.base.allocator.free(key.version);
    } else processed_map.deinit();

    try processed_map.put(.{
        .value = try wasm.base.allocator.dupe(u8, "Zld"),
        .version = try wasm.base.allocator.dupe(u8, "0.1"),
    }, {});

    for (wasm.objects.items) |object| {
        if (object.producers.len != 0) {
            var fbs = std.io.fixedBufferStream(object.producers);
            const reader = fbs.reader();

            const field_count = try leb.readULEB128(u32, reader);
            var field_index: u32 = 0;
            while (field_index < field_count) : (field_index += 1) {
                const field_name_len = try leb.readULEB128(u32, reader);
                const field_name = try wasm.base.allocator.alloc(u8, field_name_len);
                defer wasm.base.allocator.free(field_name);
                try reader.readNoEof(field_name);

                const value_count = try leb.readULEB128(u32, reader);
                var value_index: u32 = 0;
                while (value_index < value_count) : (value_index += 1) {
                    const name_len = try leb.readULEB128(u32, reader);
                    const name = try wasm.base.allocator.alloc(u8, name_len);
                    errdefer wasm.base.allocator.free(name);
                    try reader.readNoEof(name);

                    const version_len = try leb.readULEB128(u32, reader);
                    const version = try wasm.base.allocator.alloc(u8, version_len);
                    errdefer wasm.base.allocator.free(version);
                    try reader.readNoEof(version);

                    log.debug("parsed producer field", .{});
                    log.debug("  value '{s}'", .{name});
                    log.debug("  version '{s}'", .{version});

                    if (std.mem.eql(u8, field_name, "language")) {
                        try languages_map.put(.{ .value = name, .version = version }, {});
                    } else if (std.mem.eql(u8, field_name, "processed-by")) {
                        try processed_map.put(.{ .value = name, .version = version }, {});
                    } else {
                        log.err("Invalid field name '{s}' in 'producers' section", .{field_name});
                        log.err("  referenced in '{s}'", .{object.name});
                    }
                }
            }
        }
    }

    const producers = "producers";
    try leb.writeULEB128(writer, @as(u32, @intCast(producers.len)));
    try writer.writeAll(producers);

    var fields_count: u32 = 1; // always have a processed-by field
    const languages_count = @as(u32, @intCast(languages_map.count()));

    if (languages_count > 0) {
        fields_count += 1;
    }

    try leb.writeULEB128(writer, @as(u32, fields_count));

    if (languages_count > 0) {
        const language = "language";
        try leb.writeULEB128(writer, @as(u32, @intCast(language.len)));
        try writer.writeAll(language);

        try leb.writeULEB128(writer, languages_count);

        for (languages_map.keys()) |field| {
            try leb.writeULEB128(writer, @as(u32, @intCast(field.value.len)));
            try writer.writeAll(field.value);

            try leb.writeULEB128(writer, @as(u32, @intCast(field.version.len)));
            try writer.writeAll(field.version);
        }
    }

    // processed-by field (this is never empty as it's always populated by Zld itself)
    {
        const processed_by = "processed-by";
        try leb.writeULEB128(writer, @as(u32, @intCast(processed_by.len)));
        try writer.writeAll(processed_by);

        try leb.writeULEB128(writer, @as(u32, @intCast(processed_map.count())));

        // versioned name
        for (processed_map.keys()) |field| {
            try leb.writeULEB128(writer, @as(u32, @intCast(field.value.len))); // len of "Zld"
            try writer.writeAll(field.value);

            try leb.writeULEB128(writer, @as(u32, @intCast(field.version.len)));
            try writer.writeAll(field.version);
        }
    }

    try emitCustomHeader(bytes.items, offset, @intCast(bytes.items.len - offset - 6));
}

fn emitFeaturesSection(wasm: *const Wasm, bytes: *std.ArrayList(u8)) !void {
    const used_count = wasm.used_features.count();
    if (used_count == 0) return; // when no features are used, we omit the entire section
    const offset = try reserveCustomSectionHeader(bytes);
    const writer = bytes.writer();

    const target_features = "target_features";
    try leb.writeULEB128(writer, @as(u32, @intCast(target_features.len)));
    try writer.writeAll(target_features);

    try leb.writeULEB128(writer, used_count);
    var it = wasm.used_features.iterator();
    while (it.next()) |feature_tag| {
        if (wasm.used_features.isEnabled(feature_tag)) {
            const feature: types.Feature = .{ .prefix = .used, .tag = feature_tag };
            try leb.writeULEB128(writer, @intFromEnum(feature.prefix));
            var buf: [100]u8 = undefined;
            const feature_name = try std.fmt.bufPrint(&buf, "{}", .{feature.tag});
            try leb.writeULEB128(writer, @as(u32, @intCast(feature_name.len)));
            try writer.writeAll(feature_name);
        }
    }

    try emitCustomHeader(bytes.items, offset, @intCast(bytes.items.len - offset - 6));
}

fn emitDebugSections(wasm: *const Wasm, bytes: *std.ArrayList(u8)) !void {
    const DebugSection = struct {
        name: []const u8,
        index: ?u32,
    };

    const debug_sections: []const DebugSection = &.{
        .{ .name = ".debug_info", .index = wasm.debug_info_index },
        .{ .name = ".debug_pubtypes", .index = wasm.debug_pubtypes_index },
        .{ .name = ".debug_abbrev", .index = wasm.debug_abbrev_index },
        .{ .name = ".debug_line", .index = wasm.debug_line_index },
        .{ .name = ".debug_str", .index = wasm.debug_str_index },
        .{ .name = ".debug_pubnames", .index = wasm.debug_pubnames_index },
        .{ .name = ".debug_loc", .index = wasm.debug_loc_index },
        .{ .name = ".debug_ranges", .index = wasm.debug_ranges_index },
    };

    for (debug_sections) |item| {
        if (item.index) |index| {
            const segment = wasm.segments.items[index];
            if (segment.size == 0) continue;
            try bytes.ensureUnusedCapacity(segment.size + 6 + item.name.len + 5);
            const header_offset = try reserveCustomSectionHeader(bytes);
            try leb.writeULEB128(bytes.writer(), @as(u32, @intCast(item.name.len)));
            bytes.appendSliceAssumeCapacity(item.name);
            var atom_index = wasm.atoms.get(index).?;
            atom_index = Atom.firstAtom(atom_index, wasm);
            while (atom_index != .none) {
                const atom = Atom.ptrFromIndex(wasm, atom_index);
                atom.resolveRelocs(wasm);
                bytes.appendSliceAssumeCapacity(atom.data[0..atom.size]);
                atom_index = atom.next;
            }
            try emitCustomHeader(bytes.items, header_offset, @intCast(bytes.items.len - header_offset - 6));
        }
    }
}
