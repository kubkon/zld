path: []const u8,
index: File.Index,

exports: std.MultiArrayList(Export) = .{},
exports_data: std.ArrayListUnmanaged(ExportData) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},
symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},

thunks: std.ArrayListUnmanaged(Thunk) = .{},
thunks_table: std.ArrayListUnmanaged(Thunk.Index) = .{},

alive: bool = false,
idata_ctx: IdataCtx = .{},

pub fn deinit(self: *Dll, allocator: Allocator) void {
    allocator.free(self.path);
    self.exports.deinit(allocator);
    self.exports_data.deinit(allocator);
    self.strtab.deinit(allocator);
    self.thunks.deinit(allocator);
    self.thunks_table.deinit(allocator);
}

pub fn initSymbols(self: *Dll, coff_file: *Coff) !void {
    const gpa = coff_file.base.allocator;
    try self.symbols.ensureTotalCapacityPrecise(gpa, self.exports.items(.name).len);
    for (self.exports.items(.name)) |name| {
        const off = try coff_file.string_intern.insert(gpa, self.getString(name));
        const gop = try coff_file.getOrCreateGlobal(off);
        self.symbols.addOneAssumeCapacity().* = gop.index;
    }
}

pub fn addExport(self: *Dll, coff_file: *Coff, args: struct {
    name: [:0]const u8,
    strings: []const u8,
    type: coff.ImportType,
    name_type: coff.ImportNameType,
    hint: u16,
}) !void {
    const gpa = coff_file.base.allocator;
    const imp_name = try std.fmt.allocPrint(gpa, "__imp_{s}", .{args.name});
    defer gpa.free(imp_name);
    const ext_name = switch (args.name_type) {
        .ORDINAL => "",
        .NAME => args.name,
        .NAME_NOPREFIX => mem.trimLeft(u8, args.name, "?@_"),
        .NAME_UNDECORATE => blk: {
            const trimmed = std.mem.trimLeft(u8, args.name, "?@_");
            const index = std.mem.indexOf(u8, trimmed, "@") orelse trimmed.len;
            break :blk trimmed[0..index];
        },
        .NAME_EXPORTAS => blk: {
            const offset = args.name.len + 1 + self.path.len + 1;
            break :blk mem.sliceTo(@as([*:0]const u8, @ptrCast(args.strings.ptr + offset)), 0);
        },
        else => |other| {
            coff_file.base.fatal("{s}: unknown IMPORT_OBJECT_NAME_type variant: 0x{x}", .{
                self.path,
                other,
            });
            return error.ParseFailed;
        },
    };
    const data_index: ExportData.Index = @intCast(self.exports_data.items.len);
    try self.exports_data.append(gpa, .{
        .name = try self.addString(gpa, ext_name),
        .hint = args.hint,
        .type = args.type,
    });
    try self.exports.append(gpa, .{
        .name = try self.addString(gpa, imp_name),
        .data = data_index,
        .kind = .direct,
    });

    switch (args.type) {
        .CODE, .CONST => {
            const kind: Export.Kind = switch (args.type) {
                .CODE => .thunk,
                .CONST => .alias,
                else => unreachable,
            };
            try self.exports.append(gpa, .{
                .name = try self.addString(gpa, args.name),
                .data = data_index,
                .kind = kind,
            });
        },
        .DATA => {},
        else => |other| {
            coff_file.base.fatal("{s}: unknown IMPORT_OBJECT_type variant: 0x{x}", .{
                self.path,
                other,
            });
            return error.ParseFailed;
        },
    }
}

pub fn resolveSymbols(self: *Dll, coff_file: *Coff) void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.symbols.items) |index| {
        const global = coff_file.getSymbol(index);
        if (self.asFile().getSymbolRank(.{}) < global.getSymbolRank(coff_file)) {
            global.value = 0;
            global.atom = 0;
            global.coff_sym_idx = 0;
            global.file = self.index;
        }
    }
}

pub fn addThunks(self: *Dll, coff_file: *Coff) !void {
    const gpa = coff_file.base.allocator;
    // Index 0 is reserved for null thunk.
    try self.thunks.append(gpa, .{});
    // Create null thunks
    try self.thunks_table.ensureTotalCapacityPrecise(gpa, self.symbols.items.len);
    try self.thunks_table.resize(gpa, self.symbols.items.len);
    @memset(self.thunks_table.items, 0);

    for (self.symbols.items, self.exports.items(.kind), 0..) |sym_index, exp_kind, index| {
        const sym = coff_file.getSymbol(sym_index);
        if (!sym.flags.import) continue;

        switch (exp_kind) {
            .thunk => {
                const thunk_index: Thunk.Index = @intCast(self.thunks.items.len);
                try self.thunks.append(gpa, .{ .sym_index = sym_index });
                try sym.addExtra(.{ .thunk = thunk_index }, coff_file);
                self.thunks_table.items[index] = thunk_index;
                sym.flags.thunk = true;
            },
            .alias, .direct => {},
        }
    }
}

pub fn updateImportSectionSize(self: *Dll, coff_file: *Coff) !void {
    const ctx = &self.idata_ctx;
    var iat: u32 = 0;
    var names: u32 = 0;
    for (self.symbols.items, self.exports.items(.data)) |sym_index, exp_index| {
        const sym = coff_file.getSymbol(sym_index);
        if (!sym.flags.import) continue;

        const exp = self.exports_data.items[exp_index];
        if (exp.byName(self)) |res| {
            try sym.addExtra(.{ .names = names }, coff_file);
            sym.flags.names = true;
            var size: u32 = @sizeOf(u16) + @as(u32, @intCast(res.name.len + 1));
            if (size % 2 != 0) size += 1;
            ctx.names_table_size += size;
            names += size;
        }

        try sym.addExtra(.{ .iat = iat }, coff_file);
        iat += 1;
    }

    ctx.lookup_table_size = (iat + 1) * @sizeOf(u64);
    ctx.iat_size = (iat + 1) * @sizeOf(u64);
    ctx.dll_names_size += @as(u32, @intCast(self.path.len)) + 1;
}

pub fn writeImportSection(self: *Dll, buffer: []u8, coff_file: *Coff) !void {
    const ctx = self.idata_ctx;
    const base_addr = coff_file.sections.items(.header)[coff_file.idata_section_index.?].virtual_address;
    // Dir header
    const dir_header = coff.ImportDirectoryEntry{
        .import_lookup_table_rva = base_addr + ctx.lookup_table_offset,
        .time_date_stamp = 0,
        .forwarder_chain = 0,
        .name_rva = base_addr + ctx.dll_names_offset,
        .import_address_table_rva = base_addr + ctx.iat_offset,
    };
    @memcpy(buffer[ctx.dir_table_offset..][0..@sizeOf(coff.ImportDirectoryEntry)], mem.asBytes(&dir_header));

    // Lookup and IAT entries
    for (self.symbols.items, self.exports.items(.data)) |sym_index, exp_index| {
        const sym = coff_file.getSymbol(sym_index);
        if (!sym.flags.import) continue;

        const exp = self.exports_data.items[exp_index];
        const extra = sym.getExtra(coff_file).?;
        if (exp.byOrdinal(self)) |ord| {
            const lookup_entry = coff.ImportLookupEntry64.ByOrdinal{
                .ordinal_number = ord,
            };
            @memcpy(buffer[ctx.lookup_table_offset + extra.iat * @sizeOf(u64) ..][0..@sizeOf(u64)], mem.asBytes(&lookup_entry));
            @memcpy(buffer[ctx.iat_offset + extra.iat * @sizeOf(u64) ..][0..@sizeOf(u64)], mem.asBytes(&lookup_entry));
        } else if (exp.byName(self)) |res| {
            const lookup_entry = coff.ImportLookupEntry64.ByName{
                .name_table_rva = @intCast(base_addr + ctx.names_table_offset + extra.names),
            };
            @memcpy(buffer[ctx.lookup_table_offset + extra.iat * @sizeOf(u64) ..][0..@sizeOf(u64)], mem.asBytes(&lookup_entry));
            @memcpy(buffer[ctx.iat_offset + extra.iat * @sizeOf(u64) ..][0..@sizeOf(u64)], mem.asBytes(&lookup_entry));

            mem.writeInt(u16, buffer[ctx.names_table_offset + extra.names ..][0..2], res.hint, .little);
            @memcpy(buffer[ctx.names_table_offset + extra.names + 2 ..][0..res.name.len], res.name);
        } else unreachable;
    }

    // DLL name
    @memcpy(buffer[ctx.dll_names_offset..][0..self.path.len], self.path);
}

fn addString(self: *Dll, allocator: Allocator, str: []const u8) error{OutOfMemory}!u32 {
    const off = @as(u32, @intCast(self.strtab.items.len));
    try self.strtab.writer(allocator).print("{s}\x00", .{str});
    return off;
}

pub fn getString(self: Dll, off: u32) [:0]const u8 {
    assert(off < self.strtab.items.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(self.strtab.items.ptr + off)), 0);
}

pub fn getThunk(self: Dll, index: Thunk.Index) ?*Thunk {
    if (index == 0) return null;
    return &self.thunks.items[index];
}

pub fn asFile(self: *Dll) File {
    return .{ .dll = self };
}

pub fn format(
    self: Dll,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = self;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compileError("do not format Dll directly");
}

const FormatContext = struct { Dll, *Coff };

pub fn fmtSymbols(self: Dll, coff_file: *Coff) std.fmt.Formatter(formatSymbols) {
    return .{ .data = .{ self, coff_file } };
}

fn formatSymbols(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const dll, const coff_file = ctx;
    try writer.writeAll("  symbols\n");
    for (dll.symbols.items) |index| {
        const symbol = coff_file.getSymbol(index);
        try writer.print("    {}\n", .{symbol.fmt(coff_file)});
    }
}

pub fn fmtThunks(self: Dll, coff_file: *Coff) std.fmt.Formatter(formatThunks) {
    return .{ .data = .{ self, coff_file } };
}

fn formatThunks(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const dll, const coff_file = ctx;
    try writer.writeAll("  thunks\n");
    for (dll.thunks_table.items) |index| {
        const thunk = dll.getThunk(index) orelse continue;
        try writer.print("    {d} : {}\n", .{ index, thunk.fmt(coff_file) });
    }
}

pub fn fmtPath(self: Dll) std.fmt.Formatter(formatPath) {
    return .{ .data = self };
}

fn formatPath(
    dll: Dll,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    try writer.writeAll(dll.path);
}

pub fn fmtPathShort(self: Dll) std.fmt.Formatter(formatPathShort) {
    return .{ .data = self };
}

fn formatPathShort(
    dll: Dll,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    try writer.writeAll(std.fs.path.basename(dll.path));
}

const Export = struct {
    name: u32,
    data: ExportData.Index,
    kind: Kind,

    const Kind = enum {
        direct,
        thunk,
        alias,
    };
};

const ExportData = packed struct {
    /// Actual export name which doesn't take part in symbol resolution.
    name: u32,
    hint: u16,
    type: coff.ImportType,

    fn byName(expdat: ExportData, dll: *const Dll) ?ByName {
        const name = dll.getString(expdat.name);
        if (name.len == 0) return null;
        return .{ .name = name, .hint = expdat.hint };
    }

    fn byOrdinal(expdat: ExportData, dll: *const Dll) ?u16 {
        if (expdat.byName(dll)) |_| return null;
        return expdat.hint;
    }

    const Index = u32;

    const ByName = struct {
        name: [:0]const u8,
        hint: u16,
    };
};

/// Import thunk
pub const Thunk = struct {
    value: u32 = 0,
    out_section_number: ?u16 = null,
    sym_index: Symbol.Index = 0,

    pub fn thunkAlignment(coff_file: *Coff) u4 {
        const cpu_arch = coff_file.options.cpu_arch.?;
        return switch (cpu_arch) {
            .aarch64 => 2,
            .x86_64 => 0,
            else => @panic("unhandled arch"),
        };
    }

    pub fn thunkSize(coff_file: *Coff) u32 {
        const cpu_arch = coff_file.options.cpu_arch.?;
        return switch (cpu_arch) {
            .aarch64 => 3 * @sizeOf(u64),
            .x86_64 => 6,
            else => @panic("unhandled arch"),
        };
    }

    pub fn getSymbol(thunk: Thunk, coff_file: *Coff) *Symbol {
        return coff_file.getSymbol(thunk.sym_index);
    }

    pub fn getAddress(thunk: Thunk, coff_file: *Coff) u32 {
        const sect_index = thunk.out_section_number orelse return 0;
        return coff_file.sections.items(.header)[sect_index].virtual_address + thunk.value;
    }

    pub fn write(thunk: Thunk, buffer: []u8, coff_file: *Coff) !void {
        assert(buffer.len == thunkSize(coff_file));
        const cpu_arch = coff_file.options.cpu_arch.?;
        const sym = thunk.getSymbol(coff_file);
        const P: i64 = @intCast(thunk.getAddress(coff_file));
        const S: i64 = @intCast(sym.getIATAddress(coff_file));
        switch (cpu_arch) {
            .aarch64 => @panic("TODO aarch64"),
            .x86_64 => {
                @memcpy(buffer, &[_]u8{ 0xff, 0x25, 0x00, 0x00, 0x00, 0x00 });
                mem.writeInt(i32, buffer[2..][0..4], @intCast(S - P - 4), .little);
            },
            else => @panic("unhandled arch"),
        }
    }

    pub fn format(
        thunk: Thunk,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = thunk;
        _ = unused_fmt_string;
        _ = options;
        _ = writer;
        @compileError("do not format Thunk directly");
    }

    pub fn fmt(thunk: Thunk, coff_file: *Coff) std.fmt.Formatter(format2) {
        return .{ .data = .{ thunk, coff_file } };
    }

    const ThunkFormatContext = struct { Thunk, *Coff };

    fn format2(
        ctx: ThunkFormatContext,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = unused_fmt_string;
        const thunk, const coff_file = ctx;
        const target_sym = thunk.getSymbol(coff_file);
        try writer.print("@{x} : size({x}) : {s} : @{x}", .{
            thunk.getAddress(coff_file),
            thunkSize(coff_file),
            target_sym.getName(coff_file),
            target_sym.getAddress(.{}, coff_file),
        });
    }

    const Index = u32;
};

const IdataCtx = struct {
    /// Import directory table size for DLL is always fixed so we don't track it.
    dir_table_offset: u32 = 0,
    lookup_table_offset: u32 = 0,
    lookup_table_size: u32 = 0,
    names_table_offset: u32 = 0,
    names_table_size: u32 = 0,
    dll_names_offset: u32 = 0,
    dll_names_size: u32 = 0,
    iat_offset: u32 = 0,
    iat_size: u32 = 0,
};

const assert = std.debug.assert;
const coff = std.coff;
const log = std.log.scoped(.coff);
const mem = std.mem;
const std = @import("std");
const trace = @import("../tracy.zig").trace;

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const Coff = @import("../Coff.zig");
const Dll = @This();
const File = @import("file.zig").File;
const Symbol = @import("Symbol.zig");
