path: []const u8,
index: File.Index,

exports: std.ArrayListUnmanaged(Export) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},
symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
thunks: std.ArrayListUnmanaged(Thunk) = .{},
thunks_table: std.ArrayListUnmanaged(Thunk.Index) = .{},

alive: bool = false,
idata_ctx: IdataCtx = .{},

pub fn deinit(self: *Dll, allocator: Allocator) void {
    allocator.free(self.path);
    self.exports.deinit(allocator);
    self.strtab.deinit(allocator);
    self.thunks.deinit(allocator);
    self.thunks_table.deinit(allocator);
}

pub fn initSymbols(self: *Dll, coff_file: *Coff) !void {
    const gpa = coff_file.base.allocator;
    try self.symbols.ensureTotalCapacityPrecise(gpa, self.exports.items.len);
    for (self.exports.items) |exp| {
        const name = exp.getImportName(self);
        const off = try coff_file.string_intern.insert(gpa, name);
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
            coff_file.base.fatal("{s}: unhandled IMPORT_OBJECT_NAME_TYPE variant: {}", .{
                self.path,
                other,
            });
            return error.ParseFailed;
        },
    };
    try self.exports.append(gpa, .{
        .imp_name = try self.addString(gpa, imp_name),
        .ext_name = try self.addString(gpa, ext_name),
        .hint = args.hint,
        .type = args.type,
    });
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

    for (self.symbols.items, self.exports.items, 0..) |sym_index, exp, index| {
        const sym = coff_file.getSymbol(sym_index);
        if (!sym.flags.import) continue;

        switch (exp.type) {
            .CODE => {
                const thunk_index: Thunk.Index = @intCast(self.thunks.items.len);
                try self.thunks.append(gpa, .{
                    .sym_index = sym_index,
                    .exp_index = @intCast(index),
                });
                try sym.addExtra(.{ .thunk = thunk_index }, coff_file);
                self.thunks_table.items[index] = thunk_index;
                sym.flags.thunk = true;
            },
            .DATA, .CONST => {},
            else => unreachable, // Already reported in addExport()
        }
    }
}

pub fn updateIdataSize(self: *Dll, coff_file: *Coff) !void {
    const ctx = &self.idata_ctx;
    var index: u32 = 0;
    for (self.symbols.items, self.exports.items) |sym_index, exp| {
        const sym = coff_file.getSymbol(sym_index);
        if (!sym.flags.import) continue;

        if (!exp.isByOrdinal(self)) {
            ctx.names_table_size += @sizeOf(u16) + @as(u32, @intCast(exp.getExternName(self).len)) + 1;
            if (ctx.names_table_size % 2 != 0) ctx.names_table_size += 1;
        }

        try sym.addExtra(.{ .iat = index }, coff_file);
        index += 1;
    }

    ctx.lookup_table_size = index * @sizeOf(u64);
    ctx.iat_size = index * @sizeOf(u64);
    ctx.dll_names_size += @as(u32, @intCast(self.path.len)) + 1;
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

pub const Export = packed struct {
    imp_name: u32,
    ext_name: u32,
    hint: u16,
    type: coff.ImportType,

    pub fn getImportName(exp: Export, dll: *const Dll) [:0]const u8 {
        return dll.getString(exp.imp_name);
    }

    pub fn getExternName(exp: Export, dll: *const Dll) [:0]const u8 {
        return dll.getString(exp.ext_name);
    }

    pub fn isByOrdinal(exp: Export, dll: *const Dll) bool {
        return exp.getExternName(dll).len == 0;
    }
};

/// Import thunk
pub const Thunk = struct {
    value: u32 = 0,
    out_section_number: u16 = 0,
    sym_index: Symbol.Index = 0,
    exp_index: u32 = 0,

    pub fn getSize(thunk: Thunk, coff_file: *Coff) usize {
        _ = thunk;
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
            thunk.value,
            thunk.getSize(coff_file),
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
const Coff = @import("../Coff.zig");
const Dll = @This();
const File = @import("file.zig").File;
const Symbol = @import("Symbol.zig");
