/// Allocated address value of this symbol.
value: u32 = 0,

/// Offset into the string table, either global or local to object.
name: u32 = 0,

/// File where this symbol is defined.
file: File.Index = 0,

/// Atom containing this symbol if any.
/// Index 0 means there is no associated atom with this symbol.
/// Use `getAtom` to get the pointer to the atom.
atom: Atom.Index = 0,

/// Assigned output section.
out_section_number: u16 = 0,

/// Index of the source COFF symbol this symbol references.
/// Use `getCoffSymbol` to pull the COFF symbol from the relevant input file.
coff_sym_idx: Index = 0,

/// Misc flags for the symbol.
flags: Flags = .{},

extra: u32 = 0,

pub fn getName(symbol: Symbol, coff_file: *Coff) [:0]const u8 {
    if (symbol.flags.global) return coff_file.string_intern.getAssumeExists(symbol.name);
    return switch (symbol.getFile(coff_file).?) {
        .dll => unreachable, // There are no local symbols for DLLs
        inline else => |x| x.getString(symbol.name),
    };
}

pub fn getAltSymbol(symbol: Symbol, coff_file: *Coff) ?*Symbol {
    if (!symbol.flags.alt_name) return null;
    const extra = symbol.getExtra(coff_file).?;
    return coff_file.getSymbol(extra.alt_name);
}

pub fn getWeakFlag(symbol: Symbol, coff_file: *Coff) ?std.coff.WeakExternalFlag {
    if (!symbol.flags.weak) return null;
    const extra = symbol.getExtra(coff_file).?;
    return @enumFromInt(extra.weak_flag);
}

pub fn getFile(symbol: Symbol, coff_file: *Coff) ?File {
    return coff_file.getFile(symbol.file);
}

pub fn getAtom(symbol: Symbol, coff_file: *Coff) ?*Atom {
    return coff_file.getAtom(symbol.atom);
}

pub fn getAddress(symbol: Symbol, args: struct {
    alt: bool = true,
}, coff_file: *Coff) u32 {
    if (symbol.out_section_number == 0) return symbol.value;
    if (symbol.getFile(coff_file) == null) {
        if (args.alt and symbol.getAltSymbol(coff_file) != null) {
            const alt = symbol.getAltSymbol(coff_file).?;
            if (alt.getFile(coff_file)) |_| {
                const header = coff_file.sections.items(.header)[alt.out_section_number];
                return header.virtual_address + alt.value;
            }
        }
        return 0;
    }
    const header = coff_file.sections.items(.header)[symbol.out_section_number];
    return header.virtual_address + symbol.value;
}

pub fn getCoffSymbol(symbol: Symbol, coff_file: *Coff) Object.InputSymbol {
    const object = symbol.getFile(coff_file).?.object;
    return object.symtab.items[symbol.coff_sym_idx];
}

pub fn getSymbolRank(symbol: Symbol, coff_file: *Coff) u32 {
    const file = symbol.getFile(coff_file) orelse return std.math.maxInt(u32);
    const in_archive = switch (file) {
        .object => |x| !x.alive,
        else => false,
    };
    return file.getSymbolRank(.{
        .archive = in_archive,
        .common = symbol.flags.common,
    });
}

const AddExtraOpts = struct {
    alt_name: ?u32 = null,
    weak_flag: ?u32 = null,
    thunk: ?u32 = null,
};

pub fn addExtra(symbol: *Symbol, opts: AddExtraOpts, coff_file: *Coff) !void {
    if (symbol.getExtra(coff_file) == null) {
        symbol.extra = try coff_file.addSymbolExtra(.{});
    }
    var extra = symbol.getExtra(coff_file).?;
    inline for (@typeInfo(@TypeOf(opts)).Struct.fields) |field| {
        if (@field(opts, field.name)) |x| {
            @field(extra, field.name) = x;
        }
    }
    symbol.setExtra(extra, coff_file);
}

pub inline fn getExtra(symbol: Symbol, coff_file: *Coff) ?Extra {
    return coff_file.getSymbolExtra(symbol.extra);
}

pub inline fn setExtra(symbol: Symbol, extra: Extra, coff_file: *Coff) void {
    coff_file.setSymbolExtra(symbol.extra, extra);
}

pub fn format(
    symbol: Symbol,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = symbol;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compileError("do not format Symbol directly");
}

const FormatContext = struct {
    symbol: Symbol,
    coff_file: *Coff,
};

pub fn fmt(symbol: Symbol, coff_file: *Coff) std.fmt.Formatter(format2) {
    return .{ .data = .{
        .symbol = symbol,
        .coff_file = coff_file,
    } };
}

fn format2(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    const symbol = ctx.symbol;
    try writer.print("%{d} : {s} : @{x}", .{
        symbol.coff_sym_idx,
        symbol.getName(ctx.coff_file),
        symbol.getAddress(.{}, ctx.coff_file),
    });
    const file = symbol.getFile(ctx.coff_file) orelse blk: {
        if (symbol.getAltSymbol(ctx.coff_file)) |alt| {
            try writer.print(" : alt({s})", .{alt.getName(ctx.coff_file)});
            if (alt.getFile(ctx.coff_file)) |file| break :blk file;
        }
        try writer.writeAll(" : unresolved");
        return;
    };
    if (symbol.out_section_number != 0) {
        try writer.print(" : sect({d})", .{symbol.out_section_number});
    }
    if (symbol.getAtom(ctx.coff_file)) |atom| {
        try writer.print(" : atom({d})", .{atom.atom_index});
    }
    var buf: [2]u8 = .{'_'} ** 2;
    if (symbol.flags.@"export") buf[0] = 'E';
    if (symbol.flags.import) buf[1] = 'I';
    try writer.print(" : {s}", .{&buf});
    if (symbol.flags.weak) try writer.writeAll(" : weak");
    switch (file) {
        .internal => |x| try writer.print(" : internal({d})", .{x.index}),
        .object => |x| try writer.print(" : object({d})", .{x.index}),
        .dll => |x| try writer.print(" : dll({d})", .{x.index}),
    }
}

pub const Flags = packed struct {
    /// Whether the symbol is imported at runtime.
    import: bool = false,

    /// Whether the symbol is exported at runtime.
    @"export": bool = false,

    /// Whether the symbol is effectively an extern and takes part in global
    /// symbol resolution. Then, its name will be saved in global string interning
    /// table.
    global: bool = false,

    /// Whether the symbol is weak.
    weak: bool = false,

    /// Whether the symbol is a common definition.
    common: bool = false,

    /// Whether the symbol has alternate name.
    alt_name: bool = false,

    /// Whether the symbol has a jump thunk.
    thunk: bool = false,
};

pub const Extra = struct {
    alt_name: u32 = 0,
    weak_flag: u32 = 0,
    thunk: u32 = 0,
};

pub const Index = u32;

const std = @import("std");

const Atom = @import("Atom.zig");
const Coff = @import("../Coff.zig");
const File = @import("file.zig").File;
const Object = @import("Object.zig");
const Symbol = @This();
