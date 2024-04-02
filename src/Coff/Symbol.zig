/// Allocated address value of this symbol.
value: u64 = 0,

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
coff_sym_idx: u32 = 0,

/// Misc flags for the symbol.
flags: Flags = .{},

pub fn getName(symbol: Symbol, coff_file: *Coff) [:0]const u8 {
    if (symbol.flags.global) return coff_file.string_intern.getAssumeExists(symbol.name);
    return switch (symbol.getFile(coff_file).?) {
        .dll => unreachable, // There are no local symbols for DLLs
        inline else => |x| x.getString(symbol.name),
    };
}

pub fn getFile(symbol: Symbol, coff_file: *Coff) ?File {
    return coff_file.getFile(symbol.file);
}

pub fn getAtom(symbol: Symbol, coff_file: *Coff) ?*Atom {
    return coff_file.getAtom(symbol.atom);
}

pub fn getAddress(symbol: Symbol, args: struct {}, coff_file: *Coff) u64 {
    _ = args;
    if (symbol.out_section_number == 0) return symbol.value;
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
        .weak = false, // TODO
        .tentative = false, // TODO
    });
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
    if (symbol.getFile(ctx.coff_file)) |file| {
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
            .object => |x| try writer.print(" : object({d})", .{x.index}),
            .dll => |x| try writer.print(" : dll({d})", .{x.index}),
        }
    } else try writer.writeAll(" : unresolved");
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
};

pub const Index = u32;

const std = @import("std");

const Atom = @import("Atom.zig");
const Coff = @import("../Coff.zig");
const File = @import("file.zig").File;
const Object = @import("Object.zig");
const Symbol = @This();
