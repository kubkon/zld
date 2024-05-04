pub const IdataSection = struct {
    entries: std.ArrayListUnmanaged(Entry) = .{},

    pub fn deinit(idata: *IdataSection, allocator: Allocator) void {
        idata.entries.deinit(allocator);
    }

    pub fn addThunk(
        idata: *IdataSection,
        sym_index: Symbol.Index,
        exp_index: u32,
        coff_file: *Coff,
    ) !void {
        const index: u32 = @intCast(idata.entries.items.len);
        try idata.entries.append(coff_file.base.allocator, .{
            .sym_index = sym_index,
            .exp_index = exp_index,
        });
        const sym = coff_file.getSymbol(sym_index);
        try sym.addExtra(.{ .import_thunk = index }, coff_file);
    }

    const Entry = struct {
        sym_index: Symbol.Index,
        exp_index: u32,

        pub fn getSymbol(entry: Entry, coff_file: *Coff) *Symbol {
            return coff_file.getSymbol(entry.sym_index);
        }

        pub fn getExport(entry: Entry, coff_file: *Coff) Dll.Export {
            const sym = coff_file.getSymbol(entry.sym_index);
            const dll = sym.getFile(coff_file).?.dll;
            return dll.exports.items[entry.exp_index];
        }
    };
};

const mem = std.mem;
const std = @import("std");

const Allocator = mem.Allocator;
const Coff = @import("../Coff.zig");
const Dll = @import("Dll.zig");
const Symbol = @import("Symbol.zig");
