pub const RelocSection = struct {
    symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},

    pub fn deinit(rel: *RelocSection, allocator: Allocator) void {
        rel.symbols.deinit(allocator);
    }

    pub fn size(rel: RelocSection, coff_file: *Coff) u32 {
        // TODO
        _ = rel;
        _ = coff_file;
        return 0;
    }
};

const mem = std.mem;
const std = @import("std");

const Allocator = mem.Allocator;
const Coff = @import("../Coff.zig");
const Symbol = @import("Symbol.zig");
