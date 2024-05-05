pub const RelocSection = struct {
    entries: std.ArrayListUnmanaged(Entry) = .{},

    pub fn deinit(rel: *RelocSection, allocator: Allocator) void {
        rel.entries.deinit(allocator);
    }

    pub fn size(rel: RelocSection, coff_file: *Coff) u32 {
        // TODO
        _ = rel;
        _ = coff_file;
        return 0;
    }

    const Entry = struct {
        atom: Atom.Index,
        offset: u32,
    };
};

const mem = std.mem;
const std = @import("std");

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const Coff = @import("../Coff.zig");
const Symbol = @import("Symbol.zig");
