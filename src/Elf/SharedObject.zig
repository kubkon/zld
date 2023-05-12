name: []const u8,
data: []const u8,
index: u32,

pub fn deinit(self: *SharedObject, allocator: Allocator) void {
    allocator.free(self.name);
    allocator.free(self.data);
}

pub fn resolveSymbols(self: SharedObject, elf_file: *Elf) void {
    _ = self;
    _ = elf_file;
}

const SharedObject = @This();

const std = @import("std");

const Allocator = std.mem.Allocator;
const Elf = @import("../Elf.zig");
