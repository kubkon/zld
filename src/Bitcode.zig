const Elf = @This();

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const elf = std.elf;
const fs = std.fs;
const log = std.log.scoped(.elf);
const mem = std.mem;

const Allocator = mem.Allocator;
const Object = @import("Bitcode/Object.zig");
const Zld = @import("Zld.zig");

// reference documentation:
// https://llvm.org/docs/BitCodeFormat.html

pub const base_tag = Zld.Tag.bitcode;

base: Zld,
