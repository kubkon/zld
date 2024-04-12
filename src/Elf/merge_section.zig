pub const MergeSection = struct {
    out_shndx: u32 = 0,
    bytes: std.ArrayListUnmanaged(u8) = .{},
    table: std.HashMapUnmanaged(
        u32,
        MergeSubsection.Index,
        IndexContext,
        std.hash_map.default_max_load_percentage,
    ) = .{},

    pub fn deinit(msec: *MergeSection, allocator: Allocator) void {
        msec.bytes.deinit(allocator);
        msec.table.deinit(allocator);
    }

    pub fn getAddress(msec: MergeSection, elf_file: *Elf) u64 {
        const shdr = elf_file.sections.items(.shdr)[msec.out_shndx];
        return shdr.sh_addr;
    }

    const InsertResult = struct {
        found_existing: bool,
        index: u32,
        sub: *MergeSubsection.Index,
    };

    pub fn insert(msec: *MergeSection, allocator: Allocator, string: []const u8) !InsertResult {
        const gop = try msec.table.getOrPutContextAdapted(
            allocator,
            string,
            IndexAdapter{ .bytes = msec.bytes.items, .entsize = @intCast(string.len) },
            IndexContext{ .bytes = msec.bytes.items, .entsize = @intCast(string.len) },
        );
        if (!gop.found_existing) {
            const index: u32 = @intCast(msec.bytes.items.len);
            try msec.bytes.appendSlice(allocator, string);
            gop.key_ptr.* = index;
        }
        return .{ .found_existing = gop.found_existing, .index = gop.key_ptr.*, .sub = gop.value_ptr };
    }

    pub const IndexContext = struct {
        bytes: []const u8,
        entsize: u32,

        pub fn eql(_: @This(), a: u32, b: u32) bool {
            return a == b;
        }

        pub fn hash(ctx: @This(), key: u32) u64 {
            const str = ctx.bytes[key..][0..ctx.entsize];
            return std.hash_map.hashString(str);
        }
    };

    pub const IndexAdapter = struct {
        bytes: []const u8,
        entsize: u32,

        pub fn eql(ctx: @This(), a: []const u8, b: u32) bool {
            const str = ctx.bytes[b..][0..ctx.entsize];
            return mem.eql(u8, a, str);
        }

        pub fn hash(_: @This(), adapted_key: []const u8) u64 {
            return std.hash_map.hashString(adapted_key);
        }
    };

    pub const Index = u32;
};

pub const MergeSubsection = struct {
    value: u64 = 0,
    merge_section: MergeSection.Index = 0,
    string_index: u32 = 0,
    size: u32 = 0,
    alignment: u8 = 0,
    alive: bool = true,

    pub fn getAddress(msub: MergeSubsection, elf_file: *Elf) u64 {
        return msub.getMergeSection(elf_file).getAddress(elf_file) + msub.value;
    }

    pub fn getMergeSection(msub: MergeSubsection, elf_file: *Elf) *MergeSection {
        return elf_file.getMergeSection(msub.merge_section);
    }

    pub fn getString(msub: MergeSubsection, elf_file: *Elf) []const u8 {
        const msec = msub.getMergeSection(elf_file);
        return msec.bytes.items[msub.string_index..][0..msub.size];
    }

    pub const Index = u32;
};

pub const InputMergeSection = struct {
    merge_section: MergeSection.Index = 0,
    atom: Atom.Index = 0,
    offsets: std.ArrayListUnmanaged(u32) = .{},
    subsections: std.ArrayListUnmanaged(MergeSubsection.Index) = .{},
    bytes: std.ArrayListUnmanaged(u8) = .{},
    strings: std.ArrayListUnmanaged(struct { u32, u32 }) = .{},

    pub fn deinit(imsec: *InputMergeSection, allocator: Allocator) void {
        imsec.offsets.deinit(allocator);
        imsec.subsections.deinit(allocator);
        imsec.bytes.deinit(allocator);
        imsec.strings.deinit(allocator);
    }

    pub fn clearAndFree(imsec: *InputMergeSection, allocator: Allocator) void {
        imsec.bytes.clearAndFree(allocator);
        imsec.strings.clearAndFree(allocator);
    }

    pub fn findSubsection(imsec: InputMergeSection, offset: u32) ?struct { MergeSubsection.Index, u32 } {
        // TODO: binary search
        for (imsec.offsets.items, imsec.subsections.items) |off, msub| {
            if (off <= offset) return .{ msub, offset - off };
        }
        return null;
    }

    pub fn insert(imsec: *InputMergeSection, allocator: Allocator, string: []const u8) !void {
        const index: u32 = @intCast(imsec.bytes.items.len);
        try imsec.bytes.appendSlice(allocator, string);
        try imsec.strings.append(allocator, .{ index, @intCast(string.len) });
    }

    pub fn insertZ(imsec: *InputMergeSection, allocator: Allocator, string: [:0]const u8) !void {
        const index: u32 = @intCast(imsec.bytes.items.len);
        try imsec.bytes.ensureUnusedCapacity(allocator, string.len + 1);
        imsec.bytes.appendSliceAssumeCapacity(string);
        imsec.bytes.appendAssumeCapacity(0);
        try imsec.strings.append(allocator, .{ index, @intCast(string.len + 1) });
    }

    pub const Index = u32;
};

const mem = std.mem;
const std = @import("std");

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");
