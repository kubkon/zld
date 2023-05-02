const Archive = @This();

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const fs = std.fs;
const log = std.log.scoped(.elf);
const mem = std.mem;

const Allocator = mem.Allocator;
const Elf = @import("../Elf.zig");
const Object = @import("Object.zig");

file: fs.File,
name: []const u8,

/// Parsed table of contents.
/// Each symbol name points to a list of all definition
/// sites within the current static archive.
toc: std.StringArrayHashMapUnmanaged(std.ArrayListUnmanaged(u32)) = .{},

extnames_strtab: std.ArrayListUnmanaged(u8) = .{},

// Archive files start with the ARMAG identifying string.  Then follows a
// `struct ar_hdr', and as many bytes of member file data as its `ar_size'
// member indicates, for each member file.
/// String that begins an archive file.
const ARMAG: *const [SARMAG:0]u8 = "!<arch>\n";
/// Size of that string.
const SARMAG: u4 = 8;

/// String in ar_fmag at the end of each header.
const ARFMAG: *const [2:0]u8 = "`\n";

const SYM64NAME: *const [7:0]u8 = "/SYM64/";

const ar_hdr = extern struct {
    /// Member file name, sometimes / terminated.
    ar_name: [16]u8,

    /// File date, decimal seconds since Epoch.
    ar_date: [12]u8,

    /// User ID, in ASCII format.
    ar_uid: [6]u8,

    /// Group ID, in ASCII format.
    ar_gid: [6]u8,

    /// File mode, in ASCII octal.
    ar_mode: [8]u8,

    /// File size, in ASCII decimal.
    ar_size: [10]u8,

    /// Always contains ARFMAG.
    ar_fmag: [2]u8,

    fn date(self: ar_hdr) !u64 {
        const value = getValue(&self.ar_date);
        return std.fmt.parseInt(u64, value, 10);
    }

    fn size(self: ar_hdr) !u32 {
        const value = getValue(&self.ar_size);
        return std.fmt.parseInt(u32, value, 10);
    }

    fn getValue(raw: []const u8) []const u8 {
        return mem.trimRight(u8, raw, &[_]u8{@as(u8, 0x20)});
    }

    fn read(reader: anytype) !ar_hdr {
        const header = try reader.readStruct(ar_hdr);
        if (!mem.eql(u8, &header.ar_fmag, ARFMAG)) {
            log.debug("invalid header delimiter: expected '{s}', found '{s}'", .{ ARFMAG, header.ar_fmag });
            return error.NotArchive;
        }
        return header;
    }
};

pub fn deinit(self: *Archive, allocator: Allocator) void {
    self.extnames_strtab.deinit(allocator);
    for (self.toc.keys()) |*key| {
        allocator.free(key.*);
    }
    for (self.toc.values()) |*value| {
        value.deinit(allocator);
    }
    self.toc.deinit(allocator);
    allocator.free(self.name);
}

pub fn parse(self: *Archive, allocator: Allocator, reader: anytype) !void {
    const magic = try reader.readBytesNoEof(SARMAG);
    if (!mem.eql(u8, &magic, ARMAG)) {
        log.debug("invalid magic: expected '{s}', found '{s}'", .{ ARMAG, magic });
        return error.NotArchive;
    }

    {
        // Parse lookup table
        const hdr = try ar_hdr.read(reader);
        const size = try hdr.size();
        const ar_name = ar_hdr.getValue(&hdr.ar_name);

        if (!mem.eql(u8, ar_name, "/")) {
            log.err("expected symbol lookup table as first data section; instead found {s}", .{&hdr.ar_name});
            return error.NoSymbolLookupTableInArchive;
        }

        var buffer = try allocator.alloc(u8, size);
        defer allocator.free(buffer);

        try reader.readNoEof(buffer);

        var inner_stream = std.io.fixedBufferStream(buffer);
        var inner_reader = inner_stream.reader();

        const nsyms = try inner_reader.readIntBig(u32);

        var offsets = std.ArrayList(u32).init(allocator);
        defer offsets.deinit();
        try offsets.ensureTotalCapacity(nsyms);

        var i: usize = 0;
        while (i < nsyms) : (i += 1) {
            const offset = try inner_reader.readIntBig(u32);
            offsets.appendAssumeCapacity(offset);
        }

        i = 0;
        var pos: usize = try inner_stream.getPos();
        while (i < nsyms) : (i += 1) {
            const sym_name = mem.sliceTo(@ptrCast([*:0]const u8, buffer.ptr + pos), 0);
            const owned_name = try allocator.dupe(u8, sym_name);
            const res = try self.toc.getOrPut(allocator, owned_name);
            defer if (res.found_existing) allocator.free(owned_name);

            if (!res.found_existing) {
                res.value_ptr.* = .{};
            }

            try res.value_ptr.append(allocator, offsets.items[i]);
            pos += sym_name.len + 1;
        }
    }

    blk: {
        // Try parsing extended names table
        const hdr = try ar_hdr.read(reader);
        const size = try hdr.size();
        const name = ar_hdr.getValue(&hdr.ar_name);

        if (!mem.eql(u8, name, "//")) {
            break :blk;
        }

        var buffer = try allocator.alloc(u8, size);
        defer allocator.free(buffer);

        try reader.readNoEof(buffer);
        try self.extnames_strtab.appendSlice(allocator, buffer);
    }

    try reader.context.seekTo(0);
}

fn getExtName(self: Archive, off: u32) []const u8 {
    assert(off < self.extnames_strtab.items.len);
    return mem.sliceTo(@ptrCast([*:'\n']const u8, self.extnames_strtab.items.ptr + off), 0);
}

pub fn parseObject(self: Archive, offset: u32, object_id: u32, elf_file: *Elf) !*Object {
    const gpa = elf_file.base.allocator;

    const reader = self.file.reader();
    try reader.context.seekTo(offset);

    const hdr = try ar_hdr.read(reader);
    const name = blk: {
        const name = ar_hdr.getValue(&hdr.ar_name);
        if (name[0] == '/') {
            const off = try std.fmt.parseInt(u32, name[1..], 10);
            break :blk self.getExtName(off);
        }
        break :blk name;
    };
    const object_name = name[0 .. name.len - 1]; // to account for trailing '/'

    log.debug("extracting object '{s}' from archive '{s}'", .{ object_name, self.name });

    const full_name = blk: {
        var buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const path = try std.os.realpath(self.name, &buffer);
        break :blk try std.fmt.allocPrint(gpa, "{s}({s})", .{ path, object_name });
    };
    errdefer gpa.free(full_name);
    const object_size = try hdr.size();
    const data = try gpa.alloc(u8, object_size);
    errdefer gpa.free(data);
    const amt = try reader.readAll(data);
    if (amt != object_size) {
        return error.Io;
    }

    const object = try elf_file.objects.addOne(gpa);
    object.* = .{
        .name = full_name,
        .data = data,
        .object_id = object_id,
    };
    try object.parse(elf_file);

    const cpu_arch = elf_file.cpu_arch.?;
    if (cpu_arch != object.header.?.e_machine.toTargetCpuArch().?) {
        log.err("Invalid architecture {any}, expected {any}", .{
            object.header.?.e_machine,
            cpu_arch.toElfMachine(),
        });
        return error.InvalidCpuArch;
    }

    return object;
}
