name: []const u8,
data: []const u8,

offsets: std.AutoHashMapUnmanaged(u32, void) = .{},
extnames_strtab: []const u8 = &[0]u8{},

// Archive files start with the ARMAG identifying string.  Then follows a
// `struct ar_hdr', and as many bytes of member file data as its `ar_size'
// member indicates, for each member file.
/// String that begins an archive file.
pub const ARMAG: *const [SARMAG:0]u8 = "!<arch>\n";
/// Size of that string.
pub const SARMAG: u4 = 8;

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
};

pub fn isValidMagic(magic: []const u8) bool {
    if (!mem.eql(u8, magic, ARMAG)) {
        log.debug("invalid archive magic: expected '{s}', found '{s}'", .{ ARMAG, magic });
        return false;
    }
    return true;
}

pub fn deinit(self: *Archive, allocator: Allocator) void {
    self.offsets.deinit(allocator);
}

pub fn parse(self: *Archive, elf_file: *Elf) !void {
    const gpa = elf_file.base.allocator;

    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();
    _ = try reader.readBytesNoEof(SARMAG);

    {
        // Parse lookup table
        const hdr = try reader.readStruct(ar_hdr);

        if (!mem.eql(u8, &hdr.ar_fmag, ARFMAG)) {
            return elf_file.base.fatal(
                "{s}: invalid header delimiter: expected '{s}', found '{s}'",
                .{ self.name, std.fmt.fmtSliceEscapeLower(ARFMAG), std.fmt.fmtSliceEscapeLower(&hdr.ar_fmag) },
            );
        }

        const ar_name = ar_hdr.getValue(&hdr.ar_name);

        if (!mem.eql(u8, ar_name, "/")) {
            return elf_file.base.fatal(
                "{s}: expected symbol lookup table as first data section; instead found '{s}'",
                .{ self.name, &hdr.ar_name },
            );
        }

        const checkpoint = try stream.getPos();
        const size = try hdr.size();
        const nsyms = try reader.readIntBig(u32);

        try self.offsets.ensureTotalCapacity(gpa, nsyms);

        var i: usize = 0;
        while (i < nsyms) : (i += 1) {
            const offset = try reader.readIntBig(u32);
            self.offsets.putAssumeCapacity(offset, {});
        }

        try stream.seekTo(checkpoint + size);
    }

    blk: {
        // Try parsing extended names table
        const hdr = try reader.readStruct(ar_hdr);

        if (!mem.eql(u8, &hdr.ar_fmag, ARFMAG)) {
            return elf_file.base.fatal(
                "{s}: invalid header delimiter: expected '{s}', found '{s}'",
                .{ self.name, std.fmt.fmtSliceEscapeLower(ARFMAG), std.fmt.fmtSliceEscapeLower(&hdr.ar_fmag) },
            );
        }

        const size = try hdr.size();
        const name = ar_hdr.getValue(&hdr.ar_name);

        if (!mem.eql(u8, name, "//")) {
            break :blk;
        }

        self.extnames_strtab = self.data[stream.pos..][0..size];
    }
}

fn getExtName(self: Archive, off: u32) []const u8 {
    assert(off < self.extnames_strtab.len);
    return mem.sliceTo(@ptrCast([*:'\n']const u8, self.extnames_strtab.ptr + off), 0);
}

pub fn getObject(self: Archive, arena: Allocator, offset: u32, elf_file: *Elf) !Object {
    var stream = std.io.fixedBufferStream(self.data[offset..]);
    const reader = stream.reader();

    const hdr = try reader.readStruct(ar_hdr);

    if (!mem.eql(u8, &hdr.ar_fmag, ARFMAG)) {
        elf_file.base.fatal(
            "{s}: invalid header delimiter: expected '{s}', found '{s}'",
            .{ self.name, std.fmt.fmtSliceEscapeLower(ARFMAG), std.fmt.fmtSliceEscapeLower(&hdr.ar_fmag) },
        );
        return error.InvalidHeader;
    }

    const name = blk: {
        const name = ar_hdr.getValue(&hdr.ar_name);
        if (name[0] == '/') {
            const off = try std.fmt.parseInt(u32, name[1..], 10);
            break :blk self.getExtName(off);
        }
        break :blk try arena.dupe(u8, name);
    };
    const object_name = name[0 .. name.len - 1]; // to account for trailing '/'

    log.debug("extracting object '{s}' from archive '{s}'", .{ object_name, self.name });

    const object_size = try hdr.size();

    return .{
        .archive = self.name,
        .path = object_name,
        .data = self.data[offset + stream.pos ..][0..object_size],
        .index = undefined,
        .alive = false,
    };
}

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const fs = std.fs;
const log = std.log.scoped(.elf);
const mem = std.mem;

const Allocator = mem.Allocator;
const Archive = @This();
const Elf = @import("../Elf.zig");
const Object = @import("Object.zig");
