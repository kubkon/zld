const Archive = @This();

const std = @import("std");
const assert = std.debug.assert;
const fs = std.fs;
const log = std.log.scoped(.archive);
const macho = std.macho;
const mem = std.mem;

const Allocator = mem.Allocator;
const Object = @import("Object.zig");
const parseName = @import("Zld.zig").parseName;

usingnamespace @import("commands.zig");

allocator: *Allocator,
file: fs.File,
header: ar_hdr,
name: []u8,

objects: std.ArrayListUnmanaged(Object) = .{},

toc: std.StringArrayHashMapUnmanaged(u64) = .{},

// Archive files start with the ARMAG identifying string.  Then follows a
// `struct ar_hdr', and as many bytes of member file data as its `ar_size'
// member indicates, for each member file.
/// String that begins an archive file.
const ARMAG: *const [SARMAG:0]u8 = "!<arch>\n";
/// Size of that string.
const SARMAG: u4 = 8;

/// String in ar_fmag at the end of each header.
const ARFMAG: *const [2:0]u8 = "`\n";

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

    const NameOrLength = union(enum) {
        Name: []const u8,
        Length: u64,
    };
    pub fn nameOrLength(self: ar_hdr) !NameOrLength {
        const value = getValue(&self.ar_name);
        const slash_index = mem.indexOf(u8, value, "/") orelse return error.MalformedArchive;
        const len = value.len;
        if (slash_index == len - 1) {
            // Name stored directly
            return NameOrLength{ .Name = value };
        } else {
            // Name follows the header directly and its length is encoded in
            // the name field.
            const length = try std.fmt.parseInt(u64, value[slash_index + 1 ..], 10);
            return NameOrLength{ .Length = length };
        }
    }

    pub fn size(self: ar_hdr) !u64 {
        const value = getValue(&self.ar_size);
        return std.fmt.parseInt(u64, value, 10);
    }

    fn getValue(raw: []const u8) []const u8 {
        return mem.trimRight(u8, raw, &[_]u8{@as(u8, 0x20)});
    }
};

pub fn deinit(self: *Archive) void {
    self.allocator.free(self.name);
    for (self.objects.items) |*object| {
        object.deinit();
    }
    self.objects.deinit(self.allocator);
    for (self.toc.items()) |entry| {
        self.allocator.free(entry.key);
    }
    self.toc.deinit(self.allocator);
}

/// Caller owns the returned Archive instance and is responsible for calling
/// `deinit` to free allocated memory.
pub fn initFromFile(allocator: *Allocator, ar_name: []const u8, file: fs.File) !Archive {
    var reader = file.reader();
    var magic = try readMagic(allocator, reader);
    defer allocator.free(magic);

    if (!mem.eql(u8, magic, ARMAG)) {
        // Reset file cursor.
        try file.seekTo(0);
        return error.NotArchive;
    }

    const header = try reader.readStruct(ar_hdr);

    if (!mem.eql(u8, &header.ar_fmag, ARFMAG))
        return error.MalformedArchive;

    // TODO parse ToC of the archive (symbol -> object mapping)
    const toc_size = try header.size();
    log.debug("{}", .{toc_size});

    const name_or_length = try header.nameOrLength();
    var name: []u8 = undefined;
    switch (name_or_length) {
        .Name => |n| {
            name = try allocator.dupe(u8, n);
        },
        .Length => |len| {
            name = try allocator.alloc(u8, len);
            try reader.readNoEof(name);
        },
    }
    log.debug("{}, {s}", .{ name_or_length, name });

    var self = Archive{
        .allocator = allocator,
        .file = file,
        .header = header,
        .name = name,
    };
    try self.readSymtab(reader);
    try self.readStrtab(reader);

    // TODO parse objects contained within.

    return self;
}

fn readMagic(allocator: *Allocator, reader: anytype) ![]u8 {
    var magic = std.ArrayList(u8).init(allocator);
    try magic.ensureCapacity(SARMAG);
    var i: usize = 0;
    while (i < SARMAG) : (i += 1) {
        const next = try reader.readByte();
        magic.appendAssumeCapacity(next);
    }
    return magic.toOwnedSlice();
}

fn readSymtab(self: *Archive, reader: anytype) !void {
    const symtab_size = try reader.readIntLittle(u32);
    log.debug("{}", .{symtab_size});
    var buffer = try self.allocator.alloc(u8, symtab_size);
    defer self.allocator.free(buffer);
    try reader.readNoEof(buffer);

    var sym_stream = std.io.fixedBufferStream(buffer);
    var sym_reader = sym_stream.reader();

    while (true) {
        const n_strx = sym_reader.readIntLittle(u32) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        const obj = try sym_reader.readIntLittle(u32);

        log.debug("0x{x}, 0x{x}", .{ n_strx, obj });
    }
}

fn readStrtab(self: *Archive, reader: anytype) !void {
    const strtab_size = try reader.readIntLittle(u32);
}
