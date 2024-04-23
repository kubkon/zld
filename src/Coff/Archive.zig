members: std.ArrayListUnmanaged(Member) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

pub fn deinit(self: *Archive, allocator: Allocator) void {
    for (self.members.items) |member| {
        allocator.free(member.name);
    }
    self.members.deinit(allocator);
    self.strtab.deinit(allocator);
}

pub fn parse(self: *Archive, path: []const u8, file_handle: File.HandleIndex, coff_file: *Coff) !void {
    const gpa = coff_file.base.allocator;
    const file = coff_file.getFileHandle(file_handle);

    const size = (try file.stat()).size;

    var check: packed struct {
        symdef: bool = false,
        symdef_sorted: bool = false,
        longnames: bool = false,
    } = .{};
    var member_count: usize = 0;

    log.debug("parsing archive {s}", .{path});

    var pos: usize = magic.len;
    while (true) {
        if (!mem.isAligned(pos, 2)) {
            pos += 1;
        }
        if (pos >= size) break;

        var hdr_buffer: [@sizeOf(Header)]u8 = undefined;
        var amt = try file.preadAll(&hdr_buffer, pos);
        if (amt != @sizeOf(Header)) return error.InputOutput;
        const hdr = @as(*align(1) const Header, @ptrCast(&hdr_buffer));
        pos += @sizeOf(Header);

        if (!std.mem.eql(u8, &hdr.end, end)) {
            log.debug("invalid header? {}", .{hdr});
            coff_file.base.fatal("{s}: invalid header delimiter: expected '{s}', found '{s}'", .{
                path,
                std.fmt.fmtSliceEscapeLower(magic),
                std.fmt.fmtSliceEscapeLower(&hdr.end),
            });
            return error.ParseFailed;
        }

        const obj_size = try hdr.getSize();
        defer {
            pos += obj_size;
            member_count += 1;
        }

        if (hdr.isSymdef()) {
            blk: {
                if (!check.symdef) {
                    if (member_count != 0) break :blk;
                    check.symdef = true;
                    continue;
                }

                if (!check.symdef_sorted) {
                    if (member_count != 1) break :blk;
                    check.symdef_sorted = true;
                    continue;
                }
            }

            coff_file.base.fatal("{s}: unexpected archive member at position {d}", .{
                path,
                member_count,
            });
            return error.ParseFailed;
        }

        if (hdr.isStrtab()) {
            if (!check.longnames) {
                if (member_count != 2) {
                    coff_file.base.fatal("{s}: unexpected archive member at position {d}", .{
                        path,
                        member_count,
                    });
                    return error.ParseFailed;
                }
                try self.strtab.resize(gpa, obj_size);
                amt = try file.preadAll(self.strtab.items, pos);
                if (amt != obj_size) return error.InputOutput;
                check.longnames = true;
                continue;
            }
        }

        // https://reviews.llvm.org/D120645
        if (hdr.isHybridMap() or hdr.isEcSymbols() or hdr.isXfgMap()) continue;

        const name = if (hdr.getName()) |name|
            name
        else if (try hdr.getNameOffset()) |off| self.getString(off) else unreachable;

        var member_hdr_buffer: [@sizeOf(coff.CoffHeader)]u8 = undefined;
        amt = try file.preadAll(&member_hdr_buffer, pos);
        if (amt != @sizeOf(coff.CoffHeader)) return error.InputOutput;

        var member: Member = .{
            .tag = undefined,
            .machine = undefined,
            .offset = pos,
            .name = try gpa.dupe(u8, name),
        };
        if (Coff.isCoffObj(&member_hdr_buffer)) {
            const obj_hdr = @as(*align(1) const coff.CoffHeader, @ptrCast(&member_hdr_buffer));
            member.tag = .object;
            member.machine = obj_hdr.machine;
        } else if (Coff.isImportLib(&member_hdr_buffer)) {
            const import_hdr = @as(*align(1) const coff.ImportHeader, @ptrCast(&member_hdr_buffer));
            member.tag = .import;
            member.machine = import_hdr.machine;
        } else {
            coff_file.base.fatal("{s}: unhandled object member at position {d}", .{
                path,
                member_count,
            });
            return error.ParseFailed;
        }
        try self.members.append(gpa, member);
    }
}

fn getString(self: *const Archive, off: u32) [:0]const u8 {
    assert(off < self.strtab.items.len);
    return std.mem.sliceTo(@as([*:0]const u8, @ptrCast(self.strtab.items.ptr + off)), 0);
}

fn genMemberName(comptime name: []const u8) *const [16]u8 {
    assert(name.len <= 16);
    const padding = 16 - name.len;
    return name ++ &[_]u8{' '} ** padding;
}

const Header = extern struct {
    name: [16]u8,
    date: [12]u8,
    user_id: [6]u8,
    group_id: [6]u8,
    mode: [8]u8,
    size: [10]u8,
    end: [2]u8,

    fn getName(hdr: *const Header) ?[]const u8 {
        const value = &hdr.name;
        if (value[0] == '/') return null;
        const sentinel = std.mem.indexOfScalar(u8, value, '/') orelse value.len;
        return value[0..sentinel];
    }

    fn getNameOffset(hdr: *const Header) !?u32 {
        const value = &hdr.name;
        if (value[0] != '/') return null;
        const trimmed = std.mem.trimRight(u8, value, " ");
        return try std.fmt.parseInt(u32, trimmed[1..], 10);
    }

    fn getSize(hdr: *const Header) !u32 {
        const value = std.mem.trimRight(u8, &hdr.size, " ");
        return std.fmt.parseInt(u32, value, 10);
    }

    fn isSymdef(hdr: *const Header) bool {
        return std.mem.eql(u8, &hdr.name, linker_member);
    }

    fn isStrtab(hdr: *const Header) bool {
        return std.mem.eql(u8, &hdr.name, longnames_member);
    }

    fn isHybridMap(hdr: *const Header) bool {
        return std.mem.eql(u8, &hdr.name, hybridmap_member);
    }

    fn isEcSymbols(hdr: *const Header) bool {
        return std.mem.eql(u8, &hdr.name, ecsymbols_member);
    }

    fn isXfgMap(hdr: *const Header) bool {
        return std.mem.eql(u8, &hdr.name, xfgmap_member);
    }

    pub fn format(
        hdr: *const Header,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = unused_fmt_string;
        try writer.print("Header {{ .name = {s}, .date = {s}, .user_id = {s}, .group_id = {s}, .mode = {s}, .size = {s}, .end = {s} }}", .{
            std.fmt.fmtSliceEscapeLower(&hdr.name),
            std.fmt.fmtSliceEscapeLower(&hdr.date),
            std.fmt.fmtSliceEscapeLower(&hdr.user_id),
            std.fmt.fmtSliceEscapeLower(&hdr.group_id),
            std.fmt.fmtSliceEscapeLower(&hdr.mode),
            std.fmt.fmtSliceEscapeLower(&hdr.size),
            std.fmt.fmtSliceEscapeLower(&hdr.end),
        });
    }
};

const Member = struct {
    tag: Tag,
    offset: u64,
    name: []const u8,
    machine: coff.MachineType,

    const Tag = enum { object, import };
};

pub const magic = "!<arch>\n";
const end = "`\n";
const pad = "\n";
const linker_member = genMemberName("/");
const longnames_member = genMemberName("//");
const hybridmap_member = genMemberName("/<HYBRIDMAP>/");
const ecsymbols_member = genMemberName("/<ECSYMBOLS>/");
const xfgmap_member = genMemberName("/<XFGHASHMAP>/");

const assert = std.debug.assert;
const coff = std.coff;
const log = std.log.scoped(.coff);
const mem = std.mem;
const std = @import("std");

const Allocator = mem.Allocator;
const Archive = @This();
const Coff = @import("../Coff.zig");
const Dll = @import("Dll.zig");
const File = @import("file.zig").File;
const Object = @import("Object.zig");
