const Zld = @This();

const std = @import("std");
const fs = std.fs;
const macho = std.macho;
const log = std.log.scoped(.zld);

const Allocator = std.mem.Allocator;
const CrossTarget = std.zig.CrossTarget;
const Trie = @import("Trie.zig");

usingnamespace @import("commands.zig");
usingnamespace @import("imports.zig");

allocator: *Allocator,

const Object = struct {
    base: *Zld,
    file: ?fs.File = null,
    header: ?macho.mach_header_64 = null,
    load_commands: std.ArrayListUnmanaged(LoadCommand) = .{},
    segment_cmd_index: ?u16 = null,
    symtab_cmd_index: ?u16 = null,
    dysymtab_cmd_index: ?u16 = null,
    build_version_cmd_index: ?u16 = null,

    fn deinit(self: *Object) void {}

    fn parse(self: *Object, file: fs.File) !void {
        self.file = file;
        var reader = self.file.?.reader();
        self.header = try reader.readStruct(macho.mach_header_64);

        if (self.header.?.filetype != macho.MH_OBJECT)
            return error.ExpectedObjectInputFile;

        try self.load_commands.ensureCapacity(self.base.allocator, self.header.?.ncmds);

        var i: u16 = 0;
        while (i < self.header.?.ncmds) : (i += 1) {
            const cmd = try LoadCommand.read(self.base.allocator, reader);
            switch (cmd.cmd()) {
                macho.LC_SEGMENT_64 => {
                    self.segment_cmd_index = i;
                },
                macho.LC_SYMTAB => {
                    self.symtab_cmd_index = i;
                },
                macho.LC_DYSYMTAB => {
                    self.dysymtab_cmd_index = i;
                },
                macho.LC_BUILD_VERSION => {
                    self.build_version_cmd_index = i;
                },
                else => {
                    log.warn("Unknown load command detected: 0x{x}.", .{cmd.cmd()});
                },
            }
            self.load_commands.appendAssumeCapacity(cmd);
        }
    }
};

pub fn init(allocator: *Allocator) Zld {
    return .{ .allocator = allocator };
}

pub fn deinit(self: *Zld) void {}

pub fn link(self: *Zld, files: []const []const u8, target: CrossTarget) !void {
    for (files) |file_name| {
        var object: Object = .{ .base = self };
        const file = try fs.cwd().openFile(file_name, .{});
        try object.parse(file);
    }
}
