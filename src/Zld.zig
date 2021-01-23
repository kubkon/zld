const Zld = @This();

const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const macho = std.macho;
const log = std.log.scoped(.zld);
const reloc = @import("reloc.zig");

const Allocator = mem.Allocator;
const CrossTarget = std.zig.CrossTarget;
const Trie = @import("Trie.zig");

usingnamespace @import("commands.zig");
usingnamespace @import("imports.zig");

allocator: *Allocator,
relocs: std.AutoArrayHashMapUnmanaged(u16, []reloc.relocation_info) = .{},

const Object = struct {
    base: *Zld,
    file: ?fs.File = null,
    header: ?macho.mach_header_64 = null,
    load_commands: std.ArrayListUnmanaged(LoadCommand) = .{},
    segment_cmd_index: ?u16 = null,
    symtab_cmd_index: ?u16 = null,
    dysymtab_cmd_index: ?u16 = null,
    build_version_cmd_index: ?u16 = null,
    symtab: std.ArrayListUnmanaged(macho.nlist_64) = .{},
    strtab: std.ArrayListUnmanaged(u8) = .{},
    relocs: std.AutoArrayHashMapUnmanaged(u16, []reloc.relocation_info) = .{},

    fn deinit(self: *Object, allocator: *Allocator) void {
        for (self.load_commands.items) |*lc| {
            lc.deinit(allocator);
        }
        self.load_commands.deinit(allocator);
        self.symtab.deinit(allocator);
        self.strtab.deinit(allocator);
        for (self.relocs.items()) |entry| {
            self.base.allocator.free(entry.value);
        }
        self.relocs.deinit(self.base.allocator);
    }

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

        try self.parseSymtab();
        try self.parseStrtab();
        try self.parseRelocs();
    }

    fn parseSymtab(self: *Object) !void {
        const symtab_cmd = self.load_commands.items[self.symtab_cmd_index.?].Symtab;
        var buffer = try self.base.allocator.alloc(u8, @sizeOf(macho.nlist_64) * symtab_cmd.nsyms);
        defer self.base.allocator.free(buffer);
        _ = try self.file.?.preadAll(buffer, symtab_cmd.symoff);
        try self.symtab.ensureCapacity(self.base.allocator, symtab_cmd.nsyms);
        // TODO this align case should not be needed.
        // Probably a bug in stage1.
        const slice = @alignCast(@alignOf(macho.nlist_64), mem.bytesAsSlice(macho.nlist_64, buffer));
        self.symtab.appendSliceAssumeCapacity(slice);
    }

    fn parseStrtab(self: *Object) !void {
        const symtab_cmd = self.load_commands.items[self.symtab_cmd_index.?].Symtab;
        var buffer = try self.base.allocator.alloc(u8, symtab_cmd.strsize);
        defer self.base.allocator.free(buffer);
        _ = try self.file.?.preadAll(buffer, symtab_cmd.stroff);
        try self.strtab.ensureCapacity(self.base.allocator, symtab_cmd.strsize);
        self.strtab.appendSliceAssumeCapacity(buffer);
    }

    fn parseRelocs(self: *Object) !void {
        const segment_cmd = self.load_commands.items[self.segment_cmd_index.?].Segment;
        for (segment_cmd.sections.items) |sect, i| {
            var buffer = try self.base.allocator.alloc(u8, @sizeOf(reloc.relocation_info) * sect.nreloc);
            defer self.base.allocator.free(buffer);
            _ = try self.file.?.preadAll(buffer, sect.reloff);
            var relocs = try self.base.allocator.alloc(reloc.relocation_info, sect.nreloc);
            mem.copy(reloc.relocation_info, relocs, mem.bytesAsSlice(reloc.relocation_info, buffer));
            try self.relocs.putNoClobber(self.base.allocator, @intCast(u16, i), relocs);
        }
    }
};

pub fn init(allocator: *Allocator) Zld {
    return .{ .allocator = allocator };
}

pub fn deinit(self: *Zld) void {}

pub fn link(self: *Zld, files: []const []const u8, target: CrossTarget) !void {
    for (files) |file_name| {
        const file = try fs.cwd().openFile(file_name, .{});
        var object: Object = .{ .base = self };
        defer object.deinit(self.allocator);

        try object.parse(file);
    }
}
