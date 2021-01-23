const Zld = @This();

const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const macho = std.macho;
const log = std.log.scoped(.zld);
const reloc = @import("reloc.zig");

const Allocator = mem.Allocator;
const Target = std.Target;
const Trie = @import("Trie.zig");

usingnamespace @import("commands.zig");
usingnamespace @import("imports.zig");

allocator: *Allocator,
file: ?fs.File = null,
objects: std.ArrayListUnmanaged(Object) = .{},
load_commands: std.ArrayListUnmanaged(LoadCommand) = .{},
target: ?Target = null,

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
        self.file.?.close();
    }

    fn parse(self: *Object) !void {
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

pub fn deinit(self: *Zld) void {
    for (self.objects.items) |*object| {
        object.deinit(self.allocator);
    }
    self.objects.deinit(self.allocator);
    for (self.load_commands.items) |*lc| {
        lc.deinit(self.allocator);
    }
    self.load_commands.deinit(self.allocator);
    self.file.?.close();
}

pub fn link(self: *Zld, files: []const []const u8) !void {
    try self.objects.ensureCapacity(self.allocator, files.len);
    for (files) |file_name| {
        var object: Object = .{ .base = self };
        object.file = try fs.cwd().openFile(file_name, .{});
        try object.parse();
        self.objects.appendAssumeCapacity(object);
    }

    try self.flush();
}

fn populateMetadata(self: *Zld) !void {}

fn flush(self: *Zld) !void {
    try self.populateMetadata();
    self.file = try fs.cwd().createFile("a.out", .{ .truncate = true });
    try self.writeHeader();
}

fn writeHeader(self: *Zld) !void {
    var header: macho.mach_header_64 = undefined;
    header.magic = macho.MH_MAGIC_64;

    const CpuInfo = struct {
        cpu_type: macho.cpu_type_t,
        cpu_subtype: macho.cpu_subtype_t,
    };

    const cpu_info: CpuInfo = switch (self.target.?.cpu.arch) {
        .aarch64 => .{
            .cpu_type = macho.CPU_TYPE_ARM64,
            .cpu_subtype = macho.CPU_SUBTYPE_ARM_ALL,
        },
        .x86_64 => .{
            .cpu_type = macho.CPU_TYPE_X86_64,
            .cpu_subtype = macho.CPU_SUBTYPE_X86_64_ALL,
        },
        else => return error.UnsupportedMachOArchitecture,
    };
    header.cputype = cpu_info.cpu_type;
    header.cpusubtype = cpu_info.cpu_subtype;
    header.filetype = macho.MH_EXECUTE;
    header.flags = macho.MH_NOUNDEFS | macho.MH_DYLDLINK | macho.MH_PIE;
    header.reserved = 0;

    header.ncmds = @intCast(u32, self.load_commands.items.len);
    header.sizeofcmds = 0;
    for (self.load_commands.items) |cmd| {
        header.sizeofcmds += cmd.cmdsize();
    }
    log.debug("writing Mach-O header {}", .{header});
    try self.file.?.pwriteAll(mem.asBytes(&header), 0);
}
