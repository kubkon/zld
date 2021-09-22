const Elf = @This();

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const fs = std.fs;
const log = std.log.scoped(.elf);
const mem = std.mem;

const Allocator = mem.Allocator;
const Object = @import("Elf/Object.zig");
const Zld = @import("Zld.zig");

pub const base_tag = Zld.Tag.elf;

base: Zld,

objects: std.ArrayListUnmanaged(Object) = .{},

shdrs: std.ArrayListUnmanaged(elf.Elf64_Shdr) = .{},
phdrs: std.ArrayListUnmanaged(elf.Elf64_Phdr) = .{},

shstrtab: std.ArrayListUnmanaged(u8) = .{},

shstrtab_index: ?u16 = null,

shdrs_offset: ?u64 = null,

entry_address: ?u64 = null,

globals: std.StringArrayHashMapUnmanaged(elf.Elf64_Sym) = .{},

pub fn openPath(allocator: *Allocator, options: Zld.Options) !*Elf {
    const file = try options.emit.directory.createFile(options.emit.sub_path, .{
        .truncate = true,
        .read = true,
        .mode = if (std.Target.current.os.tag == .windows) 0 else 0o777,
    });
    errdefer file.close();

    const self = try createEmpty(allocator, options);
    errdefer self.base.destroy();

    self.base.file = file;

    return self;
}

fn createEmpty(gpa: *Allocator, options: Zld.Options) !*Elf {
    const self = try gpa.create(Elf);

    self.* = .{
        .base = .{
            .tag = .elf,
            .options = options,
            .allocator = gpa,
            .file = undefined,
        },
    };

    return self;
}

pub fn deinit(self: *Elf) void {
    for (self.globals.keys()) |key| {
        self.base.allocator.free(key);
    }
    self.globals.deinit(self.base.allocator);
    self.shstrtab.deinit(self.base.allocator);
    self.shdrs.deinit(self.base.allocator);
    self.phdrs.deinit(self.base.allocator);
    self.objects.deinit(self.base.allocator);
}

pub fn closeFiles(self: Elf) void {
    for (self.objects.items) |object| {
        object.file.close();
    }
}

pub fn flush(self: *Elf) !void {
    try self.parsePositionals(self.base.options.positionals);
    try self.writeHeader();
}

fn parsePositionals(self: *Elf, files: []const []const u8) !void {
    for (files) |file_name| {
        const full_path = full_path: {
            var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
            const path = try std.fs.realpath(file_name, &buffer);
            break :full_path try self.base.allocator.dupe(u8, path);
        };
        defer self.base.allocator.free(full_path);
        log.debug("parsing input file path '{s}'", .{full_path});

        if (try self.parseObject(full_path)) continue;

        log.warn("unknown filetype for positional input file: '{s}'", .{file_name});
    }
}

fn parseObject(self: *Elf, path: []const u8) !bool {
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    errdefer file.close();

    const name = try self.base.allocator.dupe(u8, path);
    errdefer self.base.allocator.free(name);

    var object = Object{
        .name = name,
        .file = file,
    };

    object.parse(self.base.allocator, self.base.options.target) catch |err| switch (err) {
        error.EndOfStream, error.NotObject => {
            object.deinit(self.base.allocator);
            return false;
        },
        else => |e| return e,
    };

    try self.objects.append(self.base.allocator, object);

    return true;
}

fn writeHeader(self: *Elf) !void {
    var buffer: [@sizeOf(elf.Elf64_Ehdr)]u8 = undefined;

    // Magic
    var index: usize = 0;
    buffer[0..4].* = "\x7fELF".*;
    index += 4;

    // Class
    buffer[index] = elf.ELFCLASS64;
    index += 1;

    // Endianness
    buffer[index] = elf.ELFDATA2LSB;
    index += 1;

    // ELF version
    buffer[index] = 1;
    index += 1;

    // OS ABI, often set to 0 regardless of target platform
    // ABI Version, possibly used by glibc but not by static executables
    // padding
    mem.set(u8, buffer[index..][0..9], 0);
    index += 9;

    assert(index == 16);

    const elf_type = switch (self.base.options.output_mode) {
        .exe => elf.ET.EXEC,
        .lib => elf.ET.DYN,
    };
    mem.writeIntLittle(u16, buffer[index..][0..2], @enumToInt(elf_type));
    index += 2;

    const machine = self.base.options.target.cpu.arch.toElfMachine();
    mem.writeIntLittle(u16, buffer[index..][0..2], @enumToInt(machine));
    index += 2;

    // ELF version, again
    mem.writeIntLittle(u32, buffer[index..][0..4], 1);
    index += 4;

    // Entry point address
    mem.writeIntLittle(u64, buffer[index..][0..8], self.entry_address orelse 0);
    index += 8;

    // Program headers offset
    mem.writeIntLittle(u64, buffer[index..][0..8], @sizeOf(elf.Elf64_Ehdr));
    index += 8;

    // Section headers offset
    mem.writeIntLittle(u64, buffer[index..][0..8], self.shdrs_offset orelse 0);
    index += 8;

    const e_flags = 0;
    mem.writeIntLittle(u32, buffer[index..][0..4], e_flags);
    index += 4;

    const e_ehsize: u16 = @sizeOf(elf.Elf64_Ehdr);
    mem.writeIntLittle(u16, buffer[index..][0..2], e_ehsize);
    index += 2;

    // Program headers
    const e_phentsize: u16 = @sizeOf(elf.Elf64_Phdr);
    mem.writeIntLittle(u16, buffer[index..][0..2], e_phentsize);
    index += 2;

    const e_phnum = @intCast(u16, self.phdrs.items.len);
    mem.writeIntLittle(u16, buffer[index..][0..2], e_phnum);
    index += 2;

    // Section headers
    const e_shentsize: u16 = @sizeOf(elf.Elf64_Shdr);
    mem.writeIntLittle(u16, buffer[index..][0..2], e_shentsize);
    index += 2;

    const e_shnum = @intCast(u16, self.shdrs.items.len);
    mem.writeIntLittle(u16, buffer[index..][0..2], e_shnum);
    index += 2;

    // Section header strtab
    mem.writeIntLittle(u16, buffer[index..][0..2], self.shstrtab_index orelse 0);
    index += 2;

    assert(index == e_ehsize);

    try self.base.file.pwriteAll(buffer[0..index], 0);
}
