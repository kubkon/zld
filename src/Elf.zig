const Elf = @This();

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const fs = std.fs;
const log = std.log.scoped(.elf);
const mem = std.mem;

const Allocator = mem.Allocator;
const Atom = @import("Elf/Atom.zig");
const Object = @import("Elf/Object.zig");
const Zld = @import("Zld.zig");

pub const base_tag = Zld.Tag.elf;

base: Zld,

objects: std.ArrayListUnmanaged(Object) = .{},

header: ?elf.Elf64_Ehdr = null,
shdrs: std.ArrayListUnmanaged(elf.Elf64_Shdr) = .{},
phdrs: std.ArrayListUnmanaged(elf.Elf64_Phdr) = .{},

strtab: std.ArrayListUnmanaged(u8) = .{},
shstrtab: std.ArrayListUnmanaged(u8) = .{},

phdr_seg_index: ?u16 = null,
load_r_seg_index: ?u16 = null,
load_re_seg_index: ?u16 = null,
load_rw_seg_index: ?u16 = null,

text_sect_index: ?u16 = null,
rodata_sect_index: ?u16 = null,
data_sect_index: ?u16 = null,
symtab_sect_index: ?u16 = null,
strtab_sect_index: ?u16 = null,
shstrtab_sect_index: ?u16 = null,

next_offset: u64 = 0,

base_addr: u64 = 0x200000,

globals: std.StringArrayHashMapUnmanaged(SymbolWithLoc) = .{},

managed_atoms: std.ArrayListUnmanaged(*Atom) = .{},
atoms: std.AutoHashMapUnmanaged(u16, *Atom) = .{},

pub const SymbolWithLoc = struct {
    sym_index: u32,
    file: u16,
};

pub fn openPath(allocator: *Allocator, options: Zld.Options) !*Elf {
    const file = try options.emit.directory.createFile(options.emit.sub_path, .{
        .truncate = true,
        .read = true,
        .mode = if (std.Target.current.os.tag == .windows) 0 else 0o777,
    });
    errdefer file.close();

    const self = try createEmpty(allocator, options);
    errdefer allocator.destroy(self);

    self.base.file = file;

    try self.populateMetadata();

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
    self.closeFiles();

    self.atoms.deinit(self.base.allocator);
    for (self.managed_atoms.items) |atom| {
        atom.deinit(self.base.allocator);
        self.base.allocator.destroy(atom);
    }
    self.managed_atoms.deinit(self.base.allocator);
    for (self.globals.keys()) |key| {
        self.base.allocator.free(key);
    }
    self.globals.deinit(self.base.allocator);
    self.shstrtab.deinit(self.base.allocator);
    self.strtab.deinit(self.base.allocator);
    self.shdrs.deinit(self.base.allocator);
    self.phdrs.deinit(self.base.allocator);
    self.objects.deinit(self.base.allocator);
}

fn closeFiles(self: Elf) void {
    for (self.objects.items) |object| {
        object.file.close();
    }
}

pub fn flush(self: *Elf) !void {
    try self.parsePositionals(self.base.options.positionals);

    for (self.objects.items) |_, object_id| {
        try self.resolveSymbolsInObject(@intCast(u16, object_id));
    }

    for (self.objects.items) |*object, object_id| {
        try object.parseIntoAtoms(self.base.allocator, @intCast(u16, object_id), self);
    }

    try self.sortShdrs();

    try self.allocateLoadRSeg();
    try self.allocateLoadRESeg();
    try self.allocateLoadRWSeg();
    try self.allocateAtoms();

    try self.logSymtab();

    try self.writeAtoms();
    try self.setEntryPoint();
    try self.writePhdrs();
    try self.writeSymtab();
    try self.writeStrtab();
    try self.writeShStrtab();
    try self.writeShdrs();
    try self.writeHeader();
}

fn populateMetadata(self: *Elf) !void {
    if (self.header == null) {
        var header = elf.Elf64_Ehdr{
            .e_ident = undefined,
            .e_type = switch (self.base.options.output_mode) {
                .exe => elf.ET.EXEC,
                .lib => elf.ET.DYN,
            },
            .e_machine = self.base.options.target.cpu.arch.toElfMachine(),
            .e_version = 1,
            .e_entry = 0,
            .e_phoff = @sizeOf(elf.Elf64_Ehdr),
            .e_shoff = 0,
            .e_flags = 0,
            .e_ehsize = @sizeOf(elf.Elf64_Ehdr),
            .e_phentsize = @sizeOf(elf.Elf64_Phdr),
            .e_phnum = 0,
            .e_shentsize = @sizeOf(elf.Elf64_Shdr),
            .e_shnum = 0,
            .e_shstrndx = 0,
        };
        // Magic
        mem.copy(u8, header.e_ident[0..4], "\x7fELF");
        // Class
        header.e_ident[4] = elf.ELFCLASS64;
        // Endianness
        header.e_ident[5] = elf.ELFDATA2LSB;
        // ELF version
        header.e_ident[6] = 1;
        // OS ABI, often set to 0 regardless of target platform
        // ABI Version, possibly used by glibc but not by static executables
        // padding
        mem.set(u8, header.e_ident[7..][0..9], 0);
        self.header = header;
    }
    if (self.phdr_seg_index == null) {
        const offset = @sizeOf(elf.Elf64_Ehdr);
        const size = @sizeOf(elf.Elf64_Phdr);
        self.phdr_seg_index = @intCast(u16, self.phdrs.items.len);
        try self.phdrs.append(self.base.allocator, .{
            .p_type = elf.PT_PHDR,
            .p_flags = elf.PF_R,
            .p_offset = offset,
            .p_vaddr = offset + self.base_addr,
            .p_paddr = offset + self.base_addr,
            .p_filesz = size,
            .p_memsz = size,
            .p_align = @alignOf(elf.Elf64_Phdr),
        });
    }
    if (self.load_r_seg_index == null) {
        self.load_r_seg_index = @intCast(u16, self.phdrs.items.len);
        try self.phdrs.append(self.base.allocator, .{
            .p_type = elf.PT_LOAD,
            .p_flags = elf.PF_R,
            .p_offset = 0,
            .p_vaddr = self.base_addr,
            .p_paddr = self.base_addr,
            .p_filesz = @sizeOf(elf.Elf64_Ehdr),
            .p_memsz = @sizeOf(elf.Elf64_Ehdr),
            .p_align = 0x1000,
        });
        {
            const phdr = &self.phdrs.items[self.phdr_seg_index.?];
            phdr.p_filesz += @sizeOf(elf.Elf64_Phdr);
            phdr.p_memsz += @sizeOf(elf.Elf64_Phdr);
        }
    }
    if (self.load_re_seg_index == null) {
        self.load_re_seg_index = @intCast(u16, self.phdrs.items.len);
        try self.phdrs.append(self.base.allocator, .{
            .p_type = elf.PT_LOAD,
            .p_flags = elf.PF_R | elf.PF_X,
            .p_offset = 0,
            .p_vaddr = self.base_addr,
            .p_paddr = self.base_addr,
            .p_filesz = 0,
            .p_memsz = 0,
            .p_align = 0x1000,
        });
        {
            const phdr = &self.phdrs.items[self.phdr_seg_index.?];
            phdr.p_filesz += @sizeOf(elf.Elf64_Phdr);
            phdr.p_memsz += @sizeOf(elf.Elf64_Phdr);
        }
    }
    if (self.load_rw_seg_index == null) {
        self.load_rw_seg_index = @intCast(u16, self.phdrs.items.len);
        try self.phdrs.append(self.base.allocator, .{
            .p_type = elf.PT_LOAD,
            .p_flags = elf.PF_R | elf.PF_W,
            .p_offset = 0,
            .p_vaddr = self.base_addr,
            .p_paddr = self.base_addr,
            .p_filesz = 0,
            .p_memsz = 0,
            .p_align = 0x1000,
        });
        {
            const phdr = &self.phdrs.items[self.phdr_seg_index.?];
            phdr.p_filesz += @sizeOf(elf.Elf64_Phdr);
            phdr.p_memsz += @sizeOf(elf.Elf64_Phdr);
        }
    }
    if (self.symtab_sect_index == null) {
        self.symtab_sect_index = @intCast(u16, self.shdrs.items.len);
        try self.shdrs.append(self.base.allocator, .{
            .sh_name = try self.makeShString(".symtab"),
            .sh_type = elf.SHT_SYMTAB,
            .sh_flags = 0,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = 0,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = @alignOf(elf.Elf64_Sym),
            .sh_entsize = @sizeOf(elf.Elf64_Sym),
        });
    }
    if (self.strtab_sect_index == null) {
        self.strtab_sect_index = @intCast(u16, self.shdrs.items.len);
        try self.shdrs.append(self.base.allocator, .{
            .sh_name = try self.makeShString(".strtab"),
            .sh_type = elf.SHT_STRTAB,
            .sh_flags = 0,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = 0,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = 1,
            .sh_entsize = 0,
        });
        // Link .strtab with .symtab via sh_link field.
        self.shdrs.items[self.symtab_sect_index.?].sh_link = self.strtab_sect_index.?;
    }
    if (self.shstrtab_sect_index == null) {
        try self.shstrtab.append(self.base.allocator, 0);
        self.shstrtab_sect_index = @intCast(u16, self.shdrs.items.len);
        try self.shdrs.append(self.base.allocator, .{
            .sh_name = try self.makeShString(".shstrtab"),
            .sh_type = elf.SHT_STRTAB,
            .sh_flags = 0,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = 0,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = 1,
            .sh_entsize = 0,
        });
        self.header.?.e_shstrndx = self.shstrtab_sect_index.?;
    }
}

pub fn getMatchingSection(self: *Elf, object_id: u16, sect_id: u16) !?u16 {
    const object = self.objects.items[object_id];
    const shdr = object.shdrs.items[sect_id];
    const flags = shdr.sh_flags;
    const res: ?u16 = blk: {
        if (flags & elf.SHF_ALLOC == 0) {
            log.debug("TODO non-alloc sections", .{});
            log.debug("  {s} => {}", .{ object.getString(shdr.sh_name), shdr });
            break :blk null;
        }
        if (flags & elf.SHF_EXECINSTR != 0) {
            if (self.text_sect_index == null) {
                self.text_sect_index = @intCast(u16, self.shdrs.items.len);
                try self.shdrs.append(self.base.allocator, .{
                    .sh_name = try self.makeShString(".text"),
                    .sh_type = elf.SHT_PROGBITS,
                    .sh_flags = elf.SHF_EXECINSTR | elf.SHF_ALLOC,
                    .sh_addr = 0,
                    .sh_offset = 0,
                    .sh_size = 0,
                    .sh_link = 0,
                    .sh_info = 0,
                    .sh_addralign = 0,
                    .sh_entsize = 0,
                });
            }
            break :blk self.text_sect_index.?;
        }
        if (flags & elf.SHF_WRITE != 0) {
            if (self.data_sect_index == null) {
                self.data_sect_index = @intCast(u16, self.shdrs.items.len);
                try self.shdrs.append(self.base.allocator, .{
                    .sh_name = try self.makeShString(".data"),
                    .sh_type = elf.SHT_PROGBITS,
                    .sh_flags = elf.SHF_WRITE | elf.SHF_ALLOC,
                    .sh_addr = 0,
                    .sh_offset = 0,
                    .sh_size = 0,
                    .sh_link = 0,
                    .sh_info = 0,
                    .sh_addralign = 0,
                    .sh_entsize = 0,
                });
            }
            break :blk self.data_sect_index.?;
        }
        if (flags & elf.SHF_MERGE != 0 and flags & elf.SHF_STRINGS != 0) {
            if (self.rodata_sect_index == null) {
                self.rodata_sect_index = @intCast(u16, self.shdrs.items.len);
                try self.shdrs.append(self.base.allocator, .{
                    .sh_name = try self.makeShString(".rodata"),
                    .sh_type = elf.SHT_PROGBITS,
                    .sh_flags = elf.SHF_MERGE | elf.SHF_STRINGS | elf.SHF_ALLOC,
                    .sh_addr = 0,
                    .sh_offset = 0,
                    .sh_size = 0,
                    .sh_link = 0,
                    .sh_info = 0,
                    .sh_addralign = 0,
                    .sh_entsize = 0,
                });
            }
            break :blk self.rodata_sect_index.?;
        }

        log.debug("TODO unhandled section", .{});
        log.debug("  {s} => {}", .{ object.getString(shdr.sh_name), shdr });
        break :blk null;
    };
    return res;
}

/// Sorts section headers such that loadable sections come first (following the order of program headers),
/// and symbol and string tables come last. The order of the contents within the file does not have to match
/// the order of the section headers. However loadable sections do have to be within bounds
/// of their respective program headers.
fn sortShdrs(self: *Elf) !void {
    var index_mapping = std.AutoHashMap(u16, u16).init(self.base.allocator);
    defer index_mapping.deinit();
    var shdrs = self.shdrs.toOwnedSlice(self.base.allocator);
    defer self.base.allocator.free(shdrs);
    try self.shdrs.ensureCapacity(self.base.allocator, shdrs.len);

    const indices = &[_]*?u16{
        &self.rodata_sect_index,
        &self.text_sect_index,
        &self.data_sect_index,
        &self.symtab_sect_index,
        &self.shstrtab_sect_index,
        &self.strtab_sect_index,
    };
    for (indices) |maybe_index| {
        const new_index: u16 = if (maybe_index.*) |index| blk: {
            const idx = @intCast(u16, self.shdrs.items.len);
            self.shdrs.appendAssumeCapacity(shdrs[index]);
            try index_mapping.putNoClobber(index, idx);
            break :blk idx;
        } else continue;
        maybe_index.* = new_index;
    }

    self.header.?.e_shstrndx = index_mapping.get(self.header.?.e_shstrndx).?;
    {
        var shdr = &self.shdrs.items[self.symtab_sect_index.?];
        shdr.sh_link = self.strtab_sect_index.?;
    }

    var transient: std.AutoHashMapUnmanaged(u16, *Atom) = .{};
    try transient.ensureCapacity(self.base.allocator, self.atoms.count());

    var it = self.atoms.iterator();
    while (it.next()) |entry| {
        const old_sect_id = entry.key_ptr.*;
        const new_sect_id = index_mapping.get(old_sect_id).?;
        transient.putAssumeCapacityNoClobber(new_sect_id, entry.value_ptr.*);
    }

    self.atoms.clearAndFree(self.base.allocator);
    self.atoms.deinit(self.base.allocator);
    self.atoms = transient;
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

fn resolveSymbolsInObject(self: *Elf, object_id: u16) !void {
    const object = self.objects.items[object_id];

    log.debug("resolving symbols in {s}", .{object.name});

    for (object.symtab.items) |sym, i| {
        const sym_id = @intCast(u32, i);
        const sym_name = object.getString(sym.st_name);
        const st_bind = sym.st_info >> 4;

        switch (st_bind) {
            elf.STB_LOCAL => {
                log.debug("  (symbol '{s}' local to object; skipping...)", .{sym_name});
                continue;
            },
            elf.STB_WEAK, elf.STB_GLOBAL => {
                const name = try self.base.allocator.dupe(u8, sym_name);
                const res = try self.globals.getOrPut(self.base.allocator, name);
                defer if (res.found_existing) self.base.allocator.free(name);

                if (!res.found_existing) {
                    res.value_ptr.* = .{
                        .sym_index = sym_id,
                        .file = object_id,
                    };
                    continue;
                }

                const global = res.value_ptr.*;
                const linked_obj = self.objects.items[global.file];
                const linked_sym = linked_obj.symtab.items[global.sym_index];
                const linked_sym_bind = linked_sym.st_info >> 4;

                if (linked_sym.st_shndx != elf.SHN_UNDEF) {
                    if (linked_sym_bind == elf.STB_GLOBAL and st_bind == elf.STB_GLOBAL) {
                        log.err("symbol '{s}' defined multiple times", .{sym_name});
                        log.err("  first definition in '{s}'", .{linked_obj.name});
                        log.err("  next definition in '{s}'", .{object.name});
                        return error.MultipleSymbolDefinitions;
                    }

                    if (st_bind == elf.STB_WEAK) {
                        log.debug("  (symbol '{s}' already defined; skipping...)", .{sym_name});
                        continue;
                    }
                }

                res.value_ptr.* = .{
                    .sym_index = sym_id,
                    .file = object_id,
                };
            },
            else => {
                log.err("unhandled symbol binding type: {}", .{st_bind});
                log.err("  symbol '{s}'", .{sym_name});
                log.err("  first definition in '{s}'", .{object.name});
                return error.UnhandledSymbolBindType;
            },
        }
    }
}

fn allocateSection(self: *Elf, ndx: u16, phdr_ndx: u16) !void {
    const shdr = &self.shdrs.items[ndx];
    const phdr = &self.phdrs.items[phdr_ndx];
    const base_offset = phdr.p_offset + phdr.p_filesz;
    shdr.sh_offset = mem.alignForwardGeneric(u64, base_offset, shdr.sh_addralign);
    shdr.sh_addr = phdr.p_vaddr + shdr.sh_offset;

    log.debug("allocating '{s}' section from 0x{x} to 0x{x}", .{
        self.getShString(shdr.sh_name),
        shdr.sh_addr,
        shdr.sh_addr + shdr.sh_size,
    });

    if (phdr.p_filesz == 0) {
        phdr.p_offset = shdr.sh_offset;
        phdr.p_vaddr += shdr.sh_offset;
        phdr.p_paddr += shdr.sh_offset;
    }

    // TODO fix this!
    phdr.p_filesz += (shdr.sh_offset + shdr.sh_size) - (phdr.p_offset + phdr.p_filesz);
    phdr.p_memsz = phdr.p_filesz;
}

fn getSegmentBaseAddr(self: *Elf, phdr_ndx: u16) u64 {
    const phdr = self.phdrs.items[phdr_ndx];
    const base_addr = mem.alignForwardGeneric(u64, phdr.p_vaddr + phdr.p_memsz, 0x1000);
    return base_addr;
}

fn getSegmentBaseOff(self: *Elf, phdr_ndx: u16) u64 {
    const phdr = self.phdrs.items[phdr_ndx];
    const base_off = phdr.p_offset + phdr.p_filesz;
    return base_off;
}

fn allocateLoadRSeg(self: *Elf) !void {
    const phdr = &self.phdrs.items[self.load_r_seg_index.?];
    const init_size = @sizeOf(elf.Elf64_Ehdr) + self.phdrs.items.len * @sizeOf(elf.Elf64_Phdr);
    phdr.p_offset = 0;
    phdr.p_vaddr = self.base_addr;
    phdr.p_paddr = self.base_addr;
    phdr.p_filesz = init_size;
    phdr.p_memsz = init_size;

    if (self.rodata_sect_index) |ndx| {
        try self.allocateSection(ndx, self.load_r_seg_index.?);
    }

    log.debug("allocating read-only LOAD segment:", .{});
    log.debug("  in file from 0x{x} to 0x{x}", .{ phdr.p_offset, phdr.p_offset + phdr.p_filesz });
    log.debug("  in memory from 0x{x} to 0x{x}", .{ phdr.p_vaddr, phdr.p_vaddr + phdr.p_memsz });
}

fn allocateLoadRESeg(self: *Elf) !void {
    const base_addr = self.getSegmentBaseAddr(self.load_r_seg_index.?);
    const base_off = self.getSegmentBaseOff(self.load_r_seg_index.?);
    const phdr = &self.phdrs.items[self.load_re_seg_index.?];
    phdr.p_offset = base_off;
    phdr.p_vaddr = base_addr;
    phdr.p_paddr = base_addr;
    phdr.p_filesz = 0;
    phdr.p_memsz = 0;

    if (self.text_sect_index) |ndx| {
        try self.allocateSection(ndx, self.load_re_seg_index.?);
    }

    log.debug("allocating read-execute LOAD segment:", .{});
    log.debug("  in file from 0x{x} to 0x{x}", .{ phdr.p_offset, phdr.p_offset + phdr.p_filesz });
    log.debug("  in memory from 0x{x} to 0x{x}", .{ phdr.p_vaddr, phdr.p_vaddr + phdr.p_memsz });
}

fn allocateLoadRWSeg(self: *Elf) !void {
    const base_addr = self.getSegmentBaseAddr(self.load_re_seg_index.?);
    const base_off = self.getSegmentBaseOff(self.load_re_seg_index.?);
    const phdr = &self.phdrs.items[self.load_rw_seg_index.?];
    phdr.p_offset = base_off;
    phdr.p_vaddr = base_addr;
    phdr.p_paddr = base_addr;
    phdr.p_filesz = 0;
    phdr.p_memsz = 0;

    if (self.data_sect_index) |ndx| {
        try self.allocateSection(ndx, self.load_rw_seg_index.?);
    }

    log.debug("allocating read-write LOAD segment:", .{});
    log.debug("  in file from 0x{x} to 0x{x}", .{ phdr.p_offset, phdr.p_offset + phdr.p_filesz });
    log.debug("  in memory from 0x{x} to 0x{x}", .{ phdr.p_vaddr, phdr.p_vaddr + phdr.p_memsz });

    self.next_offset = phdr.p_offset + phdr.p_filesz;
}

fn allocateAtoms(self: *Elf) !void {
    var it = self.atoms.iterator();
    while (it.next()) |entry| {
        const shdr_ndx = entry.key_ptr.*;
        const shdr = self.shdrs.items[shdr_ndx];
        var atom: *Atom = entry.value_ptr.*;

        // Find the first atom
        while (atom.prev) |prev| {
            atom = prev;
        }

        log.debug("allocating atoms in '{s}' section", .{self.getShString(shdr.sh_name)});

        var base_addr: u64 = shdr.sh_addr;
        while (true) {
            base_addr = mem.alignForwardGeneric(u64, base_addr, atom.alignment);

            const object = &self.objects.items[atom.file];
            const sym = &object.symtab.items[atom.local_sym_index];
            sym.st_value = base_addr;
            sym.st_shndx = shdr_ndx;
            sym.st_size = atom.size;

            log.debug("  atom '{s}' allocated from 0x{x} to 0x{x}", .{
                object.getString(sym.st_name),
                base_addr,
                base_addr + atom.size,
            });

            // Update each alias (if any)
            for (atom.aliases.items) |index| {
                const alias_sym = &object.symtab.items[index];
                alias_sym.st_value = base_addr;
                alias_sym.st_shndx = shdr_ndx;
                alias_sym.st_size = atom.size;
            }

            // Update each symbol contained within the TextBlock
            for (atom.contained.items) |sym_at_off| {
                const contained_sym = &object.symtab.items[sym_at_off.local_sym_index];
                contained_sym.st_value = base_addr + sym_at_off.offset;
                contained_sym.st_shndx = shdr_ndx;
            }

            base_addr += atom.size;

            if (atom.next) |next| {
                atom = next;
            } else break;
        }
    }
}

fn writeAtoms(self: *Elf) !void {
    var it = self.atoms.iterator();
    while (it.next()) |entry| {
        const shdr_ndx = entry.key_ptr.*;
        const shdr = self.shdrs.items[shdr_ndx];
        var atom: *Atom = entry.value_ptr.*;

        // Find the first atom
        while (atom.prev) |prev| {
            atom = prev;
        }

        log.debug("writing atoms in '{s}' section", .{self.getShString(shdr.sh_name)});

        var buffer = try self.base.allocator.alloc(u8, shdr.sh_size);
        defer self.base.allocator.free(buffer);
        mem.set(u8, buffer, 0);

        while (true) {
            const object = self.objects.items[atom.file];
            const sym = object.symtab.items[atom.local_sym_index];
            const off = sym.st_value - shdr.sh_addr;

            try atom.resolveRelocs(self);

            log.debug("writing atom '{s}' at offset 0x{x}", .{
                object.getString(sym.st_name),
                shdr.sh_offset + off,
            });

            mem.copy(u8, buffer[off..][0..atom.size], atom.code.items);

            if (atom.next) |next| {
                atom = next;
            } else break;
        }

        try self.base.file.pwriteAll(buffer, shdr.sh_offset);
    }
}

fn setEntryPoint(self: *Elf) !void {
    if (self.base.options.output_mode != .exe) return;
    const global = self.globals.get("_start") orelse return error.DefaultEntryPointNotFound;
    const object = self.objects.items[global.file];
    const sym = object.symtab.items[global.sym_index];
    self.header.?.e_entry = sym.st_value;
}

fn writeSymtab(self: *Elf) !void {
    const shdr = &self.shdrs.items[self.symtab_sect_index.?];

    var symtab = std.ArrayList(elf.Elf64_Sym).init(self.base.allocator);
    defer symtab.deinit();
    try symtab.ensureUnusedCapacity(1);
    symtab.appendAssumeCapacity(.{
        .st_name = 0,
        .st_info = 0,
        .st_other = 0,
        .st_shndx = 0,
        .st_value = 0,
        .st_size = 0,
    });

    for (self.objects.items) |object| {
        for (object.symtab.items) |sym| {
            if (sym.st_name == 0) continue;
            const st_bind = sym.st_info >> 4;
            const st_type = sym.st_info & 0xf;
            if (st_bind != elf.STB_LOCAL) continue;
            if (st_type == elf.STT_SECTION) continue;

            const sym_name = object.getString(sym.st_name);
            var out_sym = sym;
            out_sym.st_name = try self.makeString(sym_name);
            try symtab.append(out_sym);
        }
    }

    // Denote start of globals
    shdr.sh_info = @intCast(u32, symtab.items.len);
    try symtab.ensureUnusedCapacity(self.globals.count());
    for (self.globals.values()) |global| {
        const obj = self.objects.items[global.file];
        const sym = obj.symtab.items[global.sym_index];
        const sym_name = obj.getString(sym.st_name);

        var out_sym = sym;
        out_sym.st_name = try self.makeString(sym_name);
        symtab.appendAssumeCapacity(out_sym);
    }

    shdr.sh_offset = mem.alignForwardGeneric(u64, self.next_offset, @alignOf(elf.Elf64_Sym));
    shdr.sh_size = symtab.items.len * @sizeOf(elf.Elf64_Sym);
    log.debug("writing '{s}' contents from 0x{x} to 0x{x}", .{
        self.getShString(shdr.sh_name),
        shdr.sh_offset,
        shdr.sh_offset + shdr.sh_size,
    });
    try self.base.file.pwriteAll(mem.sliceAsBytes(symtab.items), shdr.sh_offset);
    self.next_offset = shdr.sh_offset + shdr.sh_size;
}

fn writeStrtab(self: *Elf) !void {
    const shdr = &self.shdrs.items[self.strtab_sect_index.?];
    shdr.sh_offset = self.next_offset;
    shdr.sh_size = self.strtab.items.len;
    log.debug("writing '{s}' contents from 0x{x} to 0x{x}", .{
        self.getShString(shdr.sh_name),
        shdr.sh_offset,
        shdr.sh_offset + shdr.sh_size,
    });
    try self.base.file.pwriteAll(self.strtab.items, shdr.sh_offset);
    self.next_offset += shdr.sh_size;
}

fn writeShStrtab(self: *Elf) !void {
    const shdr = &self.shdrs.items[self.shstrtab_sect_index.?];
    shdr.sh_offset = self.next_offset;
    shdr.sh_size = self.shstrtab.items.len;
    log.debug("writing '{s}' contents from 0x{x} to 0x{x}", .{
        self.getShString(shdr.sh_name),
        shdr.sh_offset,
        shdr.sh_offset + shdr.sh_size,
    });
    try self.base.file.pwriteAll(self.shstrtab.items, shdr.sh_offset);
    self.next_offset += shdr.sh_size;
}

fn writePhdrs(self: *Elf) !void {
    const phdrs_size = self.phdrs.items.len * @sizeOf(elf.Elf64_Phdr);
    log.debug("writing program headers from 0x{x} to 0x{x}", .{
        self.header.?.e_phoff,
        self.header.?.e_phoff + phdrs_size,
    });
    try self.base.file.pwriteAll(mem.sliceAsBytes(self.phdrs.items), self.header.?.e_phoff);
}

fn writeShdrs(self: *Elf) !void {
    const shdrs_size = self.shdrs.items.len * @sizeOf(elf.Elf64_Shdr);
    const e_shoff = mem.alignForwardGeneric(u64, self.next_offset, @alignOf(elf.Elf64_Shdr));
    log.debug("writing section headers from 0x{x} to 0x{x}", .{
        e_shoff,
        e_shoff + shdrs_size,
    });
    try self.base.file.pwriteAll(mem.sliceAsBytes(self.shdrs.items), e_shoff);
    self.header.?.e_shoff = e_shoff;
    self.next_offset = e_shoff + shdrs_size;
}

fn writeHeader(self: *Elf) !void {
    self.header.?.e_phnum = @intCast(u16, self.phdrs.items.len);
    self.header.?.e_shnum = @intCast(u16, self.shdrs.items.len);
    log.debug("writing ELF header {} at 0x{x}", .{ self.header.?, 0 });
    try self.base.file.pwriteAll(mem.asBytes(&self.header.?), 0);
}

fn makeShString(self: *Elf, bytes: []const u8) !u32 {
    try self.shstrtab.ensureUnusedCapacity(self.base.allocator, bytes.len + 1);
    const new_off = @intCast(u32, self.shstrtab.items.len);
    log.debug("writing new string'{s}' in .shstrtab at offset 0x{x}", .{ bytes, new_off });
    self.shstrtab.appendSliceAssumeCapacity(bytes);
    self.shstrtab.appendAssumeCapacity(0);
    return new_off;
}

fn getShString(self: Elf, off: u32) []const u8 {
    assert(off < self.shstrtab.items.len);
    return mem.spanZ(@ptrCast([*:0]const u8, self.shstrtab.items.ptr + off));
}

fn makeString(self: *Elf, bytes: []const u8) !u32 {
    try self.strtab.ensureUnusedCapacity(self.base.allocator, bytes.len + 1);
    const new_off = @intCast(u32, self.strtab.items.len);
    log.debug("writing new string'{s}' in .strtab at offset 0x{x}", .{ bytes, new_off });
    self.strtab.appendSliceAssumeCapacity(bytes);
    self.strtab.appendAssumeCapacity(0);
    return new_off;
}

fn getString(self: Elf, off: u32) []const u8 {
    assert(off < self.strtab.items.len);
    return mem.spanZ(@ptrCast([*:0]const u8, self.strtab.items.ptr + off));
}

fn logSymtab(self: Elf) !void {
    for (self.objects.items) |object| {
        log.debug("locals in {s}", .{object.name});
        for (object.symtab.items) |sym, i| {
            const st_bind = sym.st_info >> 4;
            if (st_bind != elf.STB_LOCAL) continue;
            log.debug("  {d}: {s}: {}", .{ i, object.getString(sym.st_name), sym });
        }
    }

    log.debug("globals:", .{});
    for (self.globals.values()) |global| {
        const object = self.objects.items[global.file];
        const sym = object.symtab.items[global.sym_index];
        log.debug("  {s}: {} => {}", .{ object.getString(sym.st_name), global, sym });
    }
}
