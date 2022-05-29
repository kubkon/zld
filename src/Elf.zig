const Elf = @This();

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const elf = std.elf;
const fs = std.fs;
const log = std.log.scoped(.elf);
const mem = std.mem;

const Allocator = mem.Allocator;
const Archive = @import("Elf/Archive.zig");
const Atom = @import("Elf/Atom.zig");
const Object = @import("Elf/Object.zig");
const Zld = @import("Zld.zig");

pub const base_tag = Zld.Tag.elf;

base: Zld,

archives: std.ArrayListUnmanaged(Archive) = .{},
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
tls_seg_index: ?u16 = null,

null_sect_index: ?u16 = null,
rodata_sect_index: ?u16 = null,
text_sect_index: ?u16 = null,
init_sect_index: ?u16 = null,
init_array_sect_index: ?u16 = null,
fini_sect_index: ?u16 = null,
fini_array_sect_index: ?u16 = null,
data_rel_ro_sect_index: ?u16 = null,
got_sect_index: ?u16 = null,
data_sect_index: ?u16 = null,
bss_sect_index: ?u16 = null,
tdata_sect_index: ?u16 = null,
tbss_sect_index: ?u16 = null,

debug_loc_index: ?u16 = null,
debug_abbrev_index: ?u16 = null,
debug_info_index: ?u16 = null,
debug_str_index: ?u16 = null,
debug_frame_index: ?u16 = null,
debug_line_index: ?u16 = null,

symtab_sect_index: ?u16 = null,
strtab_sect_index: ?u16 = null,
shstrtab_sect_index: ?u16 = null,

next_offset: u64 = 0,

base_addr: u64 = 0x200000,

locals: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
globals: std.StringArrayHashMapUnmanaged(SymbolWithLoc) = .{},
unresolved: std.AutoArrayHashMapUnmanaged(u32, void) = .{},

got_entries_map: std.AutoArrayHashMapUnmanaged(SymbolWithLoc, *Atom) = .{},

managed_atoms: std.ArrayListUnmanaged(*Atom) = .{},
atoms: std.AutoHashMapUnmanaged(u16, *Atom) = .{},

pub const SymbolWithLoc = struct {
    /// Index in the respective symbol table.
    sym_index: u32,

    /// null means it's a synthetic global.
    file: ?u16,
};

pub fn openPath(allocator: Allocator, options: Zld.Options) !*Elf {
    const file = try options.emit.directory.createFile(options.emit.sub_path, .{
        .truncate = true,
        .read = true,
        .mode = if (builtin.os.tag == .windows) 0 else 0o777,
    });
    errdefer file.close();

    const self = try createEmpty(allocator, options);
    errdefer allocator.destroy(self);

    self.base.file = file;

    try self.populateMetadata();

    return self;
}

fn createEmpty(gpa: Allocator, options: Zld.Options) !*Elf {
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
    self.got_entries_map.deinit(self.base.allocator);
    self.unresolved.deinit(self.base.allocator);
    self.globals.deinit(self.base.allocator);
    self.locals.deinit(self.base.allocator);
    self.shstrtab.deinit(self.base.allocator);
    self.strtab.deinit(self.base.allocator);
    self.shdrs.deinit(self.base.allocator);
    self.phdrs.deinit(self.base.allocator);
    for (self.objects.items) |*object| {
        object.deinit(self.base.allocator);
    }
    self.objects.deinit(self.base.allocator);
    for (self.archives.items) |*archive| {
        archive.deinit(self.base.allocator);
    }
    self.archives.deinit(self.base.allocator);
}

fn closeFiles(self: Elf) void {
    for (self.objects.items) |object| {
        object.file.close();
    }
    for (self.archives.items) |archive| {
        archive.file.close();
    }
}

fn resolveLib(
    arena: Allocator,
    search_dirs: []const []const u8,
    name: []const u8,
    ext: []const u8,
) !?[]const u8 {
    const search_name = try std.fmt.allocPrint(arena, "lib{s}{s}", .{ name, ext });

    for (search_dirs) |dir| {
        const full_path = try fs.path.join(arena, &[_][]const u8{ dir, search_name });

        // Check if the file exists.
        const tmp = fs.cwd().openFile(full_path, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        defer tmp.close();

        return full_path;
    }

    return null;
}

pub fn flush(self: *Elf) !void {
    var arena_allocator = std.heap.ArenaAllocator.init(self.base.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var lib_dirs = std.ArrayList([]const u8).init(arena);
    for (self.base.options.lib_dirs) |dir| {
        // Verify that search path actually exists
        var tmp = fs.cwd().openDir(dir, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        defer tmp.close();

        try lib_dirs.append(dir);
    }

    var libs = std.ArrayList([]const u8).init(arena);
    var lib_not_found = false;
    for (self.base.options.libs) |lib_name| {
        for (&[_][]const u8{ ".dylib", ".a" }) |ext| {
            if (try resolveLib(arena, lib_dirs.items, lib_name, ext)) |full_path| {
                try libs.append(full_path);
                break;
            }
        } else {
            log.warn("library not found for '-l{s}'", .{lib_name});
            lib_not_found = true;
        }
    }
    if (lib_not_found) {
        log.warn("Library search paths:", .{});
        for (lib_dirs.items) |dir| {
            log.warn("  {s}", .{dir});
        }
    }

    try self.parsePositionals(self.base.options.positionals);
    try self.parseLibs(libs.items);

    for (self.objects.items) |_, object_id| {
        try self.resolveSymbolsInObject(@intCast(u16, object_id));
    }
    try self.resolveSymbolsInArchives();
    try self.resolveSpecialSymbols();

    // self.logSymtab();

    for (self.unresolved.keys()) |ndx| {
        const global = self.globals.values()[ndx];
        const object = self.objects.items[global.file.?];
        const sym = object.symtab.items[global.sym_index];
        const sym_name = object.getString(sym.st_name);
        log.err("undefined reference to symbol '{s}'", .{sym_name});
        log.err("  first referenced in '{s}'", .{object.name});
    }
    if (self.unresolved.count() > 0) {
        return error.UndefinedSymbolReference;
    }

    for (self.objects.items) |*object, object_id| {
        try object.parseIntoAtoms(self.base.allocator, @intCast(u16, object_id), self);
    }

    try self.sortShdrs();

    try self.allocateLoadRSeg();
    try self.allocateLoadRESeg();
    try self.allocateTlsSeg();
    try self.allocateLoadRWSeg();
    try self.allocateNonAllocSections();
    try self.allocateAtoms();
    try self.setEntryPoint();

    {
        // TODO this should be put in its own logic but probably is linked to
        // C++ handling so leaving it here until I gather more knowledge on
        // those special symbols.
        if (self.init_array_sect_index == null) {
            if (self.globals.get("__init_array_start")) |global| {
                assert(global.file == null);
                const sym = &self.locals.items[global.sym_index];
                sym.st_value = self.header.?.e_entry;
                sym.st_shndx = self.text_sect_index.?;
            }
            if (self.globals.get("__init_array_end")) |global| {
                assert(global.file == null);
                const sym = &self.locals.items[global.sym_index];
                sym.st_value = self.header.?.e_entry;
                sym.st_shndx = self.text_sect_index.?;
            }
        }
        if (self.fini_array_sect_index == null) {
            if (self.globals.get("__fini_array_start")) |global| {
                assert(global.file == null);
                const sym = &self.locals.items[global.sym_index];
                sym.st_value = self.header.?.e_entry;
                sym.st_shndx = self.text_sect_index.?;
            }
            if (self.globals.get("__fini_array_end")) |global| {
                assert(global.file == null);
                const sym = &self.locals.items[global.sym_index];
                sym.st_value = self.header.?.e_entry;
                sym.st_shndx = self.text_sect_index.?;
            }
        }
    }

    self.logSymtab();
    self.logAtoms();

    try self.writeAtoms();
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
    if (self.null_sect_index == null) {
        self.null_sect_index = @intCast(u16, self.shdrs.items.len);
        try self.shdrs.append(self.base.allocator, .{
            .sh_name = 0,
            .sh_type = elf.SHT_NULL,
            .sh_flags = 0,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = 0,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = 0,
            .sh_entsize = 0,
        });
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
        try self.strtab.append(self.base.allocator, 0);
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
}

pub fn getMatchingSection(self: *Elf, object_id: u16, sect_id: u16) !?u16 {
    const object = self.objects.items[object_id];
    const shdr = object.shdrs.items[sect_id];
    const shdr_name = object.getString(shdr.sh_name);
    const flags = shdr.sh_flags;
    const res: ?u16 = blk: {
        if (flags & elf.SHF_EXCLUDE != 0) break :blk null;
        if (flags & elf.SHF_ALLOC == 0) {
            if (flags & elf.SHF_MERGE != 0 and flags & elf.SHF_STRINGS != 0) {
                if (mem.eql(u8, shdr_name, ".debug_str")) {
                    if (self.debug_str_index == null) {
                        self.debug_str_index = @intCast(u16, self.shdrs.items.len);
                        try self.shdrs.append(self.base.allocator, .{
                            .sh_name = try self.makeShString(shdr_name),
                            .sh_type = elf.SHT_PROGBITS,
                            .sh_flags = elf.SHF_MERGE | elf.SHF_STRINGS,
                            .sh_addr = 0,
                            .sh_offset = 0,
                            .sh_size = 0,
                            .sh_link = 0,
                            .sh_info = 0,
                            .sh_addralign = 0,
                            .sh_entsize = 1,
                        });
                    }
                    break :blk self.debug_str_index.?;
                } else if (mem.eql(u8, shdr_name, ".comment")) {
                    log.debug("TODO .comment section", .{});
                    break :blk null;
                }
            } else if (flags == 0) {
                if (mem.eql(u8, shdr_name, ".debug_loc")) {
                    if (self.debug_loc_index == null) {
                        self.debug_loc_index = @intCast(u16, self.shdrs.items.len);
                        try self.shdrs.append(self.base.allocator, .{
                            .sh_name = try self.makeShString(shdr_name),
                            .sh_type = elf.SHT_PROGBITS,
                            .sh_flags = 0,
                            .sh_addr = 0,
                            .sh_offset = 0,
                            .sh_size = 0,
                            .sh_link = 0,
                            .sh_info = 0,
                            .sh_addralign = 0,
                            .sh_entsize = 0,
                        });
                    }
                    break :blk self.debug_loc_index.?;
                } else if (mem.eql(u8, shdr_name, ".debug_abbrev")) {
                    if (self.debug_abbrev_index == null) {
                        self.debug_abbrev_index = @intCast(u16, self.shdrs.items.len);
                        try self.shdrs.append(self.base.allocator, .{
                            .sh_name = try self.makeShString(shdr_name),
                            .sh_type = elf.SHT_PROGBITS,
                            .sh_flags = 0,
                            .sh_addr = 0,
                            .sh_offset = 0,
                            .sh_size = 0,
                            .sh_link = 0,
                            .sh_info = 0,
                            .sh_addralign = 0,
                            .sh_entsize = 0,
                        });
                    }
                    break :blk self.debug_abbrev_index.?;
                } else if (mem.eql(u8, shdr_name, ".debug_info")) {
                    if (self.debug_info_index == null) {
                        self.debug_info_index = @intCast(u16, self.shdrs.items.len);
                        try self.shdrs.append(self.base.allocator, .{
                            .sh_name = try self.makeShString(shdr_name),
                            .sh_type = elf.SHT_PROGBITS,
                            .sh_flags = 0,
                            .sh_addr = 0,
                            .sh_offset = 0,
                            .sh_size = 0,
                            .sh_link = 0,
                            .sh_info = 0,
                            .sh_addralign = 0,
                            .sh_entsize = 0,
                        });
                    }
                    break :blk self.debug_info_index.?;
                } else if (mem.eql(u8, shdr_name, ".debug_frame")) {
                    if (self.debug_frame_index == null) {
                        self.debug_frame_index = @intCast(u16, self.shdrs.items.len);
                        try self.shdrs.append(self.base.allocator, .{
                            .sh_name = try self.makeShString(shdr_name),
                            .sh_type = elf.SHT_PROGBITS,
                            .sh_flags = 0,
                            .sh_addr = 0,
                            .sh_offset = 0,
                            .sh_size = 0,
                            .sh_link = 0,
                            .sh_info = 0,
                            .sh_addralign = 0,
                            .sh_entsize = 0,
                        });
                    }
                    break :blk self.debug_frame_index.?;
                } else if (mem.eql(u8, shdr_name, ".debug_line")) {
                    if (self.debug_line_index == null) {
                        self.debug_line_index = @intCast(u16, self.shdrs.items.len);
                        try self.shdrs.append(self.base.allocator, .{
                            .sh_name = try self.makeShString(shdr_name),
                            .sh_type = elf.SHT_PROGBITS,
                            .sh_flags = 0,
                            .sh_addr = 0,
                            .sh_offset = 0,
                            .sh_size = 0,
                            .sh_link = 0,
                            .sh_info = 0,
                            .sh_addralign = 0,
                            .sh_entsize = 0,
                        });
                    }
                    break :blk self.debug_line_index.?;
                }
            }

            log.debug("TODO non-alloc sections", .{});
            log.debug("  {s} => {}", .{ object.getString(shdr.sh_name), shdr });
            break :blk null;
        }
        if (flags & elf.SHF_EXECINSTR != 0) {
            if (mem.eql(u8, shdr_name, ".init")) {
                if (self.init_sect_index == null) {
                    self.init_sect_index = @intCast(u16, self.shdrs.items.len);
                    try self.shdrs.append(self.base.allocator, .{
                        .sh_name = try self.makeShString(shdr_name),
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
                break :blk self.init_sect_index.?;
            } else if (mem.eql(u8, shdr_name, ".fini")) {
                if (self.fini_sect_index == null) {
                    self.fini_sect_index = @intCast(u16, self.shdrs.items.len);
                    try self.shdrs.append(self.base.allocator, .{
                        .sh_name = try self.makeShString(shdr_name),
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
                break :blk self.fini_sect_index.?;
            } else if (mem.eql(u8, shdr_name, ".init_array")) {
                if (self.init_array_sect_index == null) {
                    self.init_array_sect_index = @intCast(u16, self.shdrs.items.len);
                    try self.shdrs.append(self.base.allocator, .{
                        .sh_name = try self.makeShString(shdr_name),
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
                break :blk self.init_array_sect_index.?;
            } else if (mem.eql(u8, shdr_name, ".fini_array")) {
                if (self.fini_array_sect_index == null) {
                    self.fini_array_sect_index = @intCast(u16, self.shdrs.items.len);
                    try self.shdrs.append(self.base.allocator, .{
                        .sh_name = try self.makeShString(shdr_name),
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
                break :blk self.fini_array_sect_index.?;
            }

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
            if (shdr.sh_type == elf.SHT_NOBITS) {
                if (shdr.sh_flags & elf.SHF_TLS != 0) {
                    if (self.tls_seg_index == null) {
                        self.tls_seg_index = @intCast(u16, self.phdrs.items.len);
                        try self.phdrs.append(self.base.allocator, .{
                            .p_type = elf.PT_TLS,
                            .p_flags = elf.PF_R,
                            .p_offset = 0,
                            .p_vaddr = self.base_addr,
                            .p_paddr = self.base_addr,
                            .p_filesz = 0,
                            .p_memsz = 0,
                            .p_align = 0,
                        });
                    }
                    if (self.tbss_sect_index == null) {
                        self.tbss_sect_index = @intCast(u16, self.shdrs.items.len);
                        try self.shdrs.append(self.base.allocator, .{
                            .sh_name = try self.makeShString(".tbss"),
                            .sh_type = elf.SHT_NOBITS,
                            .sh_flags = elf.SHF_WRITE | elf.SHF_ALLOC | elf.SHF_TLS,
                            .sh_addr = 0,
                            .sh_offset = 0,
                            .sh_size = 0,
                            .sh_link = 0,
                            .sh_info = 0,
                            .sh_addralign = 0,
                            .sh_entsize = 0,
                        });
                    }
                    break :blk self.tbss_sect_index.?;
                }

                if (self.bss_sect_index == null) {
                    self.bss_sect_index = @intCast(u16, self.shdrs.items.len);
                    try self.shdrs.append(self.base.allocator, .{
                        .sh_name = try self.makeShString(".bss"),
                        .sh_type = elf.SHT_NOBITS,
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
                break :blk self.bss_sect_index.?;
            }
            if (mem.startsWith(u8, shdr_name, ".data.rel.ro")) {
                if (self.data_rel_ro_sect_index == null) {
                    self.data_rel_ro_sect_index = @intCast(u16, self.shdrs.items.len);
                    try self.shdrs.append(self.base.allocator, .{
                        .sh_name = try self.makeShString(".data.rel.ro"),
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
                break :blk self.data_rel_ro_sect_index.?;
            }

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
    try self.shdrs.ensureTotalCapacity(self.base.allocator, shdrs.len);

    const indices = &[_]*?u16{
        // null
        &self.null_sect_index,
        // RO
        &self.rodata_sect_index,
        // RE
        &self.text_sect_index,
        &self.init_sect_index,
        &self.init_array_sect_index,
        &self.fini_sect_index,
        &self.fini_array_sect_index,
        // TLS
        &self.tbss_sect_index,
        // RW
        &self.data_rel_ro_sect_index,
        &self.got_sect_index,
        &self.data_sect_index,
        &self.bss_sect_index,
        // DWARF
        &self.debug_loc_index,
        &self.debug_abbrev_index,
        &self.debug_info_index,
        &self.debug_str_index,
        &self.debug_frame_index,
        &self.debug_line_index,
        // link-edit
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
    try transient.ensureTotalCapacity(self.base.allocator, self.atoms.count());

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
        if (try self.parseArchive(full_path)) continue;

        log.warn("unknown filetype for positional input file: '{s}'", .{file_name});
    }
}

fn parseLibs(self: *Elf, libs: []const []const u8) !void {
    for (libs) |lib| {
        log.debug("parsing lib path '{s}'", .{lib});
        if (try self.parseArchive(lib)) continue;

        log.warn("unknown filetype for a library: '{s}'", .{lib});
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

fn parseArchive(self: *Elf, path: []const u8) !bool {
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    errdefer file.close();

    const name = try self.base.allocator.dupe(u8, path);
    errdefer self.base.allocator.free(name);

    var archive = Archive{
        .name = name,
        .file = file,
    };

    archive.parse(self.base.allocator) catch |err| switch (err) {
        error.EndOfStream, error.NotArchive => {
            archive.deinit(self.base.allocator);
            return false;
        },
        else => |e| return e,
    };

    try self.archives.append(self.base.allocator, archive);

    return true;
}

fn resolveSymbolsInObject(self: *Elf, object_id: u16) !void {
    const object = self.objects.items[object_id];

    log.debug("resolving symbols in {s}", .{object.name});

    for (object.symtab.items) |sym, i| {
        const sym_id = @intCast(u32, i);
        const sym_name = object.getString(sym.st_name);
        const st_bind = sym.st_info >> 4;
        const st_type = sym.st_info & 0xf;

        switch (st_bind) {
            elf.STB_LOCAL => {
                log.debug("  (symbol '{s}' local to object; skipping...)", .{sym_name});
                continue;
            },
            elf.STB_WEAK, elf.STB_GLOBAL => {
                const name = try self.base.allocator.dupe(u8, sym_name);
                const glob_ndx = @intCast(u32, self.globals.values().len);
                const res = try self.globals.getOrPut(self.base.allocator, name);
                defer if (res.found_existing) self.base.allocator.free(name);

                if (!res.found_existing) {
                    res.value_ptr.* = .{
                        .sym_index = sym_id,
                        .file = object_id,
                    };
                    if (sym.st_shndx == elf.SHN_UNDEF and st_type == elf.STT_NOTYPE) {
                        try self.unresolved.putNoClobber(self.base.allocator, glob_ndx, {});
                    }
                    continue;
                }

                const global = res.value_ptr.*;
                const linked_obj = self.objects.items[global.file.?];
                const linked_sym = linked_obj.symtab.items[global.sym_index];
                const linked_sym_bind = linked_sym.st_info >> 4;

                if (sym.st_shndx == elf.SHN_UNDEF and st_type == elf.STT_NOTYPE) {
                    log.debug("  (symbol '{s}' already defined; skipping...)", .{sym_name});
                    continue;
                }

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
                _ = self.unresolved.fetchSwapRemove(@intCast(u32, self.globals.getIndex(name).?));

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

fn resolveSymbolsInArchives(self: *Elf) !void {
    if (self.archives.items.len == 0) return;

    var next_sym: usize = 0;
    loop: while (next_sym < self.unresolved.count()) {
        const global = self.globals.values()[self.unresolved.keys()[next_sym]];
        const ref_object = self.objects.items[global.file.?];
        const sym = ref_object.symtab.items[global.sym_index];
        const sym_name = ref_object.getString(sym.st_name);

        for (self.archives.items) |archive| {
            // Check if the entry exists in a static archive.
            const offsets = archive.toc.get(sym_name) orelse {
                // No hit.
                continue;
            };
            assert(offsets.items.len > 0);

            const object_id = @intCast(u16, self.objects.items.len);
            const object = try self.objects.addOne(self.base.allocator);
            object.* = try archive.parseObject(self.base.allocator, self.base.options.target, offsets.items[0]);
            try self.resolveSymbolsInObject(object_id);

            continue :loop;
        }

        next_sym += 1;
    }
}

fn resolveSpecialSymbols(self: *Elf) !void {
    var next_sym: usize = 0;
    loop: while (next_sym < self.unresolved.count()) {
        const global = &self.globals.values()[self.unresolved.keys()[next_sym]];
        const object = self.objects.items[global.file.?];
        const sym = object.symtab.items[global.sym_index];
        const sym_name = object.getString(sym.st_name);

        if (mem.eql(u8, sym_name, "__init_array_start") or
            mem.eql(u8, sym_name, "__init_array_end") or
            mem.eql(u8, sym_name, "__fini_array_start") or
            mem.eql(u8, sym_name, "__fini_array_end") or
            mem.eql(u8, sym_name, "_DYNAMIC"))
        {
            const st_shndx: u8 = if (mem.eql(u8, sym_name, "_DYNAMIC")) 0 else 1;
            const sym_index = @intCast(u32, self.locals.items.len);
            try self.locals.append(self.base.allocator, .{
                .st_name = try self.makeString(sym_name),
                .st_info = 0,
                .st_other = 0,
                .st_shndx = st_shndx,
                .st_value = 0,
                .st_size = 0,
            });
            global.* = .{
                .sym_index = sym_index,
                .file = null,
            };
            _ = self.unresolved.fetchSwapRemove(@intCast(u32, self.globals.getIndex(sym_name).?));

            continue :loop;
        }

        next_sym += 1;
    }
}

pub fn createGotAtom(self: *Elf, target: SymbolWithLoc) !*Atom {
    const shdr_ndx = self.got_sect_index orelse blk: {
        const shdr_ndx = @intCast(u16, self.shdrs.items.len);
        try self.shdrs.append(self.base.allocator, .{
            .sh_name = try self.makeShString(".got"),
            .sh_type = elf.SHT_PROGBITS,
            .sh_flags = elf.SHF_WRITE | elf.SHF_ALLOC,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = 0,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = @alignOf(u64),
            .sh_entsize = 0,
        });
        self.got_sect_index = shdr_ndx;
        break :blk shdr_ndx;
    };
    const shdr = &self.shdrs.items[shdr_ndx];

    const atom = try Atom.createEmpty(self.base.allocator);
    errdefer {
        atom.deinit(self.base.allocator);
        self.base.allocator.destroy(atom);
    }
    try self.managed_atoms.append(self.base.allocator, atom);

    atom.file = null;
    atom.size = @sizeOf(u64);
    atom.alignment = @alignOf(u64);

    var code = try self.base.allocator.alloc(u8, @sizeOf(u64));
    defer self.base.allocator.free(code);
    mem.set(u8, code, 0);
    try atom.code.appendSlice(self.base.allocator, code);

    const tsym = if (target.file) |file| blk: {
        const object = self.objects.items[file];
        break :blk object.symtab.items[target.sym_index];
    } else self.locals.items[target.sym_index];
    const tsym_name = if (target.file) |file| blk: {
        const object = self.objects.items[file];
        break :blk object.getString(tsym.st_name);
    } else self.getString(tsym.st_name);
    const r_sym = @intCast(u64, target.sym_index) << 32;
    const r_addend: i64 = target.file orelse -1;
    const r_info = r_sym | elf.R_X86_64_64;
    try atom.relocs.append(self.base.allocator, .{
        .r_offset = 0,
        .r_info = r_info,
        .r_addend = r_addend,
    });

    const tmp_name = try std.fmt.allocPrint(self.base.allocator, ".got.{s}", .{tsym_name});
    defer self.base.allocator.free(tmp_name);
    const sym_index = @intCast(u32, self.locals.items.len);
    try self.locals.append(self.base.allocator, .{
        .st_name = try self.makeString(tmp_name),
        .st_info = (elf.STB_LOCAL << 4) | elf.STT_OBJECT,
        .st_other = 1,
        .st_shndx = shdr_ndx,
        .st_value = 0,
        .st_size = @sizeOf(u64),
    });
    atom.local_sym_index = sym_index;

    // Update target section's metadata
    shdr.sh_size += @sizeOf(u64);

    if (self.atoms.getPtr(shdr_ndx)) |last| {
        last.*.next = atom;
        atom.prev = last.*;
        last.* = atom;
    } else {
        try self.atoms.putNoClobber(self.base.allocator, shdr_ndx, atom);
    }

    return atom;
}

fn allocateSection(self: *Elf, shdr: *elf.Elf64_Shdr, phdr: *elf.Elf64_Phdr) !void {
    const base_addr = phdr.p_vaddr + phdr.p_memsz;
    shdr.sh_addr = mem.alignForwardGeneric(u64, base_addr, shdr.sh_addralign);
    const p_memsz = shdr.sh_addr + shdr.sh_size - base_addr;

    const base_offset = phdr.p_offset + phdr.p_filesz;
    shdr.sh_offset = mem.alignForwardGeneric(u64, base_offset, shdr.sh_addralign);
    const p_filesz = shdr.sh_offset + shdr.sh_size - base_offset;

    if (shdr.sh_type == elf.SHT_NOBITS) {
        log.debug("allocating section '{s}' from 0x{x} to 0x{x} (no physical size)", .{
            self.getShString(shdr.sh_name),
            shdr.sh_addr,
            shdr.sh_addr + shdr.sh_size,
        });
    } else {
        log.debug("allocating section '{s}' from 0x{x} to 0x{x} (0x{x} - 0x{x})", .{
            self.getShString(shdr.sh_name),
            shdr.sh_addr,
            shdr.sh_addr + shdr.sh_size,
            shdr.sh_offset,
            shdr.sh_offset + shdr.sh_size,
        });
        phdr.p_filesz += p_filesz;
    }

    phdr.p_memsz += p_memsz;
}

fn getSegmentBase(self: *Elf, phdr_ndx: u16, alignment: u64) struct { off: u64, vaddr: u64 } {
    const phdr = self.phdrs.items[phdr_ndx];
    const off = phdr.p_offset + phdr.p_filesz;
    const vaddr = mem.alignForwardGeneric(u64, phdr.p_vaddr + phdr.p_memsz, alignment) + @rem(off, alignment);
    return .{ .off = off, .vaddr = vaddr };
}

fn allocateLoadRSeg(self: *Elf) !void {
    const phdr = &self.phdrs.items[self.load_r_seg_index.?];
    const init_size = @sizeOf(elf.Elf64_Ehdr) + self.phdrs.items.len * @sizeOf(elf.Elf64_Phdr);
    phdr.p_offset = 0;
    phdr.p_vaddr = self.base_addr;
    phdr.p_paddr = self.base_addr;
    phdr.p_filesz = init_size;
    phdr.p_memsz = init_size;

    // This assumes ordering of section headers matches ordering of sections in file
    // so that the segments are contiguous in memory.
    for (self.shdrs.items) |*shdr| {
        const is_read_alloc = blk: {
            const flags = shdr.sh_flags;
            if (flags & elf.SHF_ALLOC == 0) break :blk false;
            if (flags & elf.SHF_WRITE != 0) break :blk false;
            if (flags & elf.SHF_EXECINSTR != 0) break :blk false;
            break :blk true;
        };
        if (!is_read_alloc) continue;
        try self.allocateSection(shdr, phdr);
    }

    log.debug("allocating read-only LOAD segment:", .{});
    log.debug("  in file from 0x{x} to 0x{x}", .{ phdr.p_offset, phdr.p_offset + phdr.p_filesz });
    log.debug("  in memory from 0x{x} to 0x{x}", .{ phdr.p_vaddr, phdr.p_vaddr + phdr.p_memsz });
}

fn allocateLoadRESeg(self: *Elf) !void {
    const phdr = &self.phdrs.items[self.load_re_seg_index.?];
    const base = self.getSegmentBase(self.load_r_seg_index.?, phdr.p_align);
    phdr.p_offset = base.off;
    phdr.p_vaddr = base.vaddr;
    phdr.p_paddr = base.vaddr;
    phdr.p_filesz = 0;
    phdr.p_memsz = 0;

    // This assumes ordering of section headers matches ordering of sections in file
    // so that the segments are contiguous in memory.
    for (self.shdrs.items) |*shdr| {
        const is_exec_alloc = blk: {
            const flags = shdr.sh_flags;
            break :blk flags & elf.SHF_ALLOC != 0 and flags & elf.SHF_EXECINSTR != 0;
        };
        if (!is_exec_alloc) continue;
        try self.allocateSection(shdr, phdr);
    }

    log.debug("allocating read-execute LOAD segment:", .{});
    log.debug("  in file from 0x{x} to 0x{x}", .{ phdr.p_offset, phdr.p_offset + phdr.p_filesz });
    log.debug("  in memory from 0x{x} to 0x{x}", .{ phdr.p_vaddr, phdr.p_vaddr + phdr.p_memsz });
}

fn allocateTlsSeg(self: *Elf) !void {
    const tls_seg_index = self.tls_seg_index orelse return;
    const phdr = &self.phdrs.items[tls_seg_index];

    // Calculate required minimum alignment first.
    var min_align: u64 = 0;
    for (self.shdrs.items) |shdr| {
        const is_write_alloc_tls = blk: {
            const flags = shdr.sh_flags;
            break :blk flags & elf.SHF_ALLOC != 0 and flags & elf.SHF_WRITE != 0 and flags & elf.SHF_TLS != 0;
        };
        if (!is_write_alloc_tls) continue;
        min_align = std.math.max(min_align, shdr.sh_addralign);
    }
    phdr.p_align = min_align;

    const base = self.getSegmentBase(self.load_re_seg_index.?, phdr.p_align);
    phdr.p_offset = base.off;
    phdr.p_vaddr = base.vaddr;
    phdr.p_paddr = base.vaddr;
    phdr.p_filesz = 0;
    phdr.p_memsz = 0;

    // This assumes ordering of section headers matches ordering of sections in file
    // so that the segments are contiguous in memory.
    for (self.shdrs.items) |*shdr| {
        const is_write_alloc_tls = blk: {
            const flags = shdr.sh_flags;
            break :blk flags & elf.SHF_ALLOC != 0 and flags & elf.SHF_WRITE != 0 and flags & elf.SHF_TLS != 0;
        };
        if (!is_write_alloc_tls) continue;
        try self.allocateSection(shdr, phdr);
    }

    log.debug("allocating TLS segment:", .{});
    log.debug("  in file from 0x{x} to 0x{x}", .{ phdr.p_offset, phdr.p_offset + phdr.p_filesz });
    log.debug("  in memory from 0x{x} to 0x{x}", .{ phdr.p_vaddr, phdr.p_vaddr + phdr.p_memsz });
}

fn allocateLoadRWSeg(self: *Elf) !void {
    const prev_seg: u16 = blk: {
        if (self.tls_seg_index) |index| break :blk index;
        break :blk self.load_re_seg_index.?;
    };
    const phdr = &self.phdrs.items[self.load_rw_seg_index.?];
    const base = self.getSegmentBase(prev_seg, phdr.p_align);
    phdr.p_offset = base.off;
    phdr.p_vaddr = base.vaddr;
    phdr.p_paddr = base.vaddr;
    phdr.p_filesz = 0;
    phdr.p_memsz = 0;

    // This assumes ordering of section headers matches ordering of sections in file
    // so that the segments are contiguous in memory.
    for (self.shdrs.items) |*shdr| {
        const is_write_alloc = blk: {
            const flags = shdr.sh_flags;
            break :blk flags & elf.SHF_ALLOC != 0 and flags & elf.SHF_WRITE != 0 and flags & elf.SHF_TLS == 0;
        };
        if (!is_write_alloc) continue;
        try self.allocateSection(shdr, phdr);
    }

    log.debug("allocating read-write LOAD segment:", .{});
    log.debug("  in file from 0x{x} to 0x{x}", .{ phdr.p_offset, phdr.p_offset + phdr.p_filesz });
    log.debug("  in memory from 0x{x} to 0x{x}", .{ phdr.p_vaddr, phdr.p_vaddr + phdr.p_memsz });

    self.next_offset = phdr.p_offset + phdr.p_filesz;
}

fn allocateNonAllocSections(self: *Elf) !void {
    for (self.shdrs.items) |*shdr| {
        if (shdr.sh_type == elf.SHT_NULL) continue;
        if (shdr.sh_flags & elf.SHF_ALLOC != 0) continue;
        shdr.sh_offset = mem.alignForwardGeneric(u64, self.next_offset, shdr.sh_addralign);
        log.debug("setting '{s}' non-alloc section's offsets from 0x{x} to 0x{x}", .{
            self.getShString(shdr.sh_name),
            shdr.sh_offset,
            shdr.sh_offset + shdr.sh_size,
        });
        self.next_offset = shdr.sh_offset + shdr.sh_size;
    }
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

            if (atom.file) |file| {
                const object = &self.objects.items[file];
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
            } else {
                // Synthetic
                const sym = &self.locals.items[atom.local_sym_index];
                sym.st_value = base_addr;
                sym.st_shndx = shdr_ndx;
                sym.st_size = atom.size;

                log.debug("  atom '{s}' allocated from 0x{x} to 0x{x}", .{
                    self.getString(sym.st_name),
                    base_addr,
                    base_addr + atom.size,
                });
            }

            base_addr += atom.size;

            if (atom.next) |next| {
                atom = next;
            } else break;
        }
    }
}

fn logAtoms(self: Elf) void {
    for (self.shdrs.items) |shdr, ndx| {
        var atom = self.atoms.get(@intCast(u16, ndx)) orelse continue;

        log.debug("WAT >>> {s}", .{self.getShString(shdr.sh_name)});

        while (atom.prev) |prev| {
            atom = prev;
        }

        while (true) {
            if (atom.file) |file| {
                const object = self.objects.items[file];
                const sym = object.symtab.items[atom.local_sym_index];
                const sym_name = object.getString(sym.st_name);
                log.debug("  {s} : {d} => 0x{x}", .{ sym_name, atom.local_sym_index, sym.st_value });
                log.debug("    defined in {s}", .{object.name});
                log.debug("    aliases:", .{});
                for (atom.aliases.items) |alias| {
                    const asym = object.symtab.items[alias];
                    const asym_name = object.getString(asym.st_name);
                    log.debug("       {s} : {d} => 0x{x}", .{ asym_name, alias, asym.st_value });
                }
            } else {
                const sym = self.locals.items[atom.local_sym_index];
                const sym_name = self.getString(sym.st_name);
                log.debug("  {s} : {d} => 0x{x}", .{ sym_name, atom.local_sym_index, sym.st_value });
                log.debug("    synthetic", .{});
                log.debug("    aliases:", .{});
                for (atom.aliases.items) |alias| {
                    const asym = self.locals.items[alias];
                    const asym_name = self.getString(asym.st_name);
                    log.debug("       {s} : {d} => 0x{x}", .{ asym_name, alias, asym.st_value });
                }
            }

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

        if (shdr.sh_type == elf.SHT_NOBITS) continue;

        var atom: *Atom = entry.value_ptr.*;

        // Find the first atom
        while (atom.prev) |prev| {
            atom = prev;
        }

        log.debug("writing atoms in '{s}' section", .{self.getShString(shdr.sh_name)});

        if (shdr.sh_flags & elf.SHF_TLS != 0 and shdr.sh_type == elf.SHT_NOBITS) continue;
        // TODO zero prefill .bss and .tbss if have presence in file

        var buffer = try self.base.allocator.alloc(u8, shdr.sh_size);
        defer self.base.allocator.free(buffer);
        mem.set(u8, buffer, 0);

        while (true) {
            const sym = if (atom.file) |file| blk: {
                const object = self.objects.items[file];
                break :blk object.symtab.items[atom.local_sym_index];
            } else self.locals.items[atom.local_sym_index];

            const off = sym.st_value - shdr.sh_addr;

            try atom.resolveRelocs(self);

            const sym_name = if (atom.file) |file|
                self.objects.items[file].getString(sym.st_name)
            else
                self.getString(sym.st_name);
            log.debug("  writing atom '{s}' at offset 0x{x}", .{ sym_name, shdr.sh_offset + off });

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
    const object = self.objects.items[global.file.?];
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

    for (self.locals.items) |sym| {
        const st_bind = sym.st_info >> 4;
        if (st_bind != elf.STB_LOCAL) continue;
        try symtab.append(sym);
    }

    // Denote start of globals
    shdr.sh_info = @intCast(u32, symtab.items.len);
    try symtab.ensureUnusedCapacity(self.globals.count());
    for (self.globals.values()) |global| {
        const sym = if (global.file) |file| blk: {
            const obj = self.objects.items[file];
            const sym = obj.symtab.items[global.sym_index];
            const sym_name = obj.getString(sym.st_name);
            var out_sym = sym;
            out_sym.st_name = try self.makeString(sym_name);
            break :blk out_sym;
        } else self.locals.items[global.sym_index];
        // TODO refactor
        if (sym.st_info >> 4 == elf.STB_LOCAL) continue;
        symtab.appendAssumeCapacity(sym);
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

pub fn getShString(self: Elf, off: u32) []const u8 {
    assert(off < self.shstrtab.items.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, self.shstrtab.items.ptr + off), 0);
}

fn makeString(self: *Elf, bytes: []const u8) !u32 {
    try self.strtab.ensureUnusedCapacity(self.base.allocator, bytes.len + 1);
    const new_off = @intCast(u32, self.strtab.items.len);
    log.debug("writing new string'{s}' in .strtab at offset 0x{x}", .{ bytes, new_off });
    self.strtab.appendSliceAssumeCapacity(bytes);
    self.strtab.appendAssumeCapacity(0);
    return new_off;
}

pub fn getString(self: Elf, off: u32) []const u8 {
    assert(off < self.strtab.items.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, self.strtab.items.ptr + off), 0);
}

fn logSymtab(self: Elf) void {
    for (self.objects.items) |object| {
        log.debug("locals in {s}", .{object.name});
        for (object.symtab.items) |sym, i| {
            const st_type = sym.st_info & 0xf;
            const st_bind = sym.st_info >> 4;
            if (st_bind != elf.STB_LOCAL or st_type != elf.STT_SECTION) continue;
            log.debug("  {d}: {s}: {}", .{ i, object.getString(sym.st_name), sym });
        }
    }

    log.debug("globals:", .{});
    for (self.globals.values()) |global| {
        if (global.file) |file| {
            const object = self.objects.items[file];
            const sym = object.symtab.items[global.sym_index];
            log.debug("  {d}: {s}: 0x{x}, {s}", .{ global.sym_index, object.getString(sym.st_name), sym.st_value, object.name });
        } else {
            const sym = self.locals.items[global.sym_index];
            log.debug("  {d}: {s}: 0x{x}", .{ global.sym_index, self.getString(sym.st_name), sym.st_value });
        }
    }
}
