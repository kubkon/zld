const Elf = @This();

const std = @import("std");
const build_options = @import("build_options");
const builtin = @import("builtin");
const assert = std.debug.assert;
const elf = std.elf;
const fs = std.fs;
const gc = @import("Elf/gc.zig");
const log = std.log.scoped(.elf);
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const Archive = @import("Elf/Archive.zig");
const Atom = @import("Elf/Atom.zig");
const Object = @import("Elf/Object.zig");
pub const Options = @import("Elf/Options.zig");
const StringTable = @import("strtab.zig").StringTable;
const ThreadPool = @import("ThreadPool.zig");
const Zld = @import("Zld.zig");

pub const base_tag = Zld.Tag.elf;

base: Zld,
options: Options,

archives: std.ArrayListUnmanaged(Archive) = .{},
objects: std.ArrayListUnmanaged(Object) = .{},

header: ?elf.Elf64_Ehdr = null,
phdrs: std.ArrayListUnmanaged(elf.Elf64_Phdr) = .{},

sections: std.MultiArrayList(Section) = .{},

strtab: StringTable(.strtab) = .{},
shstrtab: StringTable(.shstrtab) = .{},

phdr_seg_index: ?u16 = null,
load_r_seg_index: ?u16 = null,
load_re_seg_index: ?u16 = null,
load_rw_seg_index: ?u16 = null,
tls_seg_index: ?u16 = null,
gnu_stack_phdr_index: ?u16 = null,

text_sect_index: ?u16 = null,
got_sect_index: ?u16 = null,
symtab_sect_index: ?u16 = null,
strtab_sect_index: ?u16 = null,
shstrtab_sect_index: ?u16 = null,

locals: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
globals: std.StringArrayHashMapUnmanaged(SymbolWithLoc) = .{},
unresolved: std.AutoArrayHashMapUnmanaged(u32, void) = .{},

got_entries_map: std.AutoArrayHashMapUnmanaged(SymbolWithLoc, *Atom) = .{},

managed_atoms: std.ArrayListUnmanaged(*Atom) = .{},
atom_table: std.AutoHashMapUnmanaged(u32, *Atom) = .{},

const Section = struct {
    shdr: elf.Elf64_Shdr,
    last_atom: ?*Atom,
};

/// Special st_other value used internally by zld to mark symbol
/// as GCed.
pub const STV_GC: u8 = std.math.maxInt(u8);

pub const SymbolWithLoc = struct {
    /// Index in the respective symbol table.
    sym_index: u32,

    /// null means it's a synthetic global.
    file: ?u32,
};

const default_base_addr: u64 = 0x200000;

pub fn openPath(allocator: Allocator, options: Options, thread_pool: *ThreadPool) !*Elf {
    const file = try options.emit.directory.createFile(options.emit.sub_path, .{
        .truncate = true,
        .read = true,
        .mode = if (builtin.os.tag == .windows) 0 else 0o777,
    });
    errdefer file.close();

    const self = try createEmpty(allocator, options, thread_pool);
    errdefer allocator.destroy(self);

    self.base.file = file;

    try self.populateMetadata();

    return self;
}

fn createEmpty(gpa: Allocator, options: Options, thread_pool: *ThreadPool) !*Elf {
    const self = try gpa.create(Elf);

    self.* = .{
        .base = .{
            .tag = .elf,
            .allocator = gpa,
            .file = undefined,
            .thread_pool = thread_pool,
        },
        .options = options,
    };

    return self;
}

pub fn deinit(self: *Elf) void {
    for (self.managed_atoms.items) |atom| {
        atom.deinit(self.base.allocator);
        self.base.allocator.destroy(atom);
    }
    self.managed_atoms.deinit(self.base.allocator);
    for (self.globals.keys()) |key| {
        self.base.allocator.free(key);
    }
    self.atom_table.deinit(self.base.allocator);
    self.got_entries_map.deinit(self.base.allocator);
    self.unresolved.deinit(self.base.allocator);
    self.globals.deinit(self.base.allocator);
    self.locals.deinit(self.base.allocator);
    self.shstrtab.deinit(self.base.allocator);
    self.strtab.deinit(self.base.allocator);
    self.phdrs.deinit(self.base.allocator);
    self.sections.deinit(self.base.allocator);
    for (self.objects.items) |*object| {
        object.deinit(self.base.allocator);
    }
    self.objects.deinit(self.base.allocator);
    for (self.archives.items) |*archive| {
        archive.deinit(self.base.allocator);
    }
    self.archives.deinit(self.base.allocator);
}

pub fn closeFiles(self: *const Elf) void {
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
    for (self.options.lib_dirs) |dir| {
        // Verify that search path actually exists
        var tmp = fs.cwd().openDir(dir, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        defer tmp.close();

        try lib_dirs.append(dir);
    }

    var libs = std.StringArrayHashMap(Zld.SystemLib).init(arena);
    var lib_not_found = false;
    for (self.options.libs.keys()) |lib_name| {
        for (&[_][]const u8{ ".dylib", ".a" }) |ext| {
            if (try resolveLib(arena, lib_dirs.items, lib_name, ext)) |full_path| {
                try libs.put(full_path, self.options.libs.get(lib_name).?);
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

    var positionals = std.ArrayList([]const u8).init(arena);
    try positionals.ensureTotalCapacity(self.options.positionals.len);
    for (self.options.positionals) |obj| {
        positionals.appendAssumeCapacity(obj.path);
    }

    try self.parsePositionals(positionals.items);
    try self.parseLibs(libs.keys());

    for (self.objects.items) |_, object_id| {
        try self.resolveSymbolsInObject(@intCast(u16, object_id));
    }
    try self.resolveSymbolsInArchives();
    try self.resolveSpecialSymbols();

    for (self.unresolved.keys()) |ndx| {
        const global = self.globals.values()[ndx];
        const object = self.objects.items[global.file.?];
        const sym_name = self.getSymbolName(global);
        log.err("undefined reference to symbol '{s}'", .{sym_name});
        log.err("  first referenced in '{s}'", .{object.name});
    }
    if (self.unresolved.count() > 0) {
        return error.UndefinedSymbolReference;
    }

    for (self.objects.items) |*object| {
        try object.scanInputSections(self);
    }

    for (self.objects.items) |*object, object_id| {
        try object.splitIntoAtoms(self.base.allocator, @intCast(u16, object_id), self);
    }

    if (self.options.gc_sections) {
        try gc.gcAtoms(self);
    }

    try self.setStackSize();
    try self.allocateLoadRSeg();
    try self.allocateLoadRESeg();
    try self.allocateLoadRWSeg();
    try self.allocateNonAllocSections();
    try self.allocateAtoms();
    try self.setEntryPoint();

    {
        // TODO this should be put in its own logic but probably is linked to
        // C++ handling so leaving it here until I gather more knowledge on
        // those special symbols.
        if (self.getSectionByName(".init_array") == null) {
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
        if (self.getSectionByName(".fini_array") == null) {
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

    if (build_options.enable_logging) {
        self.logSymtab();
        self.logSections();
        self.logAtoms();
    }

    try self.writeAtoms();
    try self.writePhdrs();
    try self.writeSymtab();
    try self.writeStrtab();
    try self.writeShStrtab();
    try self.writeShdrs();
    try self.writeHeader();
}

fn populateMetadata(self: *Elf) !void {
    const gpa = self.base.allocator;
    if (self.header == null) {
        var header = elf.Elf64_Ehdr{
            .e_ident = undefined,
            .e_type = switch (self.options.output_mode) {
                .exe => elf.ET.EXEC,
                .lib => elf.ET.DYN,
            },
            .e_machine = self.options.target.cpu_arch.?.toElfMachine(),
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
        try self.phdrs.append(gpa, .{
            .p_type = elf.PT_PHDR,
            .p_flags = elf.PF_R,
            .p_offset = offset,
            .p_vaddr = offset + default_base_addr,
            .p_paddr = offset + default_base_addr,
            .p_filesz = size,
            .p_memsz = size,
            .p_align = @alignOf(elf.Elf64_Phdr),
        });
    }
    if (self.load_r_seg_index == null) {
        self.load_r_seg_index = @intCast(u16, self.phdrs.items.len);
        try self.phdrs.append(gpa, .{
            .p_type = elf.PT_LOAD,
            .p_flags = elf.PF_R,
            .p_offset = 0,
            .p_vaddr = default_base_addr,
            .p_paddr = default_base_addr,
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
        try self.phdrs.append(gpa, .{
            .p_type = elf.PT_LOAD,
            .p_flags = elf.PF_R | elf.PF_X,
            .p_offset = 0,
            .p_vaddr = default_base_addr,
            .p_paddr = default_base_addr,
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
        try self.phdrs.append(gpa, .{
            .p_type = elf.PT_LOAD,
            .p_flags = elf.PF_R | elf.PF_W,
            .p_offset = 0,
            .p_vaddr = default_base_addr,
            .p_paddr = default_base_addr,
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
    {
        _ = try self.insertSection(.{
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
        }, "");
    }
    // TODO remove this once GC is done prior to creating synthetic sections
    if (self.got_sect_index == null) {
        self.got_sect_index = try self.insertSection(.{
            .sh_name = 0,
            .sh_type = elf.SHT_PROGBITS,
            .sh_flags = elf.SHF_WRITE | elf.SHF_ALLOC,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = 0,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = @alignOf(u64),
            .sh_entsize = 0,
        }, ".got");
    }
    if (self.symtab_sect_index == null) {
        self.symtab_sect_index = try self.insertSection(.{
            .sh_name = 0,
            .sh_type = elf.SHT_SYMTAB,
            .sh_flags = 0,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = 0,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = @alignOf(elf.Elf64_Sym),
            .sh_entsize = @sizeOf(elf.Elf64_Sym),
        }, ".symtab");
    }
    if (self.strtab_sect_index == null) {
        try self.strtab.buffer.append(gpa, 0);
        self.strtab_sect_index = try self.insertSection(.{
            .sh_name = 0,
            .sh_type = elf.SHT_STRTAB,
            .sh_flags = 0,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = 0,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = 1,
            .sh_entsize = 0,
        }, ".strtab");
    }
    if (self.shstrtab_sect_index == null) {
        try self.shstrtab.buffer.append(gpa, 0);
        self.shstrtab_sect_index = try self.insertSection(.{
            .sh_name = 0,
            .sh_type = elf.SHT_STRTAB,
            .sh_flags = 0,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = 0,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = 1,
            .sh_entsize = 0,
        }, ".shstrtab");
    }
}

fn getSectionPrecedence(shdr: elf.Elf64_Shdr, shdr_name: []const u8) u4 {
    const flags = shdr.sh_flags;
    switch (shdr.sh_type) {
        elf.SHT_NULL => return 0,
        elf.SHT_PREINIT_ARRAY,
        elf.SHT_INIT_ARRAY,
        elf.SHT_FINI_ARRAY,
        => return 2,
        elf.SHT_PROGBITS => if (flags & elf.SHF_ALLOC != 0) {
            if (flags & elf.SHF_EXECINSTR != 0) {
                return 2;
            } else if (flags & elf.SHF_WRITE != 0) {
                return if (flags & elf.SHF_TLS != 0) 3 else 5;
            } else {
                return 1;
            }
        } else {
            if (mem.startsWith(u8, shdr_name, ".debug")) {
                return 7;
            } else {
                return 8;
            }
        },
        elf.SHT_NOBITS => return if (flags & elf.SHF_TLS != 0) 4 else 6,
        elf.SHT_SYMTAB => return 0xa,
        elf.SHT_STRTAB => return 0xb,
        else => return 0xf,
    }
}

fn insertSection(self: *Elf, shdr: elf.Elf64_Shdr, shdr_name: []const u8) !u16 {
    const precedence = getSectionPrecedence(shdr, shdr_name);
    // Actually, the order doesn't really matter as long as the sections are correctly
    // allocated within each respective segment. Of course, it is good practice to have
    // the sections sorted, but it's a useful hack we can use for the debug builds in
    // self-hosted Zig compiler.
    const insertion_index = for (self.sections.items(.shdr)) |oshdr, i| {
        const oshdr_name = self.shstrtab.getAssumeExists(oshdr.sh_name);
        if (getSectionPrecedence(oshdr, oshdr_name) > precedence) break @intCast(u16, i);
    } else @intCast(u16, self.sections.items(.shdr).len);
    log.debug("inserting section '{s}' at index {d}", .{
        shdr_name,
        insertion_index,
    });
    for (&[_]*?u16{
        &self.text_sect_index,
        &self.got_sect_index,
        &self.symtab_sect_index,
        &self.strtab_sect_index,
        &self.shstrtab_sect_index,
    }) |maybe_index| {
        const index = maybe_index.* orelse continue;
        if (insertion_index <= index) maybe_index.* = index + 1;
    }
    try self.sections.insert(self.base.allocator, insertion_index, .{
        .shdr = .{
            .sh_name = try self.shstrtab.insert(self.base.allocator, shdr_name),
            .sh_type = shdr.sh_type,
            .sh_flags = shdr.sh_flags,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = 0,
            .sh_link = 0,
            .sh_info = shdr.sh_info,
            .sh_addralign = shdr.sh_addralign,
            .sh_entsize = shdr.sh_entsize,
        },
        .last_atom = null,
    });
    return insertion_index;
}

pub fn getOutputSection(self: *Elf, shdr: elf.Elf64_Shdr, shdr_name: []const u8) !?u16 {
    const flags = shdr.sh_flags;
    const res: ?u16 = blk: {
        if (flags & elf.SHF_EXCLUDE != 0) break :blk null;
        const out_name: []const u8 = name: {
            switch (shdr.sh_type) {
                elf.SHT_NULL => break :blk 0,
                elf.SHT_PROGBITS => {
                    if (flags & elf.SHF_ALLOC == 0) break :name shdr_name;
                    if (flags & elf.SHF_EXECINSTR != 0) {
                        if (mem.startsWith(u8, shdr_name, ".init")) {
                            break :name ".init";
                        } else if (mem.startsWith(u8, shdr_name, ".fini")) {
                            break :name ".fini";
                        } else if (mem.startsWith(u8, shdr_name, ".init_array")) {
                            break :name ".init_array";
                        } else if (mem.startsWith(u8, shdr_name, ".fini_array")) {
                            break :name ".fini_array";
                        } else {
                            break :name ".text";
                        }
                    }
                    if (flags & elf.SHF_WRITE != 0) {
                        if (flags & elf.SHF_TLS != 0) {
                            if (self.tls_seg_index == null) {
                                self.tls_seg_index = @intCast(u16, self.phdrs.items.len);
                                try self.phdrs.append(self.base.allocator, .{
                                    .p_type = elf.PT_TLS,
                                    .p_flags = elf.PF_R,
                                    .p_offset = 0,
                                    .p_vaddr = default_base_addr,
                                    .p_paddr = default_base_addr,
                                    .p_filesz = 0,
                                    .p_memsz = 0,
                                    .p_align = 0,
                                });
                            }
                            break :name ".tdata";
                        } else if (mem.startsWith(u8, shdr_name, ".data.rel.ro")) {
                            break :name ".data.rel.ro";
                        } else {
                            break :name ".data";
                        }
                    }
                    break :name ".rodata";
                },
                elf.SHT_NOBITS => {
                    if (flags & elf.SHF_TLS != 0) {
                        if (self.tls_seg_index == null) {
                            self.tls_seg_index = @intCast(u16, self.phdrs.items.len);
                            try self.phdrs.append(self.base.allocator, .{
                                .p_type = elf.PT_TLS,
                                .p_flags = elf.PF_R,
                                .p_offset = 0,
                                .p_vaddr = default_base_addr,
                                .p_paddr = default_base_addr,
                                .p_filesz = 0,
                                .p_memsz = 0,
                                .p_align = 0,
                            });
                        }
                        break :name ".tbss";
                    } else {
                        break :name ".bss";
                    }
                },
                else => break :name shdr_name,
            }
        };
        const res = self.getSectionByName(out_name) orelse try self.insertSection(shdr, out_name);
        if (mem.eql(u8, out_name, ".text")) {
            if (self.text_sect_index == null) {
                self.text_sect_index = res;
            }
        }
        break :blk res;
    };
    return res;
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
    const gpa = self.base.allocator;
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    defer file.close();

    const name = try gpa.dupe(u8, path);
    const cpu_arch = self.options.target.cpu_arch.?;
    const file_stat = try file.stat();
    const file_size = math.cast(usize, file_stat.size) orelse return error.Overflow;
    const data = try file.readToEndAllocOptions(gpa, file_size, file_size, @alignOf(u64), null);

    var object = Object{
        .name = name,
        .data = data,
    };

    object.parse(gpa, cpu_arch) catch |err| switch (err) {
        error.EndOfStream, error.NotObject => {
            object.deinit(self.base.allocator);
            return false;
        },
        else => |e| return e,
    };

    try self.objects.append(gpa, object);

    return true;
}

fn parseArchive(self: *Elf, path: []const u8) !bool {
    const gpa = self.base.allocator;
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    errdefer file.close();

    const name = try gpa.dupe(u8, path);
    const reader = file.reader();

    var archive = Archive{
        .name = name,
        .file = file,
    };

    archive.parse(gpa, reader) catch |err| switch (err) {
        error.EndOfStream, error.NotArchive => {
            archive.deinit(gpa);
            return false;
        },
        else => |e| return e,
    };

    try self.archives.append(gpa, archive);

    return true;
}

fn resolveSymbolsInObject(self: *Elf, object_id: u16) !void {
    const object = self.objects.items[object_id];

    log.debug("resolving symbols in {s}", .{object.name});

    for (object.symtab.items) |sym, i| {
        const sym_id = @intCast(u32, i);
        const sym_name = self.getSymbolName(.{ .sym_index = sym_id, .file = object_id });
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
        const sym_name = self.getSymbolName(global);

        for (self.archives.items) |archive| {
            // Check if the entry exists in a static archive.
            const offsets = archive.toc.get(sym_name) orelse {
                // No hit.
                continue;
            };
            assert(offsets.items.len > 0);

            const object_id = @intCast(u16, self.objects.items.len);
            const object = try archive.parseObject(
                self.base.allocator,
                self.options.target.cpu_arch.?,
                offsets.items[0],
            );
            try self.objects.append(self.base.allocator, object);
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
        const sym_name = self.getSymbolName(global.*);

        if (mem.eql(u8, sym_name, "__init_array_start") or
            mem.eql(u8, sym_name, "__init_array_end") or
            mem.eql(u8, sym_name, "__fini_array_start") or
            mem.eql(u8, sym_name, "__fini_array_end") or
            mem.eql(u8, sym_name, "_DYNAMIC"))
        {
            const local: elf.Elf64_Sym = if (mem.eql(u8, sym_name, "_DYNAMIC")) .{
                .st_name = try self.strtab.insert(self.base.allocator, sym_name),
                .st_info = elf.STB_WEAK << 4,
                .st_other = 0,
                .st_shndx = 0,
                .st_value = 0,
                .st_size = 0,
            } else .{
                .st_name = try self.strtab.insert(self.base.allocator, sym_name),
                .st_info = 0,
                .st_other = 0,
                .st_shndx = 1, // TODO should this be hardcoded?
                .st_value = 0,
                .st_size = 0,
            };
            const sym_index = @intCast(u32, self.locals.items.len);
            try self.locals.append(self.base.allocator, local);
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
    if (self.got_sect_index == null) {
        self.got_sect_index = try self.insertSection(.{
            .sh_name = 0,
            .sh_type = elf.SHT_PROGBITS,
            .sh_flags = elf.SHF_WRITE | elf.SHF_ALLOC,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = 0,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = @alignOf(u64),
            .sh_entsize = 0,
        }, ".got");
    }

    log.debug("creating GOT atom for target {}", .{target});

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

    const tsym_name = self.getSymbolName(target);
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
        .st_name = try self.strtab.insert(self.base.allocator, tmp_name),
        .st_info = (elf.STB_LOCAL << 4) | elf.STT_OBJECT,
        .st_other = 1,
        .st_shndx = 0,
        .st_value = 0,
        .st_size = @sizeOf(u64),
    });
    atom.sym_index = sym_index;

    try self.atom_table.putNoClobber(self.base.allocator, atom.sym_index, atom);
    try self.addAtomToSection(atom, self.got_sect_index.?);

    return atom;
}

pub fn addAtomToSection(self: *Elf, atom: *Atom, sect_id: u16) !void {
    const sym = atom.getSymbolPtr(self);
    sym.st_shndx = sect_id;
    var section = self.sections.get(sect_id);
    if (section.shdr.sh_size > 0) {
        section.last_atom.?.next = atom;
        atom.prev = section.last_atom.?;
    }
    section.last_atom = atom;
    const aligned_end_addr = mem.alignForwardGeneric(u64, section.shdr.sh_size, atom.alignment);
    const padding = aligned_end_addr - section.shdr.sh_size;
    section.shdr.sh_size += padding + atom.size;
    section.shdr.sh_addralign = @max(section.shdr.sh_addralign, atom.alignment);
    self.sections.set(sect_id, section);
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
            self.shstrtab.getAssumeExists(shdr.sh_name),
            shdr.sh_addr,
            shdr.sh_addr + shdr.sh_size,
        });
    } else {
        log.debug("allocating section '{s}' from 0x{x} to 0x{x} (0x{x} - 0x{x})", .{
            self.shstrtab.getAssumeExists(shdr.sh_name),
            shdr.sh_addr,
            shdr.sh_addr + shdr.sh_size,
            shdr.sh_offset,
            shdr.sh_offset + shdr.sh_size,
        });
        phdr.p_filesz += p_filesz;
    }

    phdr.p_memsz += p_memsz;
}

const SegmentBase = struct {
    offset: u64,
    vaddr: u64,
    init_size: u64 = 0,
    alignment: ?u32 = null,
};

fn allocateSegment(self: *Elf, phdr_ndx: u16, shdr_ndxs: []const ?u16, base: SegmentBase) !void {
    const phdr = &self.phdrs.items[phdr_ndx];

    var min_align: u64 = 0;
    for (shdr_ndxs) |maybe_shdr_ndx| {
        const shdr_ndx = maybe_shdr_ndx orelse continue;
        const shdr = self.sections.items(.shdr)[shdr_ndx];
        min_align = @max(min_align, shdr.sh_addralign);
    }

    const p_align = base.alignment orelse min_align;
    const p_offset = mem.alignForwardGeneric(u64, base.offset, min_align);
    const p_vaddr = mem.alignForwardGeneric(u64, base.vaddr, p_align) + @rem(p_offset, p_align);

    phdr.p_offset = p_offset;
    phdr.p_vaddr = p_vaddr;
    phdr.p_paddr = p_vaddr;
    phdr.p_filesz = base.init_size;
    phdr.p_memsz = base.init_size;
    phdr.p_align = p_align;

    // This assumes ordering of section headers matches ordering of sections in file
    // so that the segments are contiguous in memory.
    for (shdr_ndxs) |maybe_shdr_ndx| {
        const shdr_ndx = maybe_shdr_ndx orelse continue;
        const shdr = &self.sections.items(.shdr)[shdr_ndx];
        try self.allocateSection(shdr, phdr);
    }

    log.debug("allocating segment of type {x} and flags {x}:", .{ phdr.p_type, phdr.p_flags });
    log.debug("  in file from 0x{x} to 0x{x}", .{ phdr.p_offset, phdr.p_offset + phdr.p_filesz });
    log.debug("  in memory from 0x{x} to 0x{x}", .{ phdr.p_vaddr, phdr.p_vaddr + phdr.p_memsz });
}

fn allocateLoadRSeg(self: *Elf) !void {
    const init_size = @sizeOf(elf.Elf64_Ehdr) + self.phdrs.items.len * @sizeOf(elf.Elf64_Phdr);
    try self.allocateSegment(self.load_r_seg_index.?, &.{
        self.getSectionByName(".rodata"),
    }, .{
        .offset = 0,
        .vaddr = default_base_addr,
        .init_size = init_size,
        .alignment = 0x1000,
    });
}

fn allocateLoadRESeg(self: *Elf) !void {
    const prev_seg = self.phdrs.items[self.load_r_seg_index.?];
    try self.allocateSegment(self.load_re_seg_index.?, &.{
        self.getSectionByName(".text"),
        self.getSectionByName(".init"),
        self.getSectionByName(".init_array"),
        self.getSectionByName(".fini"),
        self.getSectionByName(".fini_array"),
    }, .{
        .offset = prev_seg.p_offset + prev_seg.p_filesz,
        .vaddr = prev_seg.p_vaddr + prev_seg.p_memsz,
        .alignment = 0x1000,
    });

    if (self.tls_seg_index) |tls_seg_index| blk: {
        if (self.getSectionByName(".tdata")) |_| break :blk; // TLS segment contains tdata section, hence it will be part of RW
        const phdr = self.phdrs.items[self.load_re_seg_index.?];
        try self.allocateSegment(tls_seg_index, &.{
            self.getSectionByName(".tdata"),
            self.getSectionByName(".tbss"),
        }, .{
            .offset = phdr.p_offset + phdr.p_filesz,
            .vaddr = phdr.p_vaddr + phdr.p_memsz,
        });
    }
}

fn allocateLoadRWSeg(self: *Elf) !void {
    const base: SegmentBase = base: {
        if (self.tls_seg_index) |tls_seg_index| blk: {
            if (self.getSectionByName(".tdata")) |_| break :blk;
            const prev_seg = self.phdrs.items[tls_seg_index];
            break :base .{
                .offset = prev_seg.p_offset + prev_seg.p_filesz,
                .vaddr = prev_seg.p_vaddr + prev_seg.p_memsz,
                .alignment = 0x1000,
            };
        }
        const prev_seg = self.phdrs.items[self.load_re_seg_index.?];
        break :base .{
            .offset = prev_seg.p_offset + prev_seg.p_filesz,
            .vaddr = prev_seg.p_vaddr + prev_seg.p_memsz,
            .alignment = 0x1000,
        };
    };
    try self.allocateSegment(self.load_rw_seg_index.?, &.{
        self.getSectionByName(".tdata"),
        self.getSectionByName(".data.rel.ro"),
        self.getSectionByName(".got"),
        self.getSectionByName(".data"),
        self.getSectionByName(".bss"),
    }, base);

    const phdr = self.phdrs.items[self.load_rw_seg_index.?];

    if (self.getSectionByName(".tdata")) |_| {
        try self.allocateSegment(self.tls_seg_index.?, &.{
            self.getSectionByName(".tdata"),
            self.getSectionByName(".tbss"),
        }, .{
            .offset = phdr.p_offset,
            .vaddr = phdr.p_vaddr,
        });
    }
}

fn allocateNonAllocSections(self: *Elf) !void {
    var offset: u64 = 0;
    for (self.sections.items(.shdr)) |*shdr| {
        defer {
            offset = shdr.sh_offset + shdr.sh_size;
        }

        if (shdr.sh_type == elf.SHT_NULL) continue;
        if (shdr.sh_flags & elf.SHF_ALLOC != 0) continue;

        shdr.sh_offset = mem.alignForwardGeneric(u64, offset, shdr.sh_addralign);
        log.debug("setting '{s}' non-alloc section's offsets from 0x{x} to 0x{x}", .{
            self.shstrtab.getAssumeExists(shdr.sh_name),
            shdr.sh_offset,
            shdr.sh_offset + shdr.sh_size,
        });
    }
}

fn allocateAtoms(self: *Elf) !void {
    const slice = self.sections.slice();
    for (slice.items(.last_atom)) |last_atom, i| {
        var atom = last_atom orelse continue;
        const shdr_ndx = @intCast(u16, i);
        const shdr = slice.items(.shdr)[shdr_ndx];

        // Find the first atom
        while (atom.prev) |prev| {
            atom = prev;
        }

        log.debug("allocating atoms in '{s}' section", .{self.shstrtab.getAssumeExists(shdr.sh_name)});

        var base_addr: u64 = shdr.sh_addr;
        while (true) {
            base_addr = mem.alignForwardGeneric(u64, base_addr, atom.alignment);

            const sym = atom.getSymbolPtr(self);
            sym.st_value = base_addr;
            sym.st_shndx = shdr_ndx;
            sym.st_size = atom.size;

            log.debug("  atom '{s}' allocated from 0x{x} to 0x{x}", .{
                atom.getName(self),
                base_addr,
                base_addr + atom.size,
            });

            // Update each symbol contained within the TextBlock
            for (atom.contained.items) |sym_at_off| {
                const contained_sym = self.getSymbolPtr(.{
                    .sym_index = sym_at_off.sym_index,
                    .file = atom.file,
                });
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

pub fn logAtom(self: *Elf, atom: *const Atom, comptime logger: anytype) void {
    const sym = atom.getSymbol(self);
    const sym_name = atom.getName(self);
    logger.debug("  ATOM(%{d}, '{s}') @ {x} (sizeof({x}), alignof({x})) in object({?}) in sect({d})", .{
        atom.sym_index,
        sym_name,
        sym.st_value,
        sym.st_size,
        atom.alignment,
        atom.file,
        sym.st_shndx,
    });

    for (atom.contained.items) |sym_off| {
        const inner_sym = self.getSymbol(.{
            .sym_index = sym_off.sym_index,
            .file = atom.file,
        });
        const inner_sym_name = self.getSymbolName(.{
            .sym_index = sym_off.sym_index,
            .file = atom.file,
        });
        logger.debug("    (%{d}, '{s}') @ {x} ({x})", .{
            sym_off.sym_index,
            inner_sym_name,
            inner_sym.st_value,
            sym_off.offset,
        });
    }
}

fn logAtoms(self: *Elf) void {
    const slice = self.sections.slice();
    for (slice.items(.last_atom)) |last_atom, i| {
        var atom = last_atom orelse continue;
        const ndx = @intCast(u16, i);
        const shdr = slice.items(.shdr)[ndx];

        log.debug(">>> {s}", .{self.shstrtab.getAssumeExists(shdr.sh_name)});

        while (atom.prev) |prev| {
            atom = prev;
        }

        while (true) {
            self.logAtom(atom, log);
            if (atom.next) |next| {
                atom = next;
            } else break;
        }
    }
}

fn writeAtoms(self: *Elf) !void {
    const slice = self.sections.slice();
    for (slice.items(.last_atom)) |last_atom, i| {
        var atom = last_atom orelse continue;
        const shdr_ndx = @intCast(u16, i);
        const shdr = slice.items(.shdr)[shdr_ndx];

        // TODO zero prefill .bss and .tbss if have presence in file
        if (shdr.sh_type == elf.SHT_NOBITS) continue;

        // Find the first atom
        while (atom.prev) |prev| {
            atom = prev;
        }

        log.debug("writing atoms in '{s}' section", .{self.shstrtab.getAssumeExists(shdr.sh_name)});

        var buffer = try self.base.allocator.alloc(u8, shdr.sh_size);
        defer self.base.allocator.free(buffer);
        mem.set(u8, buffer, 0);

        while (true) {
            const sym = atom.getSymbol(self);
            try atom.resolveRelocs(self);
            const off = sym.st_value - shdr.sh_addr;

            log.debug("  writing atom '{s}' at offset 0x{x}", .{ atom.getName(self), shdr.sh_offset + off });

            mem.copy(u8, buffer[off..][0..atom.size], atom.code.items);

            if (atom.next) |next| {
                atom = next;
            } else break;
        }

        try self.base.file.pwriteAll(buffer, shdr.sh_offset);
    }
}

fn setEntryPoint(self: *Elf) !void {
    if (self.options.output_mode != .exe) return;
    const global = try self.getEntryPoint();
    const sym = self.getSymbol(global);
    self.header.?.e_entry = sym.st_value;
}

fn setStackSize(self: *Elf) !void {
    const stack_size = self.options.stack_size orelse return;
    const gnu_stack_phdr_index = self.gnu_stack_phdr_index orelse blk: {
        const gnu_stack_phdr_index = @intCast(u16, self.phdrs.items.len);
        try self.phdrs.append(self.base.allocator, .{
            .p_type = elf.PT_GNU_STACK,
            .p_flags = elf.PF_R | elf.PF_W,
            .p_offset = 0,
            .p_vaddr = 0,
            .p_paddr = 0,
            .p_filesz = 0,
            .p_memsz = 0,
            .p_align = 0,
        });
        self.gnu_stack_phdr_index = gnu_stack_phdr_index;
        break :blk gnu_stack_phdr_index;
    };
    const phdr = &self.phdrs.items[gnu_stack_phdr_index];
    phdr.p_memsz = stack_size;
}

fn writeSymtab(self: *Elf) !void {
    const offset: u64 = blk: {
        const shdr = self.sections.items(.shdr)[self.symtab_sect_index.? - 1];
        break :blk shdr.sh_offset + shdr.sh_size;
    };
    const shdr = &self.sections.items(.shdr)[self.symtab_sect_index.?];

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
        for (object.symtab.items) |sym, sym_id| {
            if (sym.st_name == 0) continue;
            const st_bind = sym.st_info >> 4;
            const st_type = sym.st_info & 0xf;
            if (st_bind != elf.STB_LOCAL) continue;
            if (st_type == elf.STT_SECTION) continue;
            if (st_type == elf.STT_NOTYPE) continue;
            if (sym.st_other == @enumToInt(elf.STV.INTERNAL)) continue;
            if (sym.st_other == @enumToInt(elf.STV.HIDDEN)) continue;
            if (sym.st_other == STV_GC) continue;

            const sym_name = object.getSymbolName(@intCast(u32, sym_id));
            var out_sym = sym;
            out_sym.st_name = try self.strtab.insert(self.base.allocator, sym_name);
            try symtab.append(out_sym);
        }
    }

    for (self.locals.items) |sym| {
        const st_bind = sym.st_info >> 4;
        if (st_bind != elf.STB_LOCAL) continue;
        if (sym.st_other == @enumToInt(elf.STV.INTERNAL)) continue;
        if (sym.st_other == @enumToInt(elf.STV.HIDDEN)) continue;
        if (sym.st_other == STV_GC) continue;
        try symtab.append(sym);
    }

    // Denote start of globals
    shdr.sh_info = @intCast(u32, symtab.items.len);
    try symtab.ensureUnusedCapacity(self.globals.count());
    for (self.globals.values()) |global| {
        var sym = self.getSymbol(global);
        assert(sym.st_name > 0);
        if (sym.st_other == STV_GC) continue;
        // TODO refactor
        if (sym.st_info >> 4 == elf.STB_LOCAL) continue;
        const sym_name = self.getSymbolName(global);
        sym.st_name = try self.strtab.insert(self.base.allocator, sym_name);
        symtab.appendAssumeCapacity(sym);
    }

    shdr.sh_offset = mem.alignForwardGeneric(u64, offset, @alignOf(elf.Elf64_Sym));
    shdr.sh_size = symtab.items.len * @sizeOf(elf.Elf64_Sym);
    log.debug("writing '{s}' contents from 0x{x} to 0x{x}", .{
        self.shstrtab.getAssumeExists(shdr.sh_name),
        shdr.sh_offset,
        shdr.sh_offset + shdr.sh_size,
    });
    try self.base.file.pwriteAll(mem.sliceAsBytes(symtab.items), shdr.sh_offset);
}

fn writeStrtab(self: *Elf) !void {
    const offset: u64 = blk: {
        const shdr = self.sections.items(.shdr)[self.strtab_sect_index.? - 1];
        break :blk shdr.sh_offset + shdr.sh_size;
    };
    const buffer = try self.strtab.toOwnedSlice(self.base.allocator);
    defer self.base.allocator.free(buffer);
    const shdr = &self.sections.items(.shdr)[self.strtab_sect_index.?];
    shdr.sh_offset = offset;
    shdr.sh_size = buffer.len;
    log.debug("writing '{s}' contents from 0x{x} to 0x{x}", .{
        self.shstrtab.getAssumeExists(shdr.sh_name),
        shdr.sh_offset,
        shdr.sh_offset + shdr.sh_size,
    });
    try self.base.file.pwriteAll(buffer, shdr.sh_offset);
}

fn writeShStrtab(self: *Elf) !void {
    const offset: u64 = blk: {
        const shdr = self.sections.items(.shdr)[self.shstrtab_sect_index.? - 1];
        break :blk shdr.sh_offset + shdr.sh_size;
    };
    const buffer = try self.shstrtab.toOwnedSlice(self.base.allocator);
    defer self.base.allocator.free(buffer);
    const shdr = &self.sections.items(.shdr)[self.shstrtab_sect_index.?];
    shdr.sh_offset = offset;
    shdr.sh_size = buffer.len;
    log.debug("writing '.shstrtab' contents from 0x{x} to 0x{x}", .{
        shdr.sh_offset,
        shdr.sh_offset + shdr.sh_size,
    });
    try self.base.file.pwriteAll(buffer, shdr.sh_offset);
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
    self.sections.items(.shdr)[self.symtab_sect_index.?].sh_link = self.strtab_sect_index.?;
    const offset: u64 = blk: {
        const shdr = self.sections.items(.shdr)[self.sections.len - 1];
        break :blk shdr.sh_offset + shdr.sh_size;
    };
    const shdrs_size = self.sections.items(.shdr).len * @sizeOf(elf.Elf64_Shdr);
    const e_shoff = mem.alignForwardGeneric(u64, offset, @alignOf(elf.Elf64_Shdr));
    log.debug("writing section headers from 0x{x} to 0x{x}", .{
        e_shoff,
        e_shoff + shdrs_size,
    });
    try self.base.file.pwriteAll(mem.sliceAsBytes(self.sections.items(.shdr)), e_shoff);
    self.header.?.e_shoff = e_shoff;
}

fn writeHeader(self: *Elf) !void {
    self.header.?.e_shstrndx = self.shstrtab_sect_index.?;
    self.header.?.e_phnum = @intCast(u16, self.phdrs.items.len);
    self.header.?.e_shnum = @intCast(u16, self.sections.items(.shdr).len);
    log.debug("writing ELF header {} at 0x{x}", .{ self.header.?, 0 });
    try self.base.file.pwriteAll(mem.asBytes(&self.header.?), 0);
}

pub fn getSectionByName(self: *Elf, name: []const u8) ?u16 {
    for (self.sections.items(.shdr)) |shdr, i| {
        const this_name = self.shstrtab.getAssumeExists(shdr.sh_name);
        if (mem.eql(u8, this_name, name)) return @intCast(u16, i);
    } else return null;
}

/// Returns pointer-to-symbol described by `sym_with_loc` descriptor.
pub fn getSymbolPtr(self: *Elf, sym_with_loc: SymbolWithLoc) *elf.Elf64_Sym {
    if (sym_with_loc.file) |file| {
        const object = &self.objects.items[file];
        return &object.symtab.items[sym_with_loc.sym_index];
    } else {
        return &self.locals.items[sym_with_loc.sym_index];
    }
}

/// Returns symbol described by `sym_with_loc` descriptor.
pub fn getSymbol(self: *Elf, sym_with_loc: SymbolWithLoc) elf.Elf64_Sym {
    return self.getSymbolPtr(sym_with_loc).*;
}

/// Returns name of the symbol described by `sym_with_loc` descriptor.
pub fn getSymbolName(self: *Elf, sym_with_loc: SymbolWithLoc) []const u8 {
    if (sym_with_loc.file) |file| {
        const object = self.objects.items[file];
        return object.getSymbolName(sym_with_loc.sym_index);
    } else {
        const sym = self.locals.items[sym_with_loc.sym_index];
        return self.strtab.getAssumeExists(sym.st_name);
    }
}

/// Returns atom if there is an atom referenced by the symbol described by `sym_with_loc` descriptor.
/// Returns null on failure.
pub fn getAtomForSymbol(self: *Elf, sym_with_loc: SymbolWithLoc) ?*Atom {
    if (sym_with_loc.file) |file| {
        const object = self.objects.items[file];
        return object.getAtomForSymbol(sym_with_loc.sym_index);
    } else {
        return self.atom_table.get(sym_with_loc.sym_index);
    }
}

/// Returns symbol localtion corresponding to the set entry point.
/// Asserts output mode is executable.
pub fn getEntryPoint(self: Elf) error{EntrypointNotFound}!SymbolWithLoc {
    assert(self.options.output_mode == .exe);
    const entry_name = self.options.entry orelse "_start";
    const global = self.globals.get(entry_name) orelse {
        log.err("entrypoint '{s}' not found", .{entry_name});
        return error.EntrypointNotFound;
    };
    return global;
}

fn logSections(self: Elf) void {
    log.debug("sections:", .{});
    for (self.sections.items(.shdr)) |shdr, i| {
        log.debug("  sect({d}): {s} @{x}, sizeof({x})", .{
            i,
            self.shstrtab.getAssumeExists(shdr.sh_name),
            shdr.sh_offset,
            shdr.sh_size,
        });
    }
}

fn logSymtab(self: Elf) void {
    for (self.objects.items) |object| {
        log.debug("locals in {s}", .{object.name});
        for (object.symtab.items) |sym, i| {
            // const st_type = sym.st_info & 0xf;
            const st_bind = sym.st_info >> 4;
            // if (st_bind != elf.STB_LOCAL or st_type != elf.STT_SECTION) continue;
            if (st_bind != elf.STB_LOCAL) continue;
            log.debug("  {d}: {s}: {}", .{ i, object.getSymbolName(@intCast(u32, i)), sym });
        }
    }

    log.debug("globals:", .{});
    for (self.globals.values()) |global| {
        if (global.file) |file| {
            const object = self.objects.items[file];
            const sym = object.symtab.items[global.sym_index];
            log.debug("  {d}: {s}: 0x{x}, {s}", .{
                global.sym_index,
                object.getSymbolName(global.sym_index),
                sym.st_value,
                object.name,
            });
        } else {
            const sym = self.locals.items[global.sym_index];
            log.debug("  {d}: {s}: 0x{x}", .{
                global.sym_index,
                self.strtab.getAssumeExists(sym.st_name),
                sym.st_value,
            });
        }
    }
}
