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
const InternalObject = @import("Elf/InternalObject.zig");
const Object = @import("Elf/Object.zig");
pub const Options = @import("Elf/Options.zig");
const StringTable = @import("strtab.zig").StringTable;
const Symbol = @import("Elf/Symbol.zig");
const SyntheticSection = @import("synthetic_section.zig").SyntheticSection;
const ThreadPool = @import("ThreadPool.zig");
const Zld = @import("Zld.zig");

pub const base_tag = Zld.Tag.elf;

base: Zld,
options: Options,
cpu_arch: ?std.Target.Cpu.Arch = null,
shoff: ?u64 = 0,

archives: std.ArrayListUnmanaged(Archive) = .{},
objects: std.ArrayListUnmanaged(Object) = .{},

phdrs: std.ArrayListUnmanaged(elf.Elf64_Phdr) = .{},
sections: std.MultiArrayList(Section) = .{},

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

/// Internal linker state for coordinating symbol resolution and synthetics
internal_object: ?InternalObject = null,
dynamic_index: ?u32 = null,
init_array_start_index: ?u32 = null,
init_array_end_index: ?u32 = null,
fini_array_start_index: ?u32 = null,
fini_array_end_index: ?u32 = null,

entry_index: ?u32 = null,

globals: std.ArrayListUnmanaged(Symbol) = .{},
// TODO convert to context-adapted
globals_table: std.StringHashMapUnmanaged(u32) = .{},

shstrtab: StringTable(.shstrtab) = .{},
strtab: StringTable(.strtab) = .{},

got_section: SyntheticSection(u32, *Elf, .{
    .log_scope = .got_section,
    .entry_size = @sizeOf(u64),
    .baseAddrFn = Elf.getGotBaseAddress,
    .writeFn = Elf.writeGotEntry,
}) = .{},

atoms: std.ArrayListUnmanaged(Atom) = .{},

const wip_dump_state = true;

const Section = struct {
    shdr: elf.Elf64_Shdr,
    phdr: ?u16,
    first_atom: ?Atom.Index,
    last_atom: ?Atom.Index,
};

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
    const gpa = self.base.allocator;
    self.shstrtab.deinit(gpa);
    self.strtab.deinit(gpa);
    self.atoms.deinit(gpa);
    self.globals.deinit(gpa);
    self.got_section.deinit(gpa);
    self.phdrs.deinit(gpa);
    self.sections.deinit(gpa);
    for (self.objects.items) |*object| {
        object.deinit(gpa);
    }
    self.objects.deinit(gpa);
    for (self.archives.items) |*archive| {
        archive.deinit(gpa);
    }
    self.archives.deinit(gpa);
    if (self.internal_object) |*object| {
        object.deinit(gpa);
    }
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
    const gpa = self.base.allocator;

    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
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

    // Append empty string to strtab and shstrtab.
    try self.strtab.buffer.append(gpa, 0);
    try self.shstrtab.buffer.append(gpa, 0);
    // Append null section.
    _ = try self.addSection(.{ .name = "" });
    // Append null atom.
    try self.atoms.append(gpa, Atom.empty);

    try self.parsePositionals(positionals.items);
    try self.parseLibs(libs.keys());

    self.internal_object = InternalObject{};

    try self.resolveSymbols();

    if (!self.options.allow_multiple_definition) {
        self.checkDuplicates();
    }

    try self.resolveSyntheticSymbols();

    self.checkUndefined();

    // Set the entrypoint if found
    self.entry_index = blk: {
        if (self.options.output_mode != .exe) break :blk null;
        const entry_name = self.options.entry orelse "_start";
        break :blk self.globals_table.get(entry_name) orelse null;
    };

    if (self.options.gc_sections) {
        try gc.gcAtoms(self);
    } else for (self.atoms.items[1..]) |*atom| {
        atom.is_alive = true;
    }

    // TODO this is just a temp until proper functionality is actually added
    for (self.atoms.items[1..]) |*atom| {
        const shdr = atom.getInputShdr(self);
        const name = atom.getName(self);
        const mark_dead = blk: {
            if (shdr.sh_type == 0x70000001) break :blk true; // TODO SHT_X86_64_UNWIND
            if (mem.startsWith(u8, name, ".note")) break :blk true;
            if (mem.startsWith(u8, name, ".comment")) break :blk true;
            if (mem.startsWith(u8, name, ".llvm_addrsig")) break :blk true;
            break :blk false;
        };
        if (mark_dead) atom.is_alive = false;
    }

    try self.scanRelocs();
    try self.initSections();
    try self.calcSectionSizes();
    try self.sortSections();
    try self.initSegments();
    self.allocateSegments();
    self.allocateAllocSections();
    self.allocateAtoms();
    self.allocateLocals();
    self.allocateGlobals();
    self.allocateSyntheticSymbols();
    // try self.setStackSize();

    if (wip_dump_state) {
        std.debug.print("{}", .{self.dumpState()});
    }

    return error.Todo;

    // try self.setSyntheticSections();
    // try self.allocateLoadRSeg();
    // try self.allocateLoadRESeg();
    // try self.allocateLoadRWSeg();
    // try self.allocateNonAllocSections();
    // try self.allocateAtoms();

    // {
    //     // TODO this should be put in its own logic but probably is linked to
    //     // C++ handling so leaving it here until I gather more knowledge on
    //     // those special symbols.
    //     if (self.getSectionByName(".init_array") == null) {
    //         if (self.globals.get("__init_array_start")) |global| {
    //             assert(global.file == null);
    //             const sym = &self.locals.items[global.sym_index];
    //             sym.st_value = self.entry.?;
    //             sym.st_shndx = self.text_sect_index.?;
    //         }
    //         if (self.globals.get("__init_array_end")) |global| {
    //             assert(global.file == null);
    //             const sym = &self.locals.items[global.sym_index];
    //             sym.st_value = self.entry.?;
    //             sym.st_shndx = self.text_sect_index.?;
    //         }
    //     }
    //     if (self.getSectionByName(".fini_array") == null) {
    //         if (self.globals.get("__fini_array_start")) |global| {
    //             assert(global.file == null);
    //             const sym = &self.locals.items[global.sym_index];
    //             sym.st_value = self.entry.?;
    //             sym.st_shndx = self.text_sect_index.?;
    //         }
    //         if (self.globals.get("__fini_array_end")) |global| {
    //             assert(global.file == null);
    //             const sym = &self.locals.items[global.sym_index];
    //             sym.st_value = self.entry.?;
    //             sym.st_shndx = self.text_sect_index.?;
    //         }
    //     }
    // }

    // if (build_options.enable_logging) {
    //     self.logObjects();
    //     self.logSymtab();
    //     log.debug("{}", .{self.got_section});
    //     self.logSections();
    //     self.logAtoms();
    // }

    // try self.writeAtoms();
    // try self.writeSyntheticSections();
    // try self.writePhdrs();
    // try self.writeSymtab();
    // try self.writeStrtab();
    // try self.writeShStrtab();
    // try self.writeShdrs();
    // try self.writeHeader();
}

fn initSections(self: *Elf) !void {
    for (self.atoms.items[1..]) |*atom| {
        if (!atom.is_alive) continue;
        try atom.initOutputSection(self);
    }

    if (self.got_section.count() > 0) {
        self.got_sect_index = try self.addSection(.{
            .name = ".got",
            .type = elf.SHT_PROGBITS,
            .flags = elf.SHF_ALLOC | elf.SHF_WRITE,
        });
    }

    self.strtab_sect_index = try self.addSection(.{
        .name = ".shstrtab",
        .type = elf.SHT_STRTAB,
        .entsize = 1,
    });
    self.strtab_sect_index = try self.addSection(.{
        .name = ".strtab",
        .type = elf.SHT_STRTAB,
        .entsize = 1,
    });
    self.symtab_sect_index = try self.addSection(.{
        .name = ".symtab",
        .type = elf.SHT_SYMTAB,
        .link = self.strtab_sect_index.?,
        .addralign = @alignOf(elf.Elf64_Sym),
    });
}

fn calcSectionSizes(self: *Elf) !void {
    var slice = self.sections.slice();
    for (self.atoms.items[1..], 1..) |*atom, atom_index| {
        if (!atom.is_alive) continue;

        var section = slice.get(atom.out_shndx);
        const alignment = try math.powi(u64, 2, atom.alignment);
        const addr = mem.alignForwardGeneric(u64, section.shdr.sh_size, alignment);
        const padding = addr - section.shdr.sh_size;
        atom.value = addr;
        section.shdr.sh_size += padding + atom.size;
        section.shdr.sh_addralign = @max(section.shdr.sh_addralign, alignment);

        if (section.last_atom) |last_atom_index| {
            const last_atom = self.getAtom(last_atom_index).?;
            last_atom.next = @intCast(u32, atom_index);
            atom.prev = last_atom_index;
        } else {
            assert(section.first_atom == null);
            section.first_atom = @intCast(u32, atom_index);
        }
        section.last_atom = @intCast(u32, atom_index);

        slice.set(atom.out_shndx, section);
    }

    if (self.got_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.got_section.size();
        shdr.sh_addralign = @sizeOf(u64);
    }
}

fn getSectionPrecedence(self: *Elf, shdr: elf.Elf64_Shdr) u4 {
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
            const name = self.shstrtab.getAssumeExists(shdr.sh_name);
            if (mem.startsWith(u8, name, ".debug")) {
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

fn sortSections(self: *Elf) !void {
    const Entry = struct {
        shndx: u16,

        pub fn get(this: @This(), elf_file: *Elf) elf.Elf64_Shdr {
            return elf_file.sections.items(.shdr)[this.shndx];
        }

        pub fn lessThan(elf_file: *Elf, lhs: @This(), rhs: @This()) bool {
            return elf_file.getSectionPrecedence(lhs.get(elf_file)) < elf_file.getSectionPrecedence(rhs.get(elf_file));
        }
    };

    const gpa = self.base.allocator;

    var entries = try std.ArrayList(Entry).initCapacity(gpa, self.sections.slice().len);
    defer entries.deinit();
    for (0..self.sections.slice().len) |shndx| {
        entries.appendAssumeCapacity(.{ .shndx = @intCast(u16, shndx) });
    }

    std.sort.sort(Entry, entries.items, self, Entry.lessThan);

    const backlinks = try gpa.alloc(u16, entries.items.len);
    defer gpa.free(backlinks);
    for (entries.items, 0..) |entry, i| {
        backlinks[entry.shndx] = @intCast(u16, i);
    }

    var slice = self.sections.toOwnedSlice();
    defer slice.deinit(gpa);

    try self.sections.ensureTotalCapacity(gpa, slice.len);
    for (entries.items) |sorted| {
        self.sections.appendAssumeCapacity(slice.get(sorted.shndx));
    }

    for (&[_]*?u16{
        &self.text_sect_index,
        &self.got_sect_index,
        &self.symtab_sect_index,
        &self.strtab_sect_index,
        &self.shstrtab_sect_index,
    }) |maybe_index| {
        if (maybe_index.*) |*index| {
            index.* = backlinks[index.*];
        }
    }
}

fn initSegments(self: *Elf) !void {
    // We preallocate space for PHDR segment
    self.phdr_seg_index = try self.addSegment(.{
        .type = elf.PT_PHDR,
        .flags = elf.PF_R,
        .@"align" = @alignOf(elf.Elf64_Phdr),
    });

    // Then, we proceed in creating segments for all alloc sections.
    // Note that the sections are now sorted in the most optimal order meaning we expect
    // one of each segment. This of course isn't enforced by the loader, so if we decide
    // to tackle this differently, we need to tweak this logic.
    for (self.sections.items(.shdr), 0..) |shdr, i| {
        const phdr = &self.sections.items(.phdr)[i];
        if (shdr.sh_flags & elf.SHF_ALLOC == 0) continue;
        const write = shdr.sh_flags & elf.SHF_WRITE != 0;
        const exec = shdr.sh_flags & elf.SHF_EXECINSTR != 0;
        if (write and exec) {
            log.err("TODO executable segment is writeable", .{});
            return error.ExecWrite;
        }
        phdr.* = blk: {
            if (exec) {
                const phdr_index = self.load_re_seg_index orelse try self.addSegment(.{
                    .type = elf.PT_LOAD,
                    .flags = elf.PF_X | elf.PF_R,
                    .@"align" = 0x1000,
                });
                self.load_re_seg_index = phdr_index;
                break :blk phdr_index;
            }
            if (write) {
                const phdr_index = self.load_rw_seg_index orelse try self.addSegment(.{
                    .type = elf.PT_LOAD,
                    .flags = elf.PF_W | elf.PF_R,
                    .@"align" = 0x1000,
                });
                self.load_rw_seg_index = phdr_index;
                break :blk phdr_index;
            }
            const phdr_index = self.load_r_seg_index orelse try self.addSegment(.{
                .type = elf.PT_LOAD,
                .flags = elf.PF_R,
                .@"align" = 0x1000,
            });
            self.load_r_seg_index = phdr_index;
            break :blk phdr_index;
        };
    }
}

fn allocateSegments(self: *Elf) void {
    var offset: u64 = 0;
    var vaddr: u64 = default_base_addr;
    // Now that we have initialized segments, we can go ahead and allocate them in memory.
    // We start with the PHDR segment which contains all program headers.
    if (self.phdr_seg_index) |index| {
        const phdr = &self.phdrs.items[index];
        const size = self.phdrs.items.len * @sizeOf(elf.Elf64_Phdr);
        offset += @sizeOf(elf.Elf64_Ehdr);
        vaddr += offset;

        phdr.p_offset = offset;
        phdr.p_vaddr = vaddr;
        phdr.p_paddr = vaddr;
        phdr.p_filesz = size;
        phdr.p_memsz = size;

        offset += size;
        vaddr += size;
    }

    for (self.phdrs.items[1..], 1..) |*phdr, phdr_index| {
        const sect_range = self.getSectionIndexes(@intCast(u16, phdr_index));
        const start = sect_range.start;
        const end = sect_range.end;
        if (start == end) continue;

        var file_align: u64 = 0;
        var filesz: u64 = 0;
        var memsz: u64 = 0;
        for (self.sections.items(.shdr)[start..end]) |shdr| {
            file_align = @max(file_align, shdr.sh_addralign);
            if (shdr.sh_type != elf.SHT_NOBITS) {
                filesz = mem.alignForwardGeneric(u64, filesz, shdr.sh_addralign) + shdr.sh_size;
            }
            memsz = mem.alignForwardGeneric(u64, memsz, shdr.sh_addralign) + shdr.sh_size;
        }

        offset = mem.alignForwardGeneric(u64, offset, file_align);
        vaddr = mem.alignForwardGeneric(u64, vaddr, phdr.p_align) + @rem(offset, phdr.p_align);

        phdr.p_offset = offset;
        phdr.p_vaddr = vaddr;
        phdr.p_paddr = vaddr;
        phdr.p_filesz = filesz;
        phdr.p_memsz = memsz;

        offset += filesz;
        vaddr += memsz;
    }
}

fn allocateAllocSections(self: *Elf) void {
    for (self.phdrs.items[1..], 1..) |phdr, phdr_index| {
        const sect_range = self.getSectionIndexes(@intCast(u16, phdr_index));
        const start = sect_range.start;
        const end = sect_range.end;
        if (start == end) continue;

        var offset = phdr.p_offset;
        var vaddr = phdr.p_vaddr;
        for (self.sections.items(.shdr)[start..end]) |*shdr| {
            offset = mem.alignForwardGeneric(u64, offset, shdr.sh_addralign);
            vaddr = mem.alignForwardGeneric(u64, vaddr, shdr.sh_addralign);

            shdr.sh_offset = offset;
            shdr.sh_addr = vaddr;

            if (shdr.sh_type != elf.SHT_NOBITS) {
                offset += shdr.sh_size;
            }
            vaddr += shdr.sh_size;
        }
    }
}

fn allocateAtoms(self: *Elf) void {
    const slice = self.sections.slice();
    for (slice.items(.shdr), 0..) |shdr, i| {
        var atom_index = slice.items(.first_atom)[i] orelse continue;

        while (true) {
            const atom = self.getAtom(atom_index).?;
            assert(atom.is_alive);
            atom.value += shdr.sh_addr;

            if (atom.next) |next| {
                atom_index = next;
            } else break;
        }
    }
}

fn allocateLocals(self: *Elf) void {
    for (self.objects.items) |*object| {
        for (object.locals.items) |*symbol| {
            const atom = symbol.getAtom(self) orelse continue;
            if (!atom.is_alive) continue;
            symbol.value += atom.value;
            symbol.shndx = atom.out_shndx;
        }
    }
}

fn allocateGlobals(self: *Elf) void {
    for (self.globals.items) |*global| {
        const atom = global.getAtom(self) orelse continue;
        if (!atom.is_alive) continue;
        global.value += atom.value;
        global.shndx = atom.out_shndx;
    }
}

fn allocateSyntheticSymbols(self: *Elf) void {
    if (self.dynamic_index) |index| {
        if (self.got_sect_index) |got_index| {
            const shdr = self.sections.items(.shdr)[got_index];
            self.getGlobal(index).value = shdr.sh_addr;
        }
    }
    if (self.init_array_start_index) |index| {
        const global = self.getGlobal(index);
        if (self.text_sect_index) |text_index| {
            global.shndx = text_index;
        }
        if (self.entry_index) |entry_index| {
            global.value = self.getGlobal(entry_index).value;
        }
    }
    if (self.init_array_end_index) |index| {
        const global = self.getGlobal(index);
        if (self.text_sect_index) |text_index| {
            global.shndx = text_index;
        }
        if (self.entry_index) |entry_index| {
            global.value = self.getGlobal(entry_index).value;
        }
    }
    if (self.fini_array_start_index) |index| {
        const global = self.getGlobal(index);
        if (self.text_sect_index) |text_index| {
            global.shndx = text_index;
        }
        if (self.entry_index) |entry_index| {
            global.value = self.getGlobal(entry_index).value;
        }
    }
    if (self.fini_array_end_index) |index| {
        const global = self.getGlobal(index);
        if (self.text_sect_index) |text_index| {
            global.shndx = text_index;
        }
        if (self.entry_index) |entry_index| {
            global.value = self.getGlobal(entry_index).value;
        }
    }
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
    const file_stat = try file.stat();
    const file_size = math.cast(usize, file_stat.size) orelse return error.Overflow;
    const data = try file.readToEndAlloc(gpa, file_size);

    const candidate = Object{
        .name = name,
        .data = data,
        .object_id = undefined,
    };
    if (!candidate.isValid()) return false;

    const object_id = @intCast(u32, self.objects.items.len);
    const object = try self.objects.addOne(gpa);
    object.* = candidate;
    object.object_id = object_id;
    try object.parse(self);

    if (self.cpu_arch == null) {
        self.cpu_arch = object.header.?.e_machine.toTargetCpuArch().?;
    }
    const cpu_arch = self.cpu_arch.?;
    if (cpu_arch != object.header.?.e_machine.toTargetCpuArch().?) {
        log.err("Invalid architecture {any}, expected {any}", .{
            object.header.?.e_machine,
            cpu_arch.toElfMachine(),
        });
        return error.InvalidCpuArch;
    }

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

fn resolveSymbols(self: *Elf) !void {
    for (self.objects.items) |object| {
        try object.resolveSymbols(self);
    }
    try self.resolveSymbolsInArchives();
}

fn resolveSymbolsInArchives(self: *Elf) !void {
    if (self.archives.items.len == 0) return;

    var next_sym: usize = 0;
    loop: while (next_sym < self.globals.items.len) {
        const global = self.globals.items[next_sym];
        const global_name = global.getName(self);
        if (global.isUndef(self)) for (self.archives.items) |archive| {
            // Check if the entry exists in a static archive.
            const offsets = archive.toc.get(global_name) orelse {
                // No hit.
                continue;
            };
            assert(offsets.items.len > 0);

            const object_id = @intCast(u16, self.objects.items.len);
            const object = try archive.parseObject(offsets.items[0], object_id, self);
            try object.resolveSymbols(self);

            continue :loop;
        };

        next_sym += 1;
    }
}

fn resolveSyntheticSymbols(self: *Elf) !void {
    const object = &(self.internal_object orelse return);
    self.dynamic_index = try object.addSyntheticGlobal("_DYNAMIC", self);
    self.init_array_start_index = try object.addSyntheticGlobal("__init_array_start", self);
    self.init_array_end_index = try object.addSyntheticGlobal("__init_array_end", self);
    self.fini_array_start_index = try object.addSyntheticGlobal("__fini_array_start", self);
    self.fini_array_end_index = try object.addSyntheticGlobal("__fini_array_end", self);
    try object.resolveSymbols(self);
}

fn checkDuplicates(self: *Elf) void {
    for (self.objects.items) |object| {
        object.checkDuplicates(self);
    }
}

fn checkUndefined(self: *Elf) void {
    for (self.objects.items) |object| {
        object.checkUndefined(self);
    }
}

fn scanRelocs(self: *Elf) !void {
    for (self.atoms.items[1..]) |*atom| {
        if (!atom.is_alive) continue;
        try atom.scanRelocs(self);
    }
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

fn writeAtoms(self: *Elf) !void {
    const slice = self.sections.slice();
    for (slice.items(.last_atom), 0..) |last_atom, i| {
        var atom_index = last_atom orelse continue;
        const shdr_ndx = @intCast(u16, i);
        const shdr = slice.items(.shdr)[shdr_ndx];

        // TODO zero prefill .bss and .tbss if have presence in file
        if (shdr.sh_type == elf.SHT_NOBITS) continue;

        // Find the first atom
        while (true) {
            const atom = self.getAtom(atom_index);
            if (atom.prev) |prev| {
                atom_index = prev;
            } else break;
        }

        log.debug("writing atoms in '{s}' section", .{self.shstrtab.getAssumeExists(shdr.sh_name)});

        var buffer = try self.base.allocator.alloc(u8, shdr.sh_size);
        defer self.base.allocator.free(buffer);
        mem.set(u8, buffer, 0);

        var stream = std.io.fixedBufferStream(buffer);

        while (true) {
            const atom = self.getAtom(atom_index);
            const off = atom.value - shdr.sh_addr;
            log.debug("  writing ATOM(%{d},'{s}') at offset 0x{x}", .{
                atom_index,
                atom.getName(self),
                shdr.sh_offset + off,
            });
            try stream.seekTo(off);
            try atom.resolveRelocs(self, stream.writer());

            if (atom.next) |next| {
                atom_index = next;
            } else break;
        }

        try self.base.file.pwriteAll(buffer, shdr.sh_offset);
    }
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

fn writeSyntheticSections(self: *Elf) !void {
    const gpa = self.base.allocator;
    // Currently, we only have .got to worry about.
    if (self.got_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, self.got_section.size());
        defer buffer.deinit();
        try self.got_section.write(self, buffer.writer());
        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
    }
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
        for (object.symtab.items, 0..) |sym, sym_id| {
            if (sym.st_name == 0) continue;
            const st_bind = sym.st_info >> 4;
            const st_type = sym.st_info & 0xf;
            if (st_bind != elf.STB_LOCAL) continue;
            if (st_type == elf.STT_SECTION) continue;
            if (st_type == elf.STT_NOTYPE) continue;
            if (sym.st_other == @enumToInt(elf.STV.INTERNAL)) continue;
            if (sym.st_other == @enumToInt(elf.STV.HIDDEN)) continue;

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
        try symtab.append(sym);
    }

    // Denote start of globals
    shdr.sh_info = @intCast(u32, symtab.items.len);
    try symtab.ensureUnusedCapacity(self.globals.count());
    for (self.globals.values()) |global| {
        var sym = self.getSymbol(global);
        assert(sym.st_name > 0);
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
    const phoff = @sizeOf(elf.Elf64_Ehdr);
    const phdrs_size = self.phdrs.items.len * @sizeOf(elf.Elf64_Phdr);
    log.debug("writing program headers from 0x{x} to 0x{x}", .{ phoff, phoff + phdrs_size });
    try self.base.file.pwriteAll(mem.sliceAsBytes(self.phdrs.items), phoff);
}

fn writeShdrs(self: *Elf) !void {
    self.sections.items(.shdr)[self.symtab_sect_index.?].sh_link = self.strtab_sect_index.?;
    const offset: u64 = blk: {
        const shdr = self.sections.items(.shdr)[self.sections.len - 1];
        break :blk shdr.sh_offset + shdr.sh_size;
    };
    const shdrs_size = self.sections.items(.shdr).len * @sizeOf(elf.Elf64_Shdr);
    const shoff = mem.alignForwardGeneric(u64, offset, @alignOf(elf.Elf64_Shdr));
    log.debug("writing section headers from 0x{x} to 0x{x}", .{ shoff, shoff + shdrs_size });
    try self.base.file.pwriteAll(mem.sliceAsBytes(self.sections.items(.shdr)), shoff);
    self.shoff = shoff;
}

fn writeHeader(self: *Elf) !void {
    var header = elf.Elf64_Ehdr{
        .e_ident = undefined,
        .e_type = switch (self.options.output_mode) {
            .exe => elf.ET.EXEC,
            .lib => elf.ET.DYN,
        },
        .e_machine = self.cpu_arch.?.toElfMachine(),
        .e_version = 1,
        .e_entry = self.entry.?,
        .e_phoff = @sizeOf(elf.Elf64_Ehdr),
        .e_shoff = self.shoff.?,
        .e_flags = 0,
        .e_ehsize = @sizeOf(elf.Elf64_Ehdr),
        .e_phentsize = @sizeOf(elf.Elf64_Phdr),
        .e_phnum = @intCast(u16, self.phdrs.items.len),
        .e_shentsize = @sizeOf(elf.Elf64_Shdr),
        .e_shnum = @intCast(u16, self.sections.items(.shdr).len),
        .e_shstrndx = self.shstrtab_sect_index.?,
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
    log.debug("writing ELF header {} at 0x{x}", .{ header, 0 });
    try self.base.file.pwriteAll(mem.asBytes(&header), 0);
}

pub fn addSection(self: *Elf, opts: struct {
    name: [:0]const u8,
    type: u32 = elf.SHT_NULL,
    flags: u64 = 0,
    link: u32 = 0,
    info: u32 = 0,
    addralign: u64 = 0,
    entsize: u64 = 0,
}) !u16 {
    const gpa = self.base.allocator;
    const index = @intCast(u16, self.sections.slice().len);
    try self.sections.append(gpa, .{
        .shdr = .{
            .sh_name = try self.shstrtab.insert(gpa, opts.name),
            .sh_type = opts.type,
            .sh_flags = opts.flags,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = 0,
            .sh_link = 0,
            .sh_info = opts.info,
            .sh_addralign = opts.addralign,
            .sh_entsize = opts.entsize,
        },
        .phdr = null,
        .first_atom = null,
        .last_atom = null,
    });
    return index;
}

pub fn getSectionByName(self: *Elf, name: [:0]const u8) ?u16 {
    for (self.sections.items(.shdr), 0..) |shdr, i| {
        const this_name = self.shstrtab.getAssumeExists(shdr.sh_name);
        if (mem.eql(u8, this_name, name)) return @intCast(u16, i);
    } else return null;
}

fn addSegment(self: *Elf, opts: struct {
    type: u32 = 0,
    flags: u32 = 0,
    @"align": u64 = 0,
}) !u16 {
    const index = @intCast(u16, self.phdrs.items.len);
    try self.phdrs.append(self.base.allocator, .{
        .p_type = opts.type,
        .p_flags = opts.flags,
        .p_offset = 0,
        .p_vaddr = 0,
        .p_paddr = 0,
        .p_filesz = 0,
        .p_memsz = 0,
        .p_align = opts.@"align",
    });
    return index;
}

pub fn getSectionIndexes(self: *Elf, phdr_index: u16) struct { start: u16, end: u16 } {
    const start: u16 = for (self.sections.items(.phdr), 0..) |phdr, i| {
        if (phdr != null and phdr.? == phdr_index) break @intCast(u16, i);
    } else @intCast(u16, self.sections.slice().len);
    const end: u16 = for (self.sections.items(.phdr)[start..], 0..) |phdr, i| {
        if (phdr == null or phdr.? != phdr_index) break @intCast(u16, start + i);
    } else start;
    return .{ .start = start, .end = end };
}

fn getGotBaseAddress(self: *Elf) u64 {
    const shndx = self.got_sect_index orelse return 0;
    const shdr = self.sections.items(.shdr)[shndx];
    return shdr.sh_addr;
}

fn writeGotEntry(self: *Elf, entry: u32, writer: anytype) !void {
    if (self.got_sect_index == null) return;
    const sym = self.getGlobal(entry);
    try writer.writeIntLittle(u64, sym.st_value);
}

/// Returns symbol localtion corresponding to the set entry point.
/// Asserts output mode is executable.
pub fn getEntryPoint(self: Elf) ?Symbol {
    assert(self.options.output_mode == .exe);
    const entry_name = self.options.entry orelse "_start";
    return self.globals.get(entry_name) orelse null;
}

pub fn addAtom(self: *Elf) !Atom.Index {
    const index = @intCast(u32, self.atoms.items.len);
    const atom = try self.atoms.addOne(self.base.allocator);
    atom.* = Atom.empty;
    return index;
}

pub fn getAtom(self: Elf, atom_index: Atom.Index) ?*Atom {
    if (atom_index == 0) return null;
    assert(atom_index < self.atoms.items.len);
    return &self.atoms.items[atom_index];
}

const GetOrCreateGlobalResult = struct {
    found_existing: bool,
    index: u32,
};

pub fn getOrCreateGlobal(self: *Elf, name: [:0]const u8) !GetOrCreateGlobalResult {
    const gpa = self.base.allocator;
    const gop = try self.globals_table.getOrPut(gpa, name);
    if (!gop.found_existing) {
        const index = @intCast(u32, self.globals.items.len);
        const global = try self.globals.addOne(gpa);
        global.* = .{ .name = try self.strtab.insert(gpa, name) };
        gop.value_ptr.* = index;
    }
    return .{
        .found_existing = gop.found_existing,
        .index = gop.value_ptr.*,
    };
}

pub fn getGlobal(self: *Elf, index: u32) *Symbol {
    assert(index < self.globals.items.len);
    return &self.globals.items[index];
}

fn fmtSections(self: *Elf) std.fmt.Formatter(formatSections) {
    return .{ .data = self };
}

fn formatSections(
    self: *Elf,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    for (self.sections.items(.shdr), 0..) |shdr, i| {
        try writer.print("sect({d}) : {s} : @{x} ({x}) : align({x}) : size({x})\n", .{
            i,                 self.shstrtab.getAssumeExists(shdr.sh_name), shdr.sh_offset, shdr.sh_addr,
            shdr.sh_addralign, shdr.sh_size,
        });
    }
}

fn fmtSegments(self: *Elf) std.fmt.Formatter(formatSegments) {
    return .{ .data = self };
}

fn formatSegments(
    self: *Elf,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    for (self.phdrs.items, 0..) |phdr, i| {
        const write = phdr.p_flags & elf.PF_W != 0;
        const read = phdr.p_flags & elf.PF_R != 0;
        const exec = phdr.p_flags & elf.PF_X != 0;
        var flags: [3]u8 = [_]u8{'_'} ** 3;
        if (exec) flags[0] = 'X';
        if (write) flags[1] = 'W';
        if (read) flags[2] = 'R';
        try writer.print("phdr({d}) : {s} : @{x} ({x}) : align({x}) : filesz({x}) : memsz({x})\n", .{
            i, flags, phdr.p_offset, phdr.p_vaddr, phdr.p_align, phdr.p_filesz, phdr.p_memsz,
        });
    }
}

fn dumpState(self: *Elf) std.fmt.Formatter(fmtDumpState) {
    return .{ .data = self };
}

fn fmtDumpState(
    self: *Elf,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    for (self.objects.items, 0..) |object, object_id| {
        try writer.print("file({d}) : {s}\n", .{ object_id, object.name });
        try writer.print("{}{}\n", .{ object.fmtAtoms(self), object.fmtSymtab(self) });
    }
    if (self.internal_object) |object| {
        try writer.writeAll("linker-defined\n");
        try writer.print("{}\n", .{object.fmtSymtab(self)});
    }
    try writer.writeAll("GOT\n");
    try writer.print("{}\n", .{self.got_section});
    try writer.writeAll("Output sections\n");
    try writer.print("{}\n", .{self.fmtSections()});
    try writer.writeAll("Output segments\n");
    try writer.print("{}\n", .{self.fmtSegments()});
}
