const std = @import("std");
const build_options = @import("build_options");
const assert = std.debug.assert;
const elf = std.elf;
const gc_track_live_log = std.log.scoped(.gc_track_live);
const mem = std.mem;

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");
const Symbol = @import("Symbol.zig");

pub fn gcAtoms(elf_file: *Elf) !void {
    var roots = std.ArrayList(*Atom).init(elf_file.base.allocator);
    defer roots.deinit();
    try collectRoots(&roots, elf_file);
    mark(roots, elf_file);
    prune(elf_file);
}

fn collectRoots(roots: *std.ArrayList(*Atom), elf_file: *Elf) !void {
    for (elf_file.objects.items) |index| {
        for (elf_file.getFile(index).?.object.globals.items) |global_index| {
            const global = elf_file.getGlobal(global_index);
            if (global.getFile(elf_file)) |file| {
                if (file.deref().getIndex() == index and global.@"export") {
                    if (global.getAtom(elf_file)) |atom| if (markAtom(atom)) try roots.append(atom);
                }
            }
        }
    }

    for (elf_file.atoms.items[1..]) |*atom| {
        if (!atom.is_alive) continue;

        const shdr = atom.getInputShdr(elf_file);
        const name = atom.getName(elf_file);
        const is_gc_root = blk: {
            if (shdr.sh_flags & elf.SHF_GNU_RETAIN != 0) break :blk true;
            if (shdr.sh_type == elf.SHT_NOTE) break :blk true;
            if (shdr.sh_type == elf.SHT_PREINIT_ARRAY) break :blk true;
            if (shdr.sh_type == elf.SHT_INIT_ARRAY) break :blk true;
            if (shdr.sh_type == elf.SHT_FINI_ARRAY) break :blk true;
            if (mem.startsWith(u8, ".ctors", name)) break :blk true;
            if (mem.startsWith(u8, ".dtors", name)) break :blk true;
            if (mem.startsWith(u8, ".init", name)) break :blk true;
            if (mem.startsWith(u8, ".fini", name)) break :blk true;
            break :blk false;
        };
        if (is_gc_root and markAtom(atom)) {
            try roots.append(atom);
        }

        if (shdr.sh_flags & elf.SHF_ALLOC == 0) {
            atom.is_visited = true;
        }
    }
}

fn markAtom(atom: *Atom) bool {
    const already_visited = atom.is_visited;
    atom.is_visited = true;
    return atom.is_alive and !already_visited;
}

fn markLive(atom: *Atom, elf_file: *Elf) void {
    if (build_options.enable_logging) {
        track_live_level.incr();
    }

    assert(atom.is_visited);
    const object = atom.getObject(elf_file);
    for (atom.getRelocs(elf_file)) |rel| {
        const target_sym = object.getSymbol(rel.r_sym(), elf_file);
        const target_atom = target_sym.getAtom(elf_file) orelse continue;
        target_atom.is_alive = true;

        gc_track_live_log.debug("{}marking live atom({d})\n", .{ track_live_level, target_atom.atom_index });

        if (markAtom(target_atom)) {
            markLive(target_atom, elf_file);
        }
    }
}

fn mark(roots: std.ArrayList(*Atom), elf_file: *Elf) void {
    for (roots.items) |root| {
        gc_track_live_log.debug("root atom({d})\n", .{root.atom_index});
        markLive(root, elf_file);
    }
}

fn prune(elf_file: *Elf) void {
    for (elf_file.atoms.items[1..]) |*atom| {
        if (atom.is_alive and !atom.is_visited) {
            atom.is_alive = false;
        }
    }
}

pub fn dumpPrunedAtoms(elf_file: *Elf) !void {
    const stderr = std.io.getStdErr().writer();
    for (elf_file.atoms.items[1..]) |atom| {
        if (!atom.is_alive) {
            try stderr.print("ld.zld: removing unused section '{s}' in file '{s}'\n", .{
                atom.getName(elf_file),
                atom.getObject(elf_file).name,
            });
        }
    }
}

const Level = struct {
    value: usize = 0,

    fn incr(self: *@This()) void {
        self.value += 1;
    }

    pub fn format(
        self: *const @This(),
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        try writer.writeByteNTimes(' ', self.value);
    }
};

var track_live_level: Level = .{};
