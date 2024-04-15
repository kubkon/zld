pub fn gcAtoms(elf_file: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    var roots = std.ArrayList(*Atom).init(elf_file.base.allocator);
    defer roots.deinit();
    try collectRoots(&roots, elf_file);
    mark(roots, elf_file);
    prune(elf_file);
}

fn collectRoots(roots: *std.ArrayList(*Atom), elf_file: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    if (elf_file.entry_index) |index| {
        const global = elf_file.getSymbol(index);
        try markSymbol(global, roots, elf_file);
    }

    for (elf_file.objects.items) |index| {
        for (elf_file.getFile(index).?.object.getGlobals()) |global_index| {
            const global = elf_file.getSymbol(global_index);
            if (global.getFile(elf_file)) |file| {
                if (file.getIndex() == index and global.flags.@"export")
                    try markSymbol(global, roots, elf_file);
            }
        }
    }

    for (elf_file.objects.items) |index| {
        const object = elf_file.getFile(index).?.object;

        for (object.atoms.items) |atom_index| {
            const atom = elf_file.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;

            const shdr = atom.getInputShdr(elf_file);
            const name = atom.getName(elf_file);
            const is_gc_root = blk: {
                if (shdr.sh_flags & elf.SHF_GNU_RETAIN != 0) break :blk true;
                if (shdr.sh_type == elf.SHT_NOTE) break :blk true;
                if (shdr.sh_type == elf.SHT_PREINIT_ARRAY) break :blk true;
                if (shdr.sh_type == elf.SHT_INIT_ARRAY) break :blk true;
                if (shdr.sh_type == elf.SHT_FINI_ARRAY) break :blk true;
                if (mem.startsWith(u8, name, ".ctors")) break :blk true;
                if (mem.startsWith(u8, name, ".dtors")) break :blk true;
                if (mem.startsWith(u8, name, ".init")) break :blk true;
                if (mem.startsWith(u8, name, ".fini")) break :blk true;
                if (Elf.isCIdentifier(name)) break :blk true;
                break :blk false;
            };
            if (is_gc_root and markAtom(atom)) try roots.append(atom);
            if (shdr.sh_flags & elf.SHF_ALLOC == 0) atom.flags.visited = true;
        }

        // Mark every atom referenced by CIE as alive.
        for (object.cies.items) |cie| {
            for (cie.getRelocs(elf_file)) |rel| {
                const sym = object.getSymbol(rel.r_sym(), elf_file);
                try markSymbol(sym, roots, elf_file);
            }
        }
    }
}

fn markSymbol(sym: *Symbol, roots: *std.ArrayList(*Atom), elf_file: *Elf) !void {
    if (sym.getMergeSubsection(elf_file)) |msub| {
        msub.alive = true;
        return;
    }
    const atom = sym.getAtom(elf_file) orelse return;
    if (markAtom(atom)) try roots.append(atom);
}

fn markAtom(atom: *Atom) bool {
    const already_visited = atom.flags.visited;
    atom.flags.visited = true;
    return atom.flags.alive and !already_visited;
}

fn markLive(atom: *Atom, elf_file: *Elf) void {
    const tracy = trace(@src());
    defer tracy.end();

    assert(atom.flags.visited);
    atom.flags.alive = true;
    track_live_log.debug("{}marking live atom({d})", .{ track_live_level, atom.atom_index });

    if (build_options.enable_logging)
        track_live_level.incr();

    const object = atom.getObject(elf_file);

    for (atom.getFdes(elf_file)) |fde| {
        for (fde.getRelocs(elf_file)[1..]) |rel| {
            const target_sym = object.getSymbol(rel.r_sym(), elf_file);
            const target_atom = target_sym.getAtom(elf_file) orelse continue;
            if (markAtom(target_atom)) markLive(target_atom, elf_file);
        }
    }

    for (atom.getRelocs(elf_file)) |rel| {
        const target_sym = object.getSymbol(rel.r_sym(), elf_file);
        if (target_sym.getMergeSubsection(elf_file)) |msub| {
            msub.alive = true;
            continue;
        }
        const target_atom = target_sym.getAtom(elf_file) orelse continue;
        if (markAtom(target_atom)) markLive(target_atom, elf_file);
    }
}

fn mark(roots: std.ArrayList(*Atom), elf_file: *Elf) void {
    const tracy = trace(@src());
    defer tracy.end();

    for (roots.items) |root| {
        markLive(root, elf_file);
    }
}

fn prune(elf_file: *Elf) void {
    const tracy = trace(@src());
    defer tracy.end();

    for (elf_file.objects.items) |index| {
        for (elf_file.getFile(index).?.object.atoms.items) |atom_index| {
            const atom = elf_file.getAtom(atom_index) orelse continue;
            if (atom.flags.alive and !atom.flags.visited) {
                atom.flags.alive = false;
                atom.markFdesDead(elf_file);
            }
        }
    }
}

pub fn dumpPrunedAtoms(elf_file: *Elf) !void {
    const stderr = std.io.getStdErr().writer();
    for (elf_file.objects.items) |index| {
        for (elf_file.getFile(index).?.object.atoms.items) |atom_index| {
            const atom = elf_file.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive)
                try stderr.print("ld.zld: removing unused section '{s}' in file '{}'\n", .{
                    atom.getName(elf_file),
                    atom.getObject(elf_file).fmtPath(),
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

const build_options = @import("build_options");
const assert = std.debug.assert;
const elf = std.elf;
const track_live_log = std.log.scoped(.gc_track_live);
const mem = std.mem;
const trace = @import("../tracy.zig").trace;
const std = @import("std");

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");
const Symbol = @import("Symbol.zig");
