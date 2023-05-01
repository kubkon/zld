const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const log = std.log.scoped(.elf);
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
    const output_mode = elf_file.options.output_mode;

    switch (output_mode) {
        .exe => {
            if (elf_file.entry_index) |index| {
                const global = elf_file.getGlobal(index);
                const atom = global.getAtom(elf_file).?;
                if (markAtom(atom)) {
                    log.debug("adding as root atom atom({d})", .{atom.atom_index});
                    try roots.append(atom);
                }
            }
        },
        else => |other| {
            assert(other == .lib);
            for (elf_file.globals.items) |global| if (global.getAtom(elf_file)) |atom| {
                if (markAtom(atom)) {
                    log.debug("adding as root atom atom({d})", .{atom.atom_index});
                    try roots.append(atom);
                }
            };
        },
    }

    for (elf_file.atoms.items[1..]) |*atom| {
        if (!atom.is_alive) continue;

        const shdr = atom.getInputShdr(elf_file);
        const name = atom.getName(elf_file);
        const is_gc_root = blk: {
            if (shdr.sh_flags & (1 << 21) != 0) break :blk true;
            // if (shdr.sh_flags & elf.SHF_GNU_RETAIN != 0) break :blk true;
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
            log.debug("adding as root atom({d})", .{atom.atom_index});
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

fn markLive(atom: *Atom, elf_file: *Elf, indent: usize) void {
    assert(atom.is_visited);
    const inn = elf_file.base.allocator.alloc(u8, indent) catch unreachable;
    defer elf_file.base.allocator.free(inn);
    @memset(inn, ' ');
    const object = atom.getObject(elf_file);
    for (atom.getRelocs(elf_file)) |rel| {
        const target_sym = object.getSymbol(rel.r_sym(), elf_file);
        const target_atom = target_sym.getAtom(elf_file) orelse continue;
        target_atom.is_alive = true;
        log.debug("{s}marking live atom({d})", .{ inn, target_atom.atom_index });
        if (markAtom(target_atom)) {
            markLive(target_atom, elf_file, indent + 1);
        }
    }
}

fn mark(roots: std.ArrayList(*Atom), elf_file: *Elf) void {
    for (roots.items) |root| {
        log.debug("root atom({d})", .{root.atom_index});
        markLive(root, elf_file, 1);
    }
}

fn prune(elf_file: *Elf) void {
    for (elf_file.atoms.items[1..]) |*atom| {
        if (atom.is_alive and !atom.is_visited) {
            atom.is_alive = false;
        }
    }
}
