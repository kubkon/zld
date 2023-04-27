const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const log = std.log.scoped(.elf);
const mem = std.mem;

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");

pub fn gcAtoms(elf_file: *Elf) !void {
    const gpa = elf_file.base.allocator;
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var roots = std.AutoHashMap(*Atom, void).init(arena);
    try collectRoots(&roots, elf_file);
    try mark(roots, elf_file);
}

fn collectRoots(roots: *std.AutoHashMap(*Atom, void), elf_file: *Elf) !void {
    const output_mode = elf_file.options.output_mode;

    switch (output_mode) {
        .exe => {
            if (elf_file.entry_index) |index| {
                const global = elf_file.getGlobal(index);
                const atom = global.getAtom(elf_file).?;
                log.debug("adding as root atom %%%{d}", .{atom.atom_index});
                _ = try roots.getOrPut(atom);
            }
        },
        else => |other| {
            assert(other == .lib);
            for (elf_file.globals.items) |global| if (global.getAtom(elf_file)) |atom| {
                log.debug("adding as root atom %%%{d}", .{atom.atom_index});
                _ = try roots.getOrPut(atom);
            };
        },
    }

    for (elf_file.atoms.items) |*atom| {
        if (atom.atom_index == 0) continue;
        const shdr = atom.getInputShdr(elf_file);
        const name = atom.getName(elf_file);
        const is_gc_root = blk: {
            if (shdr.sh_type == elf.SHT_PREINIT_ARRAY) break :blk true;
            if (shdr.sh_type == elf.SHT_INIT_ARRAY) break :blk true;
            if (shdr.sh_type == elf.SHT_FINI_ARRAY) break :blk true;
            if (mem.startsWith(u8, ".ctors", name)) break :blk true;
            if (mem.startsWith(u8, ".dtors", name)) break :blk true;
            if (mem.startsWith(u8, ".init", name)) break :blk true;
            if (mem.startsWith(u8, ".fini", name)) break :blk true;
            if (mem.startsWith(u8, ".jcr", name)) break :blk true;
            if (mem.indexOf(u8, name, "KEEP") != null) break :blk true;
            if (mem.indexOf(u8, name, ".debug") != null) break :blk true;
            if (mem.indexOf(u8, name, ".comment") != null) break :blk true;
            if (mem.indexOf(u8, name, ".note") != null) break :blk true;
            break :blk false;
        };
        if (is_gc_root) {
            log.debug("adding as root atom %%%{d}", .{atom.atom_index});
            _ = try roots.getOrPut(atom);
        }
    }
}

fn markLive(atom: *Atom, elf_file: *Elf) void {
    if (atom.is_alive) return;
    atom.is_alive = true;
    log.debug("marking live atom %%%{d}", .{atom.atom_index});
    const object = atom.getFile(elf_file);
    const nlocals = object.getNumLocals();
    for (atom.getRelocs(elf_file)) |rel| {
        const index = rel.r_sym();
        const target_atom = if (index >= nlocals) blk: {
            // It's a global!
            assert(object.first_global != null);
            const global_index = object.globals.items[index - nlocals];
            const global = elf_file.getGlobal(global_index);
            break :blk global.getAtom(elf_file);
        } else blk: {
            const local = object.locals.items[index];
            break :blk local.getAtom(elf_file).?;
        };
        if (target_atom) |ta| {
            markLive(ta, elf_file);
        }
    }
}

fn mark(roots: std.AutoHashMap(*Atom, void), elf_file: *Elf) !void {
    var it = roots.keyIterator();
    while (it.next()) |root| {
        markLive(root.*, elf_file);
    }
}
