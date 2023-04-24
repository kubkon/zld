const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const log = std.log.scoped(.gc);
const mem = std.mem;

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");

pub fn gcAtoms(elf_file: *Elf) !void {
    const gpa = elf_file.base.allocator;
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var roots = std.AutoHashMap(Atom.Index, void).init(arena);
    try collectRoots(&roots, elf_file);

    var alive = std.AutoHashMap(Atom.Index, void).init(arena);
    try mark(roots, &alive, elf_file);

    try prune(arena, alive, elf_file);
}

fn removeAtomFromSection(atom_index: Atom.Index, match: u16, elf_file: *Elf) void {
    var section = elf_file.sections.get(match);

    // If we want to enable GC for incremental codepath, we need to take into
    // account any padding that might have been left here.
    const atom = elf_file.getAtom(atom_index);
    section.shdr.sh_size -= atom.size;

    if (atom.prev) |prev| {
        elf_file.getAtomPtr(prev).next = atom.next;
    }
    if (atom.next) |next| {
        elf_file.getAtomPtr(next).prev = atom.prev;
    } else {
        if (atom.prev) |prev| {
            section.last_atom = prev;
        } else {
            // The section will be GCed in the next step.
            section.last_atom = null;
            section.shdr.sh_size = 0;
        }
    }

    elf_file.sections.set(match, section);
}

fn collectRoots(roots: *std.AutoHashMap(Atom.Index, void), elf_file: *Elf) !void {
    const output_mode = elf_file.options.output_mode;

    switch (output_mode) {
        .exe => {
            for (&[_][]const u8{ "_init", "_fini" }) |sym_name| {
                const global = elf_file.globals.get(sym_name) orelse continue;
                const atom_index = elf_file.getAtomIndexForSymbol(global).?;
                _ = try roots.getOrPut(atom_index);
            }
            const global = try elf_file.getEntryPoint();
            const atom_index = elf_file.getAtomIndexForSymbol(global).?;
            _ = try roots.getOrPut(atom_index);
        },
        else => |other| {
            assert(other == .lib);
            for (elf_file.globals.values()) |global| {
                const sym = elf_file.getSymbol(global);
                if (sym.st_shndx == elf.SHN_UNDEF) continue;
                const atom_index = elf_file.getAtomIndexForSymbol(global).?;
                _ = try roots.getOrPut(atom_index);
            }
        },
    }

    for (elf_file.objects.items) |object| {
        const shdrs = object.getShdrs();

        for (object.atoms.items) |atom_index| {
            const atom = elf_file.getAtom(atom_index);
            const sym = object.getSourceSymbol(atom.sym_index) orelse continue;
            const shdr = shdrs[sym.st_shndx];
            const sh_name = object.getShString(shdr.sh_name);
            const is_gc_root = blk: {
                if (shdr.sh_type == elf.SHT_PREINIT_ARRAY) break :blk true;
                if (shdr.sh_type == elf.SHT_INIT_ARRAY) break :blk true;
                if (shdr.sh_type == elf.SHT_FINI_ARRAY) break :blk true;
                if (mem.startsWith(u8, ".ctors", sh_name)) break :blk true;
                if (mem.startsWith(u8, ".dtors", sh_name)) break :blk true;
                if (mem.startsWith(u8, ".init", sh_name)) break :blk true;
                if (mem.startsWith(u8, ".fini", sh_name)) break :blk true;
                if (mem.startsWith(u8, ".jcr", sh_name)) break :blk true;
                if (mem.indexOf(u8, sh_name, "KEEP") != null) break :blk true;
                break :blk false;
            };
            if (is_gc_root) {
                _ = try roots.getOrPut(atom_index);
            }
        }
    }
}

fn markLive(atom_index: Atom.Index, alive: *std.AutoHashMap(Atom.Index, void), elf_file: *Elf) anyerror!void {
    const gop = try alive.getOrPut(atom_index);
    if (gop.found_existing) return;

    log.debug("marking live", .{});
    const atom = elf_file.getAtom(atom_index);
    elf_file.logAtom(atom, log);

    for (atom.relocs.items) |rel| {
        const target_atom_index = atom.getTargetAtomIndex(elf_file, rel) orelse continue;
        try markLive(target_atom_index, alive, elf_file);
    }
}

fn mark(
    roots: std.AutoHashMap(Atom.Index, void),
    alive: *std.AutoHashMap(Atom.Index, void),
    elf_file: *Elf,
) !void {
    try alive.ensureUnusedCapacity(roots.count());

    var it = roots.keyIterator();
    while (it.next()) |root| {
        try markLive(root.*, alive, elf_file);
    }
}

fn prune(arena: Allocator, alive: std.AutoHashMap(Atom.Index, void), elf_file: *Elf) !void {
    // Any section that ends up here will be updated, that is,
    // its size and alignment recalculated.
    var gc_sections = std.AutoHashMap(u16, void).init(arena);

    for (elf_file.objects.items) |object| {
        for (object.atoms.items) |atom_index| {
            if (alive.contains(atom_index)) continue;

            const atom = elf_file.getAtom(atom_index);
            const global = atom.getSymbolWithLoc();
            const sym = atom.getSymbolPtr(elf_file);
            const tshdr = elf_file.sections.items(.shdr)[sym.st_shndx];
            const tshdr_name = elf_file.shstrtab.getAssumeExists(tshdr.sh_name);

            if (sym.st_other == Elf.STV_GC) continue;
            if (mem.startsWith(u8, tshdr_name, ".debug")) continue;
            if (mem.startsWith(u8, tshdr_name, ".comment")) continue;

            log.debug("pruning:", .{});
            elf_file.logAtom(atom, log);
            sym.st_other = Elf.STV_GC;
            removeAtomFromSection(atom_index, sym.st_shndx, elf_file);
            _ = try gc_sections.put(sym.st_shndx, {});

            for (atom.contained.items) |sym_off| {
                const inner = elf_file.getSymbolPtr(.{
                    .sym_index = sym_off.sym_index,
                    .file = atom.file,
                });
                inner.st_other = Elf.STV_GC;
            }

            if (elf_file.got_entries_map.contains(global)) {
                const got_atom_index = elf_file.got_entries_map.get(global).?;
                const got_atom = elf_file.getAtom(got_atom_index);
                const got_sym = got_atom.getSymbolPtr(elf_file);
                got_sym.st_other = Elf.STV_GC;
            }
        }

        for (elf_file.got_entries_map.keys()) |sym_loc| {
            const sym = elf_file.getSymbol(sym_loc);
            if (sym.st_other != Elf.STV_GC) continue;

            // TODO tombstone
            const atom_index = elf_file.got_entries_map.get(sym_loc).?;
            removeAtomFromSection(atom_index, sym.st_shndx, elf_file);
            _ = try gc_sections.put(sym.st_shndx, {});
        }
    }

    var gc_sections_it = gc_sections.iterator();
    while (gc_sections_it.next()) |entry| {
        const match = entry.key_ptr.*;
        var section = elf_file.sections.get(match);
        if (section.shdr.sh_size == 0) continue; // Pruning happens automatically in next step.

        section.shdr.sh_addralign = 0;
        section.shdr.sh_size = 0;

        var atom_index = section.last_atom.?;

        while (true) {
            const atom = elf_file.getAtom(atom_index);
            if (atom.prev) |prev| {
                atom_index = prev;
            } else break;
        }

        while (true) {
            const atom = elf_file.getAtom(atom_index);
            const aligned_end_addr = mem.alignForwardGeneric(u64, section.shdr.sh_size, atom.alignment);
            const padding = aligned_end_addr - section.shdr.sh_size;
            section.shdr.sh_size += padding + atom.size;
            section.shdr.sh_addralign = @max(section.shdr.sh_addralign, atom.alignment);

            if (atom.next) |next| {
                atom_index = next;
            } else break;
        }

        elf_file.sections.set(match, section);
    }

    // TODO we might want to prune empty sections next
}
