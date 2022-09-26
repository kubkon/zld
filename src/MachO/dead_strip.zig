const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.dead_strip);
const macho = std.macho;
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const AtomIndex = MachO.AtomIndex;
const MachO = @import("../MachO.zig");
const SymbolWithLoc = MachO.SymbolWithLoc;

pub fn gcAtoms(macho_file: *MachO, reverse_lookups: [][]u32) !void {
    const gpa = macho_file.base.allocator;

    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var roots = std.AutoHashMap(AtomIndex, void).init(arena);
    try collectRoots(&roots, macho_file);
    _ = reverse_lookups;

    // var alive = std.AutoHashMap(AtomIndex, void).init(arena);
    // try mark(roots, &alive, macho_file);

    // try prune(arena, alive, macho_file);
}

fn collectRoots(roots: *std.AutoHashMap(AtomIndex, void), macho_file: *MachO) !void {
    const output_mode = macho_file.options.output_mode;

    log.debug("collecting roots", .{});

    switch (output_mode) {
        .exe => {
            // Add entrypoint as GC root
            const global = try macho_file.getEntryPoint();
            const atom_index = macho_file.getAtomIndexForSymbol(global).?; // panic here means fatal error
            _ = try roots.getOrPut(atom_index);
            log.debug("adding root", .{});
            macho_file.logAtom(atom_index, log);
        },
        else => |other| {
            assert(other == .lib);
            // Add exports as GC roots
            for (macho_file.globals.values()) |global| {
                const sym = macho_file.getSymbol(global);
                if (!sym.sect()) continue;
                const atom_index = macho_file.getAtomIndexForSymbol(global) orelse {
                    log.debug("atom for symbol '{s}' not found", .{macho_file.getSymbolName(global)});
                    unreachable;
                };
                _ = try roots.getOrPut(atom_index);
                log.debug("adding root", .{});
                macho_file.logAtom(atom_index, log);
            }
        },
    }

    // TODO just a temp until we learn how to parse unwind records
    if (macho_file.globals.get("___gxx_personality_v0")) |global| {
        if (macho_file.getAtomIndexForSymbol(global)) |atom_index| {
            _ = try roots.getOrPut(atom_index);
            log.debug("adding root", .{});
            macho_file.logAtom(atom_index, log);
        }
    }

    for (macho_file.objects.items) |object| {
        for (object.atoms.items) |atom_index| {
            const atom = macho_file.getAtom(atom_index);
            const source_sym = object.getSourceSymbol(atom.sym_index) orelse continue;
            const source_sect = object.getSourceSection(source_sym.n_sect - 1);
            const is_gc_root = blk: {
                if (source_sect.isDontDeadStrip()) break :blk true;
                if (mem.eql(u8, "__StaticInit", source_sect.sectName())) break :blk true;
                switch (source_sect.@"type"()) {
                    macho.S_MOD_INIT_FUNC_POINTERS,
                    macho.S_MOD_TERM_FUNC_POINTERS,
                    => break :blk true,
                    else => break :blk false,
                }
            };
            if (is_gc_root) {
                try roots.putNoClobber(atom_index, {});
                log.debug("adding root", .{});
                macho_file.logAtom(atom_index, log);
            }
        }
    }
}

fn markLive(atom_index: AtomIndex, alive: *std.AutoHashMap(AtomIndex, void), macho_file: *MachO) anyerror!void {
    const gop = try alive.getOrPut(atom_index);
    if (gop.found_existing) return;

    log.debug("marking live", .{});
    macho_file.logAtom(atom_index, log);

    if (macho_file.relocs.get(atom_index)) |relocs| {
        for (relocs.items) |rel| {
            const target_atom_index = rel.getTargetAtomIndex(macho_file) orelse continue;
            try markLive(target_atom_index, alive, macho_file);
        }
    }
}

fn refersLive(atom_index: AtomIndex, alive: std.AutoHashMap(AtomIndex, void), macho_file: *MachO) bool {
    if (macho_file.relocs.get(atom_index)) |relocs| {
        for (relocs.items) |rel| {
            const target_atom_index = rel.getTargetAtomIndex(macho_file) orelse continue;
            if (alive.contains(target_atom_index)) return true;
        }
    }
    return false;
}

fn refersDead(atom_index: AtomIndex, macho_file: *MachO) bool {
    if (macho_file.relocs.get(atom_index)) |relocs| {
        for (relocs.items) |rel| {
            const target_atom_index = rel.getTargetAtomIndex(macho_file) orelse continue;
            const target_atom = macho_file.getAtom(target_atom_index);
            const target_sym = macho_file.getSymbol(target_atom.getSymbolWithLoc());
            if (target_sym.n_desc == MachO.N_DESC_GCED) return true;
        }
    }
    return false;
}

fn mark(roots: std.AutoHashMap(AtomIndex, void), alive: *std.AutoHashMap(AtomIndex, void), macho_file: *MachO) !void {
    try alive.ensureUnusedCapacity(roots.count());

    var it = roots.keyIterator();
    while (it.next()) |root| {
        try markLive(root.*, alive, macho_file);
    }

    var loop: bool = true;
    while (loop) {
        loop = false;

        for (macho_file.objects.items) |object| {
            for (object.atoms.items) |atom_index| {
                if (alive.contains(atom_index)) continue;

                const atom = macho_file.getAtom(atom_index);
                const source_sym = object.getSourceSymbol(atom.sym_index) orelse continue;
                if (source_sym.tentative()) continue;

                const source_sect = object.getSourceSection(source_sym.n_sect - 1);

                if (source_sect.isDontDeadStripIfReferencesLive() and refersLive(atom_index, alive.*, macho_file)) {
                    try markLive(atom_index, alive, macho_file);
                    loop = true;
                }
            }
        }
    }
}

fn prune(arena: Allocator, alive: std.AutoHashMap(AtomIndex, void), macho_file: *MachO) !void {
    // Any section that ends up here will be updated, that is,
    // its size and alignment recalculated.
    var gc_sections = std.AutoHashMap(u8, void).init(arena);
    var loop: bool = true;
    while (loop) {
        loop = false;

        for (macho_file.objects.items) |object| {
            const in_symtab = object.in_symtab orelse continue;

            for (in_symtab) |_, source_index| {
                const atom_index = object.getAtomIndexForSymbol(@intCast(u32, source_index)) orelse continue;
                if (alive.contains(atom_index)) continue;

                const atom = macho_file.getAtom(atom_index);
                const global = atom.getSymbolWithLoc();
                const sym = macho_file.getSymbolPtr(global);
                const match = sym.n_sect - 1;

                if (sym.n_desc == MachO.N_DESC_GCED) continue;
                if (!sym.ext() and !refersDead(atom_index, macho_file)) continue;

                macho_file.logAtom(atom_index, log);
                sym.n_desc = MachO.N_DESC_GCED;
                removeAtomFromSection(atom_index, match, macho_file);
                _ = try gc_sections.put(match, {});

                for (atom.contained.items) |sym_off| {
                    const inner = macho_file.getSymbolPtr(.{
                        .sym_index = sym_off.sym_index,
                        .file = atom.file,
                    });
                    inner.n_desc = MachO.N_DESC_GCED;
                }

                if (macho_file.got_entries.contains(global)) {
                    const got_atom_index = macho_file.getGotAtomIndexForSymbol(global).?;
                    const got_atom = macho_file.getAtom(got_atom_index);
                    const got_sym = macho_file.getSymbolPtr(got_atom.getSymbolWithLoc());
                    got_sym.n_desc = MachO.N_DESC_GCED;
                }

                if (macho_file.stubs.contains(global)) {
                    const stubs_atom_index = macho_file.getStubsAtomIndexForSymbol(global).?;
                    const stubs_atom = macho_file.getAtom(stubs_atom_index);
                    const stubs_sym = macho_file.getSymbolPtr(stubs_atom.getSymbolWithLoc());
                    stubs_sym.n_desc = MachO.N_DESC_GCED;
                }

                if (macho_file.tlv_ptr_entries.contains(global)) {
                    const tlv_ptr_atom_index = macho_file.getTlvPtrAtomIndexForSymbol(global).?;
                    const tlv_ptr_atom = macho_file.getAtom(tlv_ptr_atom_index);
                    const tlv_ptr_sym = macho_file.getSymbolPtr(tlv_ptr_atom.getSymbolWithLoc());
                    tlv_ptr_sym.n_desc = MachO.N_DESC_GCED;
                }

                loop = true;
            }
        }
    }

    for (macho_file.got_entries.keys()) |target| {
        const sym_index = macho_file.got_entries.get(target).?;
        const sym = macho_file.getSymbol(.{ .sym_index = sym_index, .file = null });
        if (sym.n_desc != MachO.N_DESC_GCED) continue;

        const atom_index = macho_file.getAtomIndexForSymbol(.{ .sym_index = sym_index, .file = null }).?;
        const match = sym.n_sect - 1;
        removeAtomFromSection(atom_index, match, macho_file);
        _ = try gc_sections.put(match, {});
        _ = macho_file.got_entries.swapRemove(target);
    }

    for (macho_file.stubs.keys()) |target| {
        const sym_index = macho_file.stubs.get(target).?;
        const sym = macho_file.getSymbol(.{ .sym_index = sym_index, .file = null });
        if (sym.n_desc != MachO.N_DESC_GCED) continue;

        const atom_index = macho_file.getAtomIndexForSymbol(.{ .sym_index = sym_index, .file = null }).?;
        const match = sym.n_sect - 1;
        removeAtomFromSection(atom_index, match, macho_file);
        _ = try gc_sections.put(match, {});
        _ = macho_file.stubs.swapRemove(target);
    }

    for (macho_file.tlv_ptr_entries.keys()) |target| {
        const sym_index = macho_file.tlv_ptr_entries.get(target).?;
        const sym = macho_file.getSymbol(.{ .sym_index = sym_index, .file = null });
        if (sym.n_desc != MachO.N_DESC_GCED) continue;

        const atom_index = macho_file.getAtomIndexForSymbol(.{ .sym_index = sym_index, .file = null }).?;
        const match = sym.n_sect - 1;
        removeAtomFromSection(atom_index, match, macho_file);
        _ = try gc_sections.put(match, {});
        _ = macho_file.tlv_ptr_entries.swapRemove(target);
    }

    var gc_sections_it = gc_sections.iterator();
    while (gc_sections_it.next()) |entry| {
        const match = entry.key_ptr.*;
        var section = macho_file.sections.get(match);
        if (section.header.size == 0) continue; // Pruning happens automatically in next step.

        section.header.@"align" = 0;
        section.header.size = 0;

        var atom_index = section.first_atom_index;
        var atom = macho_file.getAtom(atom_index);

        while (true) {
            const atom_alignment = try math.powi(u32, 2, atom.alignment);
            const aligned_end_addr = mem.alignForwardGeneric(u64, section.header.size, atom_alignment);
            const padding = aligned_end_addr - section.header.size;
            section.header.size += padding + atom.size;
            section.header.@"align" = @maximum(section.header.@"align", atom.alignment);

            if (atom.next_index) |next_index| {
                atom_index = next_index;
                atom = macho_file.getAtom(atom_index);
            } else break;
        }

        macho_file.sections.set(match, section);
    }
}

fn removeAtomFromSection(atom_index: AtomIndex, match: u8, macho_file: *MachO) void {
    macho_file.freeAtom(atom_index);

    var section = macho_file.sections.get(match);
    const atom = macho_file.getAtomPtr(atom_index);

    // If we want to enable GC for incremental codepath, we need to take into
    // account any padding that might have been left here.
    section.header.size -= atom.size;

    if (atom.prev_index) |prev_index| {
        const prev = macho_file.getAtomPtr(prev_index);
        prev.next_index = atom.next_index;
    } else {
        if (atom.next_index) |next_index| {
            section.first_atom_index = next_index;
        }
    }
    if (atom.next_index) |next_index| {
        const next = macho_file.getAtomPtr(next_index);
        next.prev_index = atom.prev_index;
    } else {
        if (atom.prev_index) |prev_index| {
            section.last_atom_index = prev_index;
        } else {
            // The section will be GCed in the next step.
            section.first_atom_index = undefined;
            section.last_atom_index = undefined;
            section.header.size = 0;
        }
    }

    macho_file.sections.set(match, section);
}
