const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.dead_strip);
const macho = std.macho;
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const AtomIndex = MachO.AtomIndex;
const Atom = @import("Atom.zig");
const MachO = @import("../MachO.zig");
const SymbolWithLoc = MachO.SymbolWithLoc;

const AtomTable = std.AutoHashMap(AtomIndex, void);

pub fn gcAtoms(macho_file: *MachO, reverse_lookups: [][]u32) !void {
    const gpa = macho_file.base.allocator;

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();

    var roots = AtomTable.init(arena.allocator());
    try roots.ensureUnusedCapacity(@intCast(u32, macho_file.globals.count()));

    var alive = AtomTable.init(arena.allocator());
    try alive.ensureTotalCapacity(@intCast(u32, macho_file.atoms.items.len));

    try collectRoots(macho_file, &roots);
    try mark(macho_file, roots, &alive, reverse_lookups);
    try prune(macho_file, alive);
}

fn collectRoots(macho_file: *MachO, roots: *AtomTable) !void {
    const output_mode = macho_file.options.output_mode;

    log.debug("collecting roots", .{});

    switch (output_mode) {
        .exe => {
            // Add entrypoint as GC root
            const global: SymbolWithLoc = try macho_file.getEntryPoint();
            const object = macho_file.objects.items[global.getFile().?];
            const atom_index = object.getAtomIndexForSymbol(global.sym_index).?; // panic here means fatal error
            _ = try roots.getOrPut(atom_index);
            log.debug("adding root", .{});
            macho_file.logAtom(atom_index, log);
        },
        else => |other| {
            assert(other == .lib);
            // Add exports as GC roots
            for (macho_file.globals.values()) |global| {
                const sym = macho_file.getSymbol(global);
                if (sym.undf()) continue;

                const object = macho_file.objects.items[global.getFile().?];
                const atom_index = object.getAtomIndexForSymbol(global.sym_index).?; // panic here means fatal error
                _ = try roots.getOrPut(atom_index);
                log.debug("adding root", .{});
                macho_file.logAtom(atom_index, log);
            }
        },
    }

    // TODO just a temp until we learn how to parse unwind records
    if (macho_file.globals.get("___gxx_personality_v0")) |global| {
        const object = macho_file.objects.items[global.getFile().?];
        if (object.getAtomIndexForSymbol(global.sym_index)) |atom_index| {
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

fn markLive(
    macho_file: *MachO,
    atom_index: AtomIndex,
    alive: *AtomTable,
    reverse_lookups: [][]u32,
) anyerror!void {
    if (alive.contains(atom_index)) return;

    alive.putAssumeCapacityNoClobber(atom_index, {});

    log.debug("marking live", .{});
    macho_file.logAtom(atom_index, log);

    const cpu_arch = macho_file.options.target.cpu_arch.?;

    const atom = macho_file.getAtom(atom_index);
    const sym = macho_file.getSymbol(atom.getSymbolWithLoc());
    const header = macho_file.sections.items(.header)[sym.n_sect - 1];
    if (header.isZerofill()) return;

    const relocs = Atom.getAtomRelocs(macho_file, atom_index);
    const reverse_lookup = reverse_lookups[atom.getFile().?];
    for (relocs) |rel| {
        switch (cpu_arch) {
            .aarch64 => {
                const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
                switch (rel_type) {
                    .ARM64_RELOC_ADDEND, .ARM64_RELOC_SUBTRACTOR => continue,
                    else => {},
                }
            },
            .x86_64 => {
                const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
                switch (rel_type) {
                    .X86_64_RELOC_SUBTRACTOR => continue,
                    else => {},
                }
            },
            else => unreachable,
        }

        const target = try Atom.parseRelocTarget(macho_file, atom_index, rel, reverse_lookup);
        const target_sym = macho_file.getSymbol(target);
        if (target_sym.undf()) continue;
        if (target.getFile() == null) {
            const target_sym_name = macho_file.getSymbolName(target);
            if (mem.eql(u8, "__mh_execute_header", target_sym_name)) continue;
            if (mem.eql(u8, "___dso_handle", target_sym_name)) continue;

            unreachable; // referenced symbol not found
        }

        const object = macho_file.objects.items[target.getFile().?];
        const target_atom_index = object.getAtomIndexForSymbol(target.sym_index).?;
        try markLive(macho_file, target_atom_index, alive, reverse_lookups);
    }
}

fn refersLive(macho_file: *MachO, atom_index: AtomIndex, alive: AtomTable, reverse_lookups: [][]u32) !bool {
    const cpu_arch = macho_file.options.target.cpu_arch.?;

    const atom = macho_file.getAtom(atom_index);
    const sym = macho_file.getSymbol(atom.getSymbolWithLoc());
    const header = macho_file.sections.items(.header)[sym.n_sect - 1];
    if (header.isZerofill()) return false;

    const relocs = Atom.getAtomRelocs(macho_file, atom_index);
    const reverse_lookup = reverse_lookups[atom.getFile().?];
    for (relocs) |rel| {
        switch (cpu_arch) {
            .aarch64 => {
                const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
                switch (rel_type) {
                    .ARM64_RELOC_ADDEND, .ARM64_RELOC_SUBTRACTOR => continue,
                    else => {},
                }
            },
            .x86_64 => {
                const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
                switch (rel_type) {
                    .X86_64_RELOC_SUBTRACTOR => continue,
                    else => {},
                }
            },
            else => unreachable,
        }

        const target = try Atom.parseRelocTarget(macho_file, atom_index, rel, reverse_lookup);
        const object = macho_file.objects.items[target.getFile().?];
        const target_atom_index = object.getAtomIndexForSymbol(target.sym_index) orelse {
            log.debug("atom for symbol '{s}' not found; skipping...", .{macho_file.getSymbolName(target)});
            continue;
        };
        if (alive.contains(target_atom_index)) return true;
    }

    return false;
}

fn mark(macho_file: *MachO, roots: AtomTable, alive: *AtomTable, reverse_lookups: [][]u32) !void {
    var it = roots.keyIterator();
    while (it.next()) |root| {
        try markLive(macho_file, root.*, alive, reverse_lookups);
    }

    var loop: bool = true;
    while (loop) {
        loop = false;

        for (macho_file.objects.items) |object| {
            for (object.atoms.items) |atom_index| {
                if (alive.contains(atom_index)) continue;

                const atom = macho_file.getAtom(atom_index);
                const source_sym = object.getSourceSymbol(atom.sym_index) orelse continue;
                const source_sect = object.getSourceSection(source_sym.n_sect - 1);

                if (source_sect.isDontDeadStripIfReferencesLive()) {
                    if (try refersLive(macho_file, atom_index, alive.*, reverse_lookups)) {
                        try markLive(macho_file, atom_index, alive, reverse_lookups);
                        loop = true;
                    }
                }
            }
        }
    }
}

fn prune(macho_file: *MachO, alive: AtomTable) !void {
    log.debug("pruning dead atoms", .{});
    for (macho_file.objects.items) |*object| {
        var i: usize = 0;
        while (i < object.atoms.items.len) {
            const atom_index = object.atoms.items[i];
            if (alive.contains(atom_index)) {
                i += 1;
                continue;
            }

            macho_file.logAtom(atom_index, log);

            const atom = macho_file.getAtom(atom_index);
            const sym_loc = atom.getSymbolWithLoc();
            const sym = macho_file.getSymbol(sym_loc);
            const sect_id = sym.n_sect - 1;
            var section = macho_file.sections.get(sect_id);
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
                    assert(section.header.size == 0);
                    section.first_atom_index = undefined;
                    section.last_atom_index = undefined;
                }
            }

            macho_file.sections.set(sect_id, section);
            _ = object.atoms.swapRemove(i);

            const sym_name = macho_file.getSymbolName(sym_loc);
            if (macho_file.globals.get(sym_name)) |global| {
                if (global.eql(sym_loc)) {
                    const kv = macho_file.globals.fetchSwapRemove(sym_name).?;
                    macho_file.base.allocator.free(kv.key);
                }
            }

            var inner_sym_it = Atom.getInnerSymbolsIterator(macho_file, atom_index);
            while (inner_sym_it.next()) |inner| {
                const inner_name = macho_file.getSymbolName(inner);
                if (macho_file.globals.get(inner_name)) |global| {
                    if (global.eql(inner)) {
                        const kv = macho_file.globals.fetchSwapRemove(inner_name).?;
                        macho_file.base.allocator.free(kv.key);
                    }
                }
            }
        }
    }
}
