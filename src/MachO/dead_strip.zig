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

pub fn gcAtoms(macho_file: *MachO, reverse_lookups: [][]u32) !void {
    const gpa = macho_file.base.allocator;

    var roots = std.AutoHashMap(AtomIndex, void).init(gpa);
    defer roots.deinit();

    try collectRoots(macho_file, &roots);
    try mark(macho_file, roots, reverse_lookups);
    try prune(macho_file);
}

fn collectRoots(macho_file: *MachO, roots: *std.AutoHashMap(AtomIndex, void)) !void {
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
                if (sym.undf()) continue;

                const atom_index = macho_file.getAtomIndexForSymbol(global) orelse {
                    log.debug("atom for symbol '{s}' not found", .{macho_file.getSymbolName(global)});
                    continue;
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

fn markLive(macho_file: *MachO, atom_index: AtomIndex, reverse_lookups: [][]u32) anyerror!void {
    const atom = macho_file.getAtomPtr(atom_index);
    if (atom.live) |_| return;
    atom.live = true;
    log.debug("marking live", .{});
    macho_file.logAtom(atom_index, log);

    const cpu_arch = macho_file.options.target.cpu_arch.?;

    const sym = macho_file.getSymbol(atom.getSymbolWithLoc());
    const header = macho_file.sections.items(.header)[sym.n_sect - 1];
    if (header.isZerofill()) return;

    const relocs = Atom.getAtomRelocs(macho_file, atom_index);
    const reverse_lookup = reverse_lookups[atom.file.?];
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
        const target_atom_index = macho_file.getAtomIndexForSymbol(target) orelse {
            log.debug("atom for symbol '{s}' not found; skipping...", .{macho_file.getSymbolName(target)});
            continue;
        };
        try markLive(macho_file, target_atom_index, reverse_lookups);
    }
}

fn refersLive(macho_file: *MachO, atom_index: AtomIndex, reverse_lookups: [][]u32) !bool {
    const cpu_arch = macho_file.options.target.cpu_arch.?;

    const atom = macho_file.getAtom(atom_index);
    const sym = macho_file.getSymbol(atom.getSymbolWithLoc());
    const header = macho_file.sections.items(.header)[sym.n_sect - 1];
    if (header.isZerofill()) return false;

    const relocs = Atom.getAtomRelocs(macho_file, atom_index);
    const reverse_lookup = reverse_lookups[atom.file.?];
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
        const target_atom_index = macho_file.getAtomIndexForSymbol(target) orelse {
            log.debug("atom for symbol '{s}' not found; skipping...", .{macho_file.getSymbolName(target)});
            continue;
        };
        const target_atom = macho_file.getAtom(target_atom_index);
        if (target_atom.live) |live| {
            return live;
        }
    }

    return false;
}

fn mark(macho_file: *MachO, roots: std.AutoHashMap(AtomIndex, void), reverse_lookups: [][]u32) !void {
    var it = roots.keyIterator();
    while (it.next()) |root| {
        try markLive(macho_file, root.*, reverse_lookups);
    }

    var loop: bool = true;
    while (loop) {
        loop = false;

        for (macho_file.objects.items) |object| {
            for (object.atoms.items) |atom_index| {
                const atom = macho_file.getAtom(atom_index);
                if (atom.live) |_| continue;

                const source_sym = object.getSourceSymbol(atom.sym_index) orelse continue;
                const source_sect = object.getSourceSection(source_sym.n_sect - 1);

                if (source_sect.isDontDeadStripIfReferencesLive()) {
                    if (try refersLive(macho_file, atom_index, reverse_lookups)) {
                        try markLive(macho_file, atom_index, reverse_lookups);
                        loop = true;
                    }
                }
            }
        }
    }
}

fn prune(macho_file: *MachO) !void {
    log.debug("pruning dead atoms", .{});
    for (macho_file.objects.items) |object| {
        for (object.atoms.items) |atom_index| {
            const atom = macho_file.getAtomPtr(atom_index);
            if (atom.live) |_| continue;

            atom.live = false;
            macho_file.logAtom(atom_index, log);

            const sym = macho_file.getSymbol(atom.getSymbolWithLoc());
            const sect_id = sym.n_sect - 1;
            var section = macho_file.sections.get(sect_id);

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
                    section.first_atom_index = null;
                    section.last_atom_index = null;
                }
            }

            macho_file.sections.set(sect_id, section);
        }
    }
}
