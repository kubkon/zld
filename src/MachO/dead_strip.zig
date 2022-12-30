const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.dead_strip);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const trace = @import("../tracy.zig").trace;

const Allocator = mem.Allocator;
const AtomIndex = MachO.AtomIndex;
const Atom = @import("Atom.zig");
const MachO = @import("../MachO.zig");
const SymbolWithLoc = MachO.SymbolWithLoc;

const AtomTable = std.AutoHashMap(AtomIndex, void);

pub fn gcAtoms(macho_file: *MachO) Allocator.Error!void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.allocator;

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();

    var roots = AtomTable.init(arena.allocator());
    try roots.ensureUnusedCapacity(@intCast(u32, macho_file.globals.items.len));

    var alive = AtomTable.init(arena.allocator());
    try alive.ensureTotalCapacity(@intCast(u32, macho_file.atoms.items.len));

    try collectRoots(macho_file, &roots);
    mark(macho_file, roots, &alive);
    prune(macho_file, alive);
}

fn collectRoots(macho_file: *MachO, roots: *AtomTable) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const output_mode = macho_file.options.output_mode;

    log.debug("collecting roots", .{});

    switch (output_mode) {
        .exe => {
            // Add entrypoint as GC root
            const global: SymbolWithLoc = macho_file.getEntryPoint();
            const object = macho_file.objects.items[global.getFile().?];
            const atom_index = object.getAtomIndexForSymbol(global.sym_index).?; // panic here means fatal error
            _ = try roots.getOrPut(atom_index);

            log.debug("root(ATOM({d}, %{d}, {d}))", .{
                atom_index,
                macho_file.getAtom(atom_index).sym_index,
                macho_file.getAtom(atom_index).file,
            });
        },
        else => |other| {
            assert(other == .lib);
            // Add exports as GC roots
            for (macho_file.globals.items) |global| {
                const sym = macho_file.getSymbol(global);
                if (sym.undf()) continue;

                const file = global.getFile() orelse continue; // synthetic globals are atomless
                const object = macho_file.objects.items[file];
                const atom_index = object.getAtomIndexForSymbol(global.sym_index).?; // panic here means fatal error
                _ = try roots.getOrPut(atom_index);

                log.debug("root(ATOM({d}, %{d}, {d}))", .{
                    atom_index,
                    macho_file.getAtom(atom_index).sym_index,
                    macho_file.getAtom(atom_index).file,
                });
            }
        },
    }

    // TODO just a temp until we learn how to parse unwind records
    for (macho_file.globals.items) |global| {
        if (mem.eql(u8, "___gxx_personality_v0", macho_file.getSymbolName(global))) {
            const object = macho_file.objects.items[global.getFile().?];
            if (object.getAtomIndexForSymbol(global.sym_index)) |atom_index| {
                _ = try roots.getOrPut(atom_index);

                log.debug("root(ATOM({d}, %{d}, {d}))", .{
                    atom_index,
                    macho_file.getAtom(atom_index).sym_index,
                    macho_file.getAtom(atom_index).file,
                });
            }
            break;
        }
    }

    for (macho_file.objects.items) |object| {
        const has_subsections = object.header.flags & macho.MH_SUBSECTIONS_VIA_SYMBOLS != 0;

        for (object.atoms.items) |atom_index| {
            const is_gc_root = blk: {
                // Modelled after ld64 which treats each object file compiled without MH_SUBSECTIONS_VIA_SYMBOLS
                // as a root.
                if (!has_subsections) break :blk true;

                const atom = macho_file.getAtom(atom_index);
                const sect_id = if (object.getSourceSymbol(atom.sym_index)) |source_sym|
                    source_sym.n_sect - 1
                else sect_id: {
                    const nbase = @intCast(u32, object.in_symtab.?.len);
                    const sect_id = @intCast(u16, atom.sym_index - nbase);
                    break :sect_id sect_id;
                };
                const source_sect = object.getSourceSection(sect_id);
                if (source_sect.isDontDeadStrip()) break :blk true;
                switch (source_sect.type()) {
                    macho.S_MOD_INIT_FUNC_POINTERS,
                    macho.S_MOD_TERM_FUNC_POINTERS,
                    => break :blk true,
                    else => break :blk false,
                }
            };
            if (is_gc_root) {
                try roots.putNoClobber(atom_index, {});

                log.debug("root(ATOM({d}, %{d}, {d}))", .{
                    atom_index,
                    macho_file.getAtom(atom_index).sym_index,
                    macho_file.getAtom(atom_index).file,
                });
            }
        }
    }
}

fn markLive(
    macho_file: *MachO,
    atom_index: AtomIndex,
    alive: *AtomTable,
) void {
    const tracy = trace(@src());
    defer tracy.end();

    if (alive.contains(atom_index)) return;

    const atom = macho_file.getAtom(atom_index);
    const sym_loc = atom.getSymbolWithLoc();

    log.debug("mark(ATOM({d}, %{d}, {d}))", .{ atom_index, sym_loc.sym_index, sym_loc.file });

    alive.putAssumeCapacityNoClobber(atom_index, {});

    macho_file.logAtom(atom_index, log);

    const cpu_arch = macho_file.options.target.cpu_arch.?;

    const sym = macho_file.getSymbol(sym_loc);
    const header = macho_file.sections.items(.header)[sym.n_sect - 1];
    if (header.isZerofill()) return;

    const relocs = Atom.getAtomRelocs(macho_file, atom_index);
    for (relocs) |rel| {
        const target = switch (cpu_arch) {
            .aarch64 => switch (@intToEnum(macho.reloc_type_arm64, rel.r_type)) {
                .ARM64_RELOC_ADDEND => continue,
                else => Atom.parseRelocTarget(macho_file, atom_index, rel),
            },
            .x86_64 => Atom.parseRelocTarget(macho_file, atom_index, rel),
            else => unreachable,
        };
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
        log.debug("  following ATOM({d}, %{d}, {d})", .{
            target_atom_index,
            macho_file.getAtom(target_atom_index).sym_index,
            macho_file.getAtom(target_atom_index).file,
        });

        markLive(macho_file, target_atom_index, alive);
    }
}

fn refersLive(macho_file: *MachO, atom_index: AtomIndex, alive: AtomTable) bool {
    const tracy = trace(@src());
    defer tracy.end();

    const atom = macho_file.getAtom(atom_index);
    const sym_loc = atom.getSymbolWithLoc();

    log.debug("refersLive(ATOM({d}, %{d}, {d}))", .{ atom_index, sym_loc.sym_index, sym_loc.file });

    const cpu_arch = macho_file.options.target.cpu_arch.?;

    const sym = macho_file.getSymbol(sym_loc);
    const header = macho_file.sections.items(.header)[sym.n_sect - 1];
    assert(!header.isZerofill());

    const relocs = Atom.getAtomRelocs(macho_file, atom_index);
    for (relocs) |rel| {
        const target = switch (cpu_arch) {
            .aarch64 => switch (@intToEnum(macho.reloc_type_arm64, rel.r_type)) {
                .ARM64_RELOC_ADDEND => continue,
                else => Atom.parseRelocTarget(macho_file, atom_index, rel),
            },
            .x86_64 => Atom.parseRelocTarget(macho_file, atom_index, rel),
            else => unreachable,
        };

        const object = macho_file.objects.items[target.getFile().?];
        const target_atom_index = object.getAtomIndexForSymbol(target.sym_index) orelse {
            log.debug("atom for symbol '{s}' not found; skipping...", .{macho_file.getSymbolName(target)});
            continue;
        };
        if (alive.contains(target_atom_index)) {
            if (alive.contains(target_atom_index)) {
                log.debug("  refers live ATOM({d}, %{d}, {d})", .{
                    target_atom_index,
                    macho_file.getAtom(target_atom_index).sym_index,
                    macho_file.getAtom(target_atom_index).file,
                });
                return true;
            }
        }
    }

    return false;
}

fn mark(macho_file: *MachO, roots: AtomTable, alive: *AtomTable) void {
    const tracy = trace(@src());
    defer tracy.end();

    var it = roots.keyIterator();
    while (it.next()) |root| {
        markLive(macho_file, root.*, alive);
    }

    var loop: bool = true;
    while (loop) {
        loop = false;

        for (macho_file.objects.items) |object| {
            for (object.atoms.items) |atom_index| {
                if (alive.contains(atom_index)) continue;

                const atom = macho_file.getAtom(atom_index);
                const sect_id = if (object.getSourceSymbol(atom.sym_index)) |source_sym|
                    source_sym.n_sect - 1
                else blk: {
                    const nbase = @intCast(u32, object.in_symtab.?.len);
                    const sect_id = @intCast(u16, atom.sym_index - nbase);
                    break :blk sect_id;
                };
                const source_sect = object.getSourceSection(sect_id);

                if (source_sect.isDontDeadStripIfReferencesLive()) {
                    if (refersLive(macho_file, atom_index, alive.*)) {
                        markLive(macho_file, atom_index, alive);
                        loop = true;
                    }
                }
            }
        }
    }
}

fn prune(macho_file: *MachO, alive: AtomTable) void {
    const tracy = trace(@src());
    defer tracy.end();

    log.debug("pruning dead atoms", .{});
    for (macho_file.objects.items) |*object| {
        var i: usize = 0;
        while (i < object.atoms.items.len) {
            const atom_index = object.atoms.items[i];
            if (alive.contains(atom_index)) {
                i += 1;
                continue;
            }

            const atom = macho_file.getAtom(atom_index);
            const sym_loc = atom.getSymbolWithLoc();

            log.debug("prune(ATOM({d}, %{d}, {d}))", .{
                atom_index,
                sym_loc.sym_index,
                sym_loc.file,
            });
            log.debug("  {s} in {s}", .{ macho_file.getSymbolName(sym_loc), object.name });

            const sym = macho_file.getSymbolPtr(sym_loc);
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

            sym.n_desc = MachO.N_DEAD;

            var inner_sym_it = Atom.getInnerSymbolsIterator(macho_file, atom_index);
            while (inner_sym_it.next()) |inner| {
                const inner_sym = macho_file.getSymbolPtr(inner);
                inner_sym.n_desc = MachO.N_DEAD;
            }

            if (Atom.getSectionAlias(macho_file, atom_index)) |alias| {
                const alias_sym = macho_file.getSymbolPtr(alias);
                alias_sym.n_desc = MachO.N_DEAD;
            }
        }
    }
}
