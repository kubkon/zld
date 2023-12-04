pub fn gcAtoms(macho_file: *MachO) !void {
    var roots = std.ArrayList(*Atom).init(macho_file.base.allocator);
    defer roots.deinit();
    try collectRoots(&roots, macho_file);
    mark(roots.items, macho_file);
}

fn collectRoots(roots: *std.ArrayList(*Atom), macho_file: *MachO) !void {
    for (macho_file.objects.items) |index| {
        const object = macho_file.getFile(index).?.object;
        for (object.symbols.items) |sym_index| {
            const sym = macho_file.getSymbol(sym_index);
            const file = sym.getFile(macho_file) orelse continue;
            if (file.getIndex() != index) continue;
            const nlist = sym.getNlist(macho_file);
            if (nlist.n_desc & N_NO_DEAD_STRIP != 0 or macho_file.options.dylib and sym.flags.@"export")
                try markSymbol(sym, roots, macho_file);
        }

        for (object.atoms.items) |atom_index| {
            const atom = macho_file.getAtom(atom_index).?;
            const isec = atom.getInputSection(macho_file);
            switch (isec.type()) {
                macho.S_MOD_INIT_FUNC_POINTERS,
                macho.S_MOD_TERM_FUNC_POINTERS,
                => if (markAtom(atom)) try roots.append(atom),

                else => if (isec.isDontDeadStrip() and markAtom(atom)) {
                    try roots.append(atom);
                },
            }
        }

        for (object.unwind_records.items) |cu_index| {
            const cu = macho_file.getUnwindRecord(cu_index);
            if (!cu.alive) continue;
            if (cu.getFde(macho_file)) |fde| {
                if (fde.getCie(macho_file).getPersonality(macho_file)) |sym| try markSymbol(sym, roots, macho_file);
            } else if (cu.getPersonality(macho_file)) |sym| try markSymbol(sym, roots, macho_file);
        }
    }

    for (macho_file.undefined_symbols.items) |sym_index| {
        const sym = macho_file.getSymbol(sym_index);
        try markSymbol(sym, roots, macho_file);
    }
}

fn markSymbol(sym: *Symbol, roots: *std.ArrayList(*Atom), macho_file: *MachO) !void {
    const atom = sym.getAtom(macho_file) orelse return;
    if (markAtom(atom)) try roots.append(atom);
}

fn markAtom(atom: *Atom) bool {
    const already_visited = atom.flags.visited;
    atom.flags.visited = true;
    return atom.flags.alive and !already_visited;
}

fn mark(roots: []*Atom, macho_file: *MachO) void {
    for (roots) |root| {
        markLive(root, macho_file);
    }

    var loop: bool = true;
    while (loop) {
        loop = false;

        for (macho_file.objects.items) |index| {
            const object = macho_file.getFile(index).?.object;
            for (object.atoms.items) |atom_index| {
                const atom = macho_file.getAtom(atom_index).?;
                const isec = atom.getInputSection(macho_file);
                if (isec.isDontDeadStripIfReferencesLive() and !atom.flags.alive and refersLive(atom, macho_file)) {
                    markLive(atom, macho_file);
                    loop = true;
                }
            }
        }
    }
}

fn markLive(atom: *Atom, macho_file: *MachO) void {
    assert(atom.flags.visited);
    atom.flags.alive = true;
    track_live_log.debug("{}marking live atom({d},{s})", .{
        track_live_level,
        atom.atom_index,
        atom.getName(macho_file),
    });

    if (build_options.enable_logging)
        track_live_level.incr();

    for (atom.getRelocs(macho_file)) |rel| {
        const target_atom = switch (rel.tag) {
            .local => rel.getTargetAtom(macho_file),
            .@"extern" => rel.getTargetSymbol(macho_file).getAtom(macho_file),
        };
        if (target_atom) |ta| {
            if (markAtom(ta)) markLive(ta, macho_file);
        }
    }

    for (atom.getUnwindRecords(macho_file)) |cu_index| {
        const cu = macho_file.getUnwindRecord(cu_index);
        const cu_atom = cu.getAtom(macho_file);
        if (markAtom(cu_atom)) markLive(cu_atom, macho_file);

        if (cu.getLsdaAtom(macho_file)) |lsda| {
            if (markAtom(lsda)) markLive(lsda, macho_file);
        }
        if (cu.getFde(macho_file)) |fde| {
            const fde_atom = fde.getAtom(macho_file);
            if (markAtom(fde_atom)) markLive(fde_atom, macho_file);

            if (fde.getLsdaAtom(macho_file)) |lsda| {
                if (markAtom(lsda)) markLive(lsda, macho_file);
            }
        }
    }
}

fn refersLive(atom: *Atom, macho_file: *MachO) bool {
    for (atom.getRelocs(macho_file)) |rel| {
        const target_atom = switch (rel.tag) {
            .local => rel.getTargetAtom(macho_file),
            .@"extern" => rel.getTargetSymbol(macho_file).getAtom(macho_file),
        };
        if (target_atom) |ta| {
            if (ta.flags.alive) return true;
        }
    }
    return false;
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

// TODO upstream
const N_NO_DEAD_STRIP: u16 = macho.N_DESC_DISCARDED;

// pub fn gcAtoms(macho_file: *MachO, resolver: *const SymbolResolver) !void {
//     const tracy = trace(@src());
//     defer tracy.end();

//     const gpa = macho_file.base.allocator;

//     var arena = std.heap.ArenaAllocator.init(gpa);
//     defer arena.deinit();

//     var roots = AtomTable.init(arena.allocator());
//     try roots.ensureUnusedCapacity(@as(u32, @intCast(macho_file.globals.items.len)));

//     var alive = AtomTable.init(arena.allocator());
//     try alive.ensureTotalCapacity(@as(u32, @intCast(macho_file.atoms.items.len)));

//     try collectRoots(macho_file, &roots, resolver);
//     try mark(macho_file, roots, &alive);
//     prune(macho_file, alive);
// }

// fn addRoot(macho_file: *MachO, roots: *AtomTable, file: u32, sym_loc: SymbolWithLoc) !void {
//     const sym = macho_file.getSymbol(sym_loc);
//     assert(!sym.undf());
//     const object = &macho_file.objects.items[file];
//     const atom_index = object.getAtomIndexForSymbol(sym_loc.sym_index).?; // panic here means fatal error
//     log.debug("root(ATOM({d}, %{d}, {d}))", .{
//         atom_index,
//         macho_file.getAtom(atom_index).sym_index,
//         file,
//     });
//     _ = try roots.getOrPut(atom_index);
// }

// fn collectRoots(macho_file: *MachO, roots: *AtomTable, resolver: *const SymbolResolver) !void {
//     const tracy = trace(@src());
//     defer tracy.end();

//     log.debug("collecting roots", .{});

//     if (macho_file.options.dylib) {

//         // Add exports as GC roots
//         for (macho_file.globals.items) |global| {
//             const sym = macho_file.getSymbol(global);
//             if (sym.undf()) continue;

//             if (global.getFile()) |file| {
//                 try addRoot(macho_file, roots, file, global);
//             }
//         }
//     } else {
//         // Add entrypoint as GC root
//         const global: SymbolWithLoc = macho_file.getEntryPoint();
//         if (global.getFile()) |file| {
//             try addRoot(macho_file, roots, file, global);
//         } else {
//             assert(macho_file.getSymbol(global).undf()); // Stub as our entrypoint is in a dylib.
//         }
//     }

//     // Add all symbols force-defined by the user.
//     for (macho_file.options.force_undefined_symbols) |sym_name| {
//         const global_index = resolver.table.get(sym_name).?;
//         const global = macho_file.globals.items[global_index];
//         const sym = macho_file.getSymbol(global);
//         assert(!sym.undf());
//         try addRoot(macho_file, roots, global.getFile().?, global);
//     }

//     for (macho_file.objects.items) |object| {
//         const has_subsections = object.header.flags & macho.MH_SUBSECTIONS_VIA_SYMBOLS != 0;

//         for (object.atoms.items) |atom_index| {
//             const is_gc_root = blk: {
//                 // Modelled after ld64 which treats each object file compiled without MH_SUBSECTIONS_VIA_SYMBOLS
//                 // as a root.
//                 if (!has_subsections) break :blk true;

//                 const atom = macho_file.getAtom(atom_index);
//                 const sect_id = if (object.getSourceSymbol(atom.sym_index)) |source_sym|
//                     source_sym.n_sect - 1
//                 else sect_id: {
//                     const nbase = @as(u32, @intCast(object.in_symtab.?.len));
//                     const sect_id = @as(u8, @intCast(atom.sym_index - nbase));
//                     break :sect_id sect_id;
//                 };
//                 const source_sect = object.getSourceSection(sect_id);
//                 if (source_sect.isDontDeadStrip()) break :blk true;
//                 switch (source_sect.type()) {
//                     macho.S_MOD_INIT_FUNC_POINTERS,
//                     macho.S_MOD_TERM_FUNC_POINTERS,
//                     => break :blk true,
//                     else => break :blk false,
//                 }
//             };
//             if (is_gc_root) {
//                 _ = try roots.getOrPut(atom_index);

//                 log.debug("root(ATOM({d}, %{d}, {?d}))", .{
//                     atom_index,
//                     macho_file.getAtom(atom_index).sym_index,
//                     macho_file.getAtom(atom_index).getFile(),
//                 });
//             }
//         }
//     }
// }

// fn markLive(macho_file: *MachO, atom_index: AtomIndex, alive: *AtomTable) void {
//     const tracy = trace(@src());
//     defer tracy.end();

//     if (alive.contains(atom_index)) return;

//     const atom = macho_file.getAtom(atom_index);
//     const sym_loc = atom.getSymbolWithLoc();

//     log.debug("mark(ATOM({d}, %{d}, {?d}))", .{ atom_index, sym_loc.sym_index, sym_loc.getFile() });

//     alive.putAssumeCapacityNoClobber(atom_index, {});

//     macho_file.logAtom(atom_index, log);

//     const cpu_arch = macho_file.options.cpu_arch.?;

//     const sym = macho_file.getSymbol(sym_loc);
//     const header = macho_file.sections.items(.header)[sym.n_sect - 1];
//     if (header.isZerofill()) return;

//     const code = Atom.getAtomCode(macho_file, atom_index);
//     const relocs = Atom.getAtomRelocs(macho_file, atom_index);
//     const ctx = Atom.getRelocContext(macho_file, atom_index);

//     for (relocs) |rel| {
//         const target = switch (cpu_arch) {
//             .aarch64 => switch (@as(macho.reloc_type_arm64, @enumFromInt(rel.r_type))) {
//                 .ARM64_RELOC_ADDEND => continue,
//                 else => Atom.parseRelocTarget(macho_file, .{
//                     .object_id = atom.getFile().?,
//                     .rel = rel,
//                     .code = code,
//                     .base_offset = ctx.base_offset,
//                     .base_addr = ctx.base_addr,
//                 }),
//             },
//             .x86_64 => Atom.parseRelocTarget(macho_file, .{
//                 .object_id = atom.getFile().?,
//                 .rel = rel,
//                 .code = code,
//                 .base_offset = ctx.base_offset,
//                 .base_addr = ctx.base_addr,
//             }),
//             else => unreachable,
//         };
//         const target_sym = macho_file.getSymbol(target);

//         if (target_sym.undf()) continue;
//         if (target.getFile() == null) {
//             const target_sym_name = macho_file.getSymbolName(target);
//             if (mem.eql(u8, "__mh_execute_header", target_sym_name)) continue;
//             if (mem.eql(u8, "___dso_handle", target_sym_name)) continue;

//             unreachable; // referenced symbol not found
//         }

//         const object = macho_file.objects.items[target.getFile().?];
//         const target_atom_index = object.getAtomIndexForSymbol(target.sym_index).?;
//         log.debug("  following ATOM({d}, %{d}, {?d})", .{
//             target_atom_index,
//             macho_file.getAtom(target_atom_index).sym_index,
//             macho_file.getAtom(target_atom_index).getFile(),
//         });

//         markLive(macho_file, target_atom_index, alive);
//     }
// }

// fn refersLive(macho_file: *MachO, atom_index: AtomIndex, alive: AtomTable) bool {
//     const tracy = trace(@src());
//     defer tracy.end();

//     const atom = macho_file.getAtom(atom_index);
//     const sym_loc = atom.getSymbolWithLoc();

//     log.debug("refersLive(ATOM({d}, %{d}, {?d}))", .{
//         atom_index,
//         sym_loc.sym_index,
//         sym_loc.getFile(),
//     });

//     const cpu_arch = macho_file.options.cpu_arch.?;

//     const sym = macho_file.getSymbol(sym_loc);
//     const header = macho_file.sections.items(.header)[sym.n_sect - 1];
//     assert(!header.isZerofill());

//     const code = Atom.getAtomCode(macho_file, atom_index);
//     const relocs = Atom.getAtomRelocs(macho_file, atom_index);
//     const ctx = Atom.getRelocContext(macho_file, atom_index);

//     for (relocs) |rel| {
//         const target = switch (cpu_arch) {
//             .aarch64 => switch (@as(macho.reloc_type_arm64, @enumFromInt(rel.r_type))) {
//                 .ARM64_RELOC_ADDEND => continue,
//                 else => Atom.parseRelocTarget(macho_file, .{
//                     .object_id = atom.getFile().?,
//                     .rel = rel,
//                     .code = code,
//                     .base_offset = ctx.base_offset,
//                     .base_addr = ctx.base_addr,
//                 }),
//             },
//             .x86_64 => Atom.parseRelocTarget(macho_file, .{
//                 .object_id = atom.getFile().?,
//                 .rel = rel,
//                 .code = code,
//                 .base_offset = ctx.base_offset,
//                 .base_addr = ctx.base_addr,
//             }),
//             else => unreachable,
//         };

//         const object = macho_file.objects.items[target.getFile().?];
//         const target_atom_index = object.getAtomIndexForSymbol(target.sym_index) orelse {
//             log.debug("atom for symbol '{s}' not found; skipping...", .{macho_file.getSymbolName(target)});
//             continue;
//         };
//         if (alive.contains(target_atom_index)) {
//             if (alive.contains(target_atom_index)) {
//                 log.debug("  refers live ATOM({d}, %{d}, {?d})", .{
//                     target_atom_index,
//                     macho_file.getAtom(target_atom_index).sym_index,
//                     macho_file.getAtom(target_atom_index).getFile(),
//                 });
//                 return true;
//             }
//         }
//     }

//     return false;
// }

// fn mark(macho_file: *MachO, roots: AtomTable, alive: *AtomTable) !void {
//     const tracy = trace(@src());
//     defer tracy.end();

//     var it = roots.keyIterator();
//     while (it.next()) |root| {
//         markLive(macho_file, root.*, alive);
//     }

//     var loop: bool = true;
//     while (loop) {
//         loop = false;

//         for (macho_file.objects.items) |object| {
//             for (object.atoms.items) |atom_index| {
//                 if (alive.contains(atom_index)) continue;

//                 const atom = macho_file.getAtom(atom_index);
//                 const sect_id = if (object.getSourceSymbol(atom.sym_index)) |source_sym|
//                     source_sym.n_sect - 1
//                 else blk: {
//                     const nbase = @as(u32, @intCast(object.in_symtab.?.len));
//                     const sect_id = @as(u8, @intCast(atom.sym_index - nbase));
//                     break :blk sect_id;
//                 };
//                 const source_sect = object.getSourceSection(sect_id);

//                 if (source_sect.isDontDeadStripIfReferencesLive()) {
//                     if (refersLive(macho_file, atom_index, alive.*)) {
//                         markLive(macho_file, atom_index, alive);
//                         loop = true;
//                     }
//                 }
//             }
//         }
//     }

//     for (macho_file.objects.items, 0..) |_, object_id| {
//         // Traverse unwind and eh_frame records noting if the source symbol has been marked, and if so,
//         // marking all references as live.
//         try markUnwindRecords(macho_file, @as(u32, @intCast(object_id)), alive);
//     }
// }

// fn prune(macho_file: *MachO, alive: AtomTable) void {
//     const tracy = trace(@src());
//     defer tracy.end();

//     log.debug("pruning dead atoms", .{});
//     for (macho_file.objects.items) |*object| {
//         var i: usize = 0;
//         while (i < object.atoms.items.len) {
//             const atom_index = object.atoms.items[i];
//             if (alive.contains(atom_index)) {
//                 i += 1;
//                 continue;
//             }

//             const atom = macho_file.getAtom(atom_index);
//             const sym_loc = atom.getSymbolWithLoc();

//             log.debug("prune(ATOM({d}, %{d}, {?d}))", .{
//                 atom_index,
//                 sym_loc.sym_index,
//                 sym_loc.getFile(),
//             });
//             log.debug("  {s} in {s}", .{ macho_file.getSymbolName(sym_loc), object.name });

//             const sym = macho_file.getSymbolPtr(sym_loc);
//             const sect_id = sym.n_sect - 1;
//             var section = macho_file.sections.get(sect_id);
//             section.header.size -= atom.size;

//             if (atom.prev_index) |prev_index| {
//                 const prev = macho_file.getAtomPtr(prev_index);
//                 prev.next_index = atom.next_index;
//             } else {
//                 if (atom.next_index) |next_index| {
//                     section.first_atom_index = next_index;
//                 }
//             }
//             if (atom.next_index) |next_index| {
//                 const next = macho_file.getAtomPtr(next_index);
//                 next.prev_index = atom.prev_index;
//             } else {
//                 if (atom.prev_index) |prev_index| {
//                     section.last_atom_index = prev_index;
//                 } else {
//                     assert(section.header.size == 0);
//                     section.first_atom_index = 0;
//                     section.last_atom_index = 0;
//                 }
//             }

//             macho_file.sections.set(sect_id, section);
//             _ = object.atoms.swapRemove(i);

//             sym.n_desc = MachO.N_DEAD;

//             var inner_sym_it = Atom.getInnerSymbolsIterator(macho_file, atom_index);
//             while (inner_sym_it.next()) |inner| {
//                 const inner_sym = macho_file.getSymbolPtr(inner);
//                 inner_sym.n_desc = MachO.N_DEAD;
//             }

//             if (Atom.getSectionAlias(macho_file, atom_index)) |alias| {
//                 const alias_sym = macho_file.getSymbolPtr(alias);
//                 alias_sym.n_desc = MachO.N_DEAD;
//             }
//         }
//     }
// }

const assert = std.debug.assert;
const build_options = @import("build_options");
const log = std.log.scoped(.dead_strip);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const trace = @import("../tracy.zig").trace;
const track_live_log = std.log.scoped(.dead_strip_track_live);
const std = @import("std");

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const MachO = @import("../MachO.zig");
const Symbol = @import("Symbol.zig");
