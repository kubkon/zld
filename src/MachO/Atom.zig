const Atom = @This();

const std = @import("std");
const build_options = @import("build_options");
const aarch64 = @import("../aarch64.zig");
const assert = std.debug.assert;
const log = std.log.scoped(.atom);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const trace = @import("../tracy.zig").trace;

const Allocator = mem.Allocator;
const Arch = std.Target.Cpu.Arch;
const AtomIndex = MachO.AtomIndex;
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const SymbolWithLoc = MachO.SymbolWithLoc;

const dis_x86_64 = @import("dis_x86_64");
const Disassembler = dis_x86_64.Disassembler;
const Instruction = dis_x86_64.Instruction;
const RegisterOrMemory = dis_x86_64.RegisterOrMemory;

/// Each decl always gets a local symbol with the fully qualified name.
/// The vaddr and size are found here directly.
/// The file offset is found by computing the vaddr offset from the section vaddr
/// the symbol references, and adding that to the file offset of the section.
/// If this field is 0, it means the codegen size = 0 and there is no symbol or
/// offset table entry.
sym_index: u32,

/// If this Atom references a subsection in an Object file, `nsyms_trailing`
/// tells how many symbols trailing `sym_index` fall within this Atom's address
/// range.
inner_sym_index: u32,
inner_nsyms_trailing: u32,

/// -1 means symbol defined by the linker.
/// Otherwise, it is the index into appropriate object file.
file: i32,

/// Size and alignment of this atom
/// Unlike in Elf, we need to store the size of this symbol as part of
/// the atom since macho.nlist_64 lacks this information.
size: u64,

/// Alignment of this atom as a power of 2.
/// For instance, aligmment of 0 should be read as 2^0 = 1 byte aligned.
alignment: u32,

/// Points to the previous and next neighbours
next_index: ?AtomIndex,
prev_index: ?AtomIndex,

pub const empty = Atom{
    .sym_index = 0,
    .inner_sym_index = 0,
    .inner_nsyms_trailing = 0,
    .file = -1,
    .size = 0,
    .alignment = 0,
    .prev_index = null,
    .next_index = null,
};

pub inline fn getFile(self: Atom) ?u31 {
    if (self.file == -1) return null;
    return @intCast(u31, self.file);
}

pub inline fn getSymbolWithLoc(self: Atom) SymbolWithLoc {
    return .{
        .sym_index = self.sym_index,
        .file = self.file,
    };
}

const InnerSymIterator = struct {
    sym_index: u32,
    count: u32,
    file: i32,

    pub fn next(it: *@This()) ?SymbolWithLoc {
        if (it.count == 0) return null;
        const res = SymbolWithLoc{ .sym_index = it.sym_index, .file = it.file };
        it.sym_index += 1;
        it.count -= 1;
        return res;
    }
};

pub fn getInnerSymbolsIterator(macho_file: *MachO, atom_index: AtomIndex) InnerSymIterator {
    const atom = macho_file.getAtom(atom_index);
    assert(atom.getFile() != null);
    return .{
        .sym_index = atom.inner_sym_index,
        .count = atom.inner_nsyms_trailing,
        .file = atom.file,
    };
}

pub fn getSectionAlias(macho_file: *MachO, atom_index: AtomIndex) ?SymbolWithLoc {
    const atom = macho_file.getAtom(atom_index);
    assert(atom.getFile() != null);

    const object = macho_file.objects.items[atom.getFile().?];
    const nbase = @intCast(u32, object.in_symtab.?.len);
    const ntotal = @intCast(u32, object.symtab.len);
    var sym_index: u32 = nbase;
    while (sym_index < ntotal) : (sym_index += 1) {
        if (object.getAtomIndexForSymbol(sym_index)) |other_atom_index| {
            if (other_atom_index == atom_index) return SymbolWithLoc{
                .sym_index = sym_index,
                .file = atom.file,
            };
        }
    }
    return null;
}

pub fn calcInnerSymbolOffset(macho_file: *MachO, atom_index: AtomIndex, sym_index: u32) u64 {
    const atom = macho_file.getAtom(atom_index);
    assert(atom.getFile() != null);

    if (atom.sym_index == sym_index) return 0;

    const object = macho_file.objects.items[atom.getFile().?];
    const source_sym = object.getSourceSymbol(sym_index).?;
    const base_addr = if (object.getSourceSymbol(atom.sym_index)) |sym|
        sym.n_value
    else blk: {
        const nbase = @intCast(u32, object.in_symtab.?.len);
        const sect_id = @intCast(u16, atom.sym_index - nbase);
        const source_sect = object.getSourceSection(sect_id);
        break :blk source_sect.addr;
    };
    return source_sym.n_value - base_addr;
}

pub fn scanAtomRelocs(
    macho_file: *MachO,
    atom_index: AtomIndex,
    relocs: []align(1) const macho.relocation_info,
    reverse_lookup: []u32,
) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const arch = macho_file.options.target.cpu_arch.?;
    const atom = macho_file.getAtom(atom_index);
    assert(atom.getFile() != null); // synthetic atoms do not have relocs

    return switch (arch) {
        .aarch64 => scanAtomRelocsArm64(macho_file, atom_index, relocs, reverse_lookup),
        .x86_64 => scanAtomRelocsX86(macho_file, atom_index, relocs, reverse_lookup),
        else => unreachable,
    };
}

const RelocContext = struct {
    base_addr: u64 = 0,
    base_offset: i32 = 0,
};

pub fn getRelocContext(macho_file: *MachO, atom_index: AtomIndex) RelocContext {
    const atom = macho_file.getAtom(atom_index);
    assert(atom.getFile() != null); // synthetic atoms do not have relocs

    const object = macho_file.objects.items[atom.getFile().?];
    if (object.getSourceSymbol(atom.sym_index)) |source_sym| {
        const source_sect = object.getSourceSection(source_sym.n_sect - 1);
        return .{
            .base_addr = source_sect.addr,
            .base_offset = @intCast(i32, source_sym.n_value - source_sect.addr),
        };
    }
    const nbase = @intCast(u32, object.in_symtab.?.len);
    const sect_id = @intCast(u16, atom.sym_index - nbase);
    const source_sect = object.getSourceSection(sect_id);
    return .{
        .base_addr = source_sect.addr,
        .base_offset = 0,
    };
}

pub fn parseRelocTarget(
    macho_file: *MachO,
    atom_index: AtomIndex,
    rel: macho.relocation_info,
    reverse_lookup: []u32,
) MachO.SymbolWithLoc {
    const tracy = trace(@src());
    defer tracy.end();

    const atom = macho_file.getAtom(atom_index);
    const object = &macho_file.objects.items[atom.getFile().?];

    if (rel.r_extern == 0) {
        const sect_id = @intCast(u8, rel.r_symbolnum - 1);
        const ctx = getRelocContext(macho_file, atom_index);
        const atom_code = getAtomCode(macho_file, atom_index);
        const rel_offset = @intCast(u32, rel.r_address - ctx.base_offset);

        const address_in_section = if (rel.r_pcrel == 0) blk: {
            break :blk if (rel.r_length == 3)
                mem.readIntLittle(i64, atom_code[rel_offset..][0..8])
            else
                mem.readIntLittle(i32, atom_code[rel_offset..][0..4]);
        } else blk: {
            const correction: u3 = switch (@intToEnum(macho.reloc_type_x86_64, rel.r_type)) {
                .X86_64_RELOC_SIGNED => 0,
                .X86_64_RELOC_SIGNED_1 => 1,
                .X86_64_RELOC_SIGNED_2 => 2,
                .X86_64_RELOC_SIGNED_4 => 4,
                else => unreachable,
            };
            const addend = mem.readIntLittle(i32, atom_code[rel_offset..][0..4]);
            const target_address = @intCast(i64, ctx.base_addr) + rel.r_address + 4 + correction + addend;
            break :blk target_address;
        };

        // Find containing atom
        const Predicate = struct {
            addr: i64,

            pub fn predicate(pred: @This(), other: i64) bool {
                return if (other == -1) true else other > pred.addr;
            }
        };

        if (object.source_section_index_lookup[sect_id] > -1) {
            const first_sym_index = @intCast(usize, object.source_section_index_lookup[sect_id]);
            const target_sym_index = MachO.lsearch(i64, object.source_address_lookup[first_sym_index..], Predicate{
                .addr = address_in_section,
            });

            if (target_sym_index > 0) {
                return MachO.SymbolWithLoc{
                    .sym_index = @intCast(u32, first_sym_index + target_sym_index - 1),
                    .file = atom.file,
                };
            }
        }

        // Start of section is not contained anywhere, return synthetic atom.
        const sym_index = object.getSectionAliasSymbolIndex(sect_id);
        return MachO.SymbolWithLoc{ .sym_index = sym_index, .file = atom.file };
    }

    const sym_index = reverse_lookup[rel.r_symbolnum];
    const sym_loc = MachO.SymbolWithLoc{
        .sym_index = sym_index,
        .file = atom.file,
    };
    const sym = macho_file.getSymbol(sym_loc);

    if (sym.sect() and !sym.ext()) {
        return sym_loc;
    } else if (object.globals_lookup[sym_index] > -1) {
        const global_index = @intCast(u32, object.globals_lookup[sym_index]);
        return macho_file.globals.items[global_index];
    } else return sym_loc;
}

pub fn getRelocTargetAtomIndex(macho_file: *MachO, rel: macho.relocation_info, target: SymbolWithLoc) ?AtomIndex {
    const tracy = trace(@src());
    defer tracy.end();

    const is_via_got = got: {
        switch (macho_file.options.target.cpu_arch.?) {
            .aarch64 => break :got switch (@intToEnum(macho.reloc_type_arm64, rel.r_type)) {
                .ARM64_RELOC_GOT_LOAD_PAGE21,
                .ARM64_RELOC_GOT_LOAD_PAGEOFF12,
                .ARM64_RELOC_POINTER_TO_GOT,
                => true,
                else => false,
            },
            .x86_64 => break :got switch (@intToEnum(macho.reloc_type_x86_64, rel.r_type)) {
                .X86_64_RELOC_GOT, .X86_64_RELOC_GOT_LOAD => true,
                else => false,
            },
            else => unreachable,
        }
    };

    if (is_via_got) {
        return macho_file.getGotAtomIndexForSymbol(target).?; // panic means fatal error
    }
    if (macho_file.getStubsAtomIndexForSymbol(target)) |stubs_atom| return stubs_atom;
    if (macho_file.getTlvPtrAtomIndexForSymbol(target)) |tlv_ptr_atom| return tlv_ptr_atom;

    if (target.getFile() == null) {
        const target_sym_name = macho_file.getSymbolName(target);
        if (mem.eql(u8, "__mh_execute_header", target_sym_name)) return null;
        if (mem.eql(u8, "___dso_handle", target_sym_name)) return null;

        unreachable; // referenced symbol not found
    }

    const object = macho_file.objects.items[target.getFile().?];
    return object.getAtomIndexForSymbol(target.sym_index);
}

fn scanAtomRelocsArm64(
    macho_file: *MachO,
    atom_index: AtomIndex,
    relocs: []align(1) const macho.relocation_info,
    reverse_lookup: []u32,
) !void {
    for (relocs) |rel| {
        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);

        switch (rel_type) {
            .ARM64_RELOC_ADDEND, .ARM64_RELOC_SUBTRACTOR => continue,
            else => {},
        }

        if (rel.r_extern == 0) continue;

        const atom = macho_file.getAtom(atom_index);
        const object = &macho_file.objects.items[atom.getFile().?];
        const sym_index = reverse_lookup[rel.r_symbolnum];
        const sym_loc = MachO.SymbolWithLoc{
            .sym_index = sym_index,
            .file = atom.file,
        };
        const sym = macho_file.getSymbol(sym_loc);

        if (sym.sect() and !sym.ext()) continue;

        const target = if (object.globals_lookup[sym_index] > -1) blk: {
            const global_index = @intCast(u32, object.globals_lookup[sym_index]);
            break :blk macho_file.globals.items[global_index];
        } else sym_loc;

        switch (rel_type) {
            .ARM64_RELOC_BRANCH26 => {
                // TODO rewrite relocation
                try addStub(macho_file, target);
            },
            .ARM64_RELOC_GOT_LOAD_PAGE21,
            .ARM64_RELOC_GOT_LOAD_PAGEOFF12,
            .ARM64_RELOC_POINTER_TO_GOT,
            => {
                // TODO rewrite relocation
                try addGotEntry(macho_file, target);
            },
            .ARM64_RELOC_TLVP_LOAD_PAGE21,
            .ARM64_RELOC_TLVP_LOAD_PAGEOFF12,
            => {
                try addTlvPtrEntry(macho_file, target);
            },
            else => {},
        }
    }
}

fn scanAtomRelocsX86(
    macho_file: *MachO,
    atom_index: AtomIndex,
    relocs: []align(1) const macho.relocation_info,
    reverse_lookup: []u32,
) !void {
    for (relocs) |rel| {
        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);

        switch (rel_type) {
            .X86_64_RELOC_SUBTRACTOR => continue,
            else => {},
        }

        if (rel.r_extern == 0) continue;

        const atom = macho_file.getAtom(atom_index);
        const object = &macho_file.objects.items[atom.getFile().?];
        const sym_index = reverse_lookup[rel.r_symbolnum];
        const sym_loc = MachO.SymbolWithLoc{
            .sym_index = sym_index,
            .file = atom.file,
        };
        const sym = macho_file.getSymbol(sym_loc);

        if (sym.sect() and !sym.ext()) continue;

        const target = if (object.globals_lookup[sym_index] > -1) blk: {
            const global_index = @intCast(u32, object.globals_lookup[sym_index]);
            break :blk macho_file.globals.items[global_index];
        } else sym_loc;

        switch (rel_type) {
            .X86_64_RELOC_BRANCH => {
                // TODO rewrite relocation
                try addStub(macho_file, target);
            },
            .X86_64_RELOC_GOT, .X86_64_RELOC_GOT_LOAD => {
                // TODO rewrite relocation
                try addGotEntry(macho_file, target);
            },
            .X86_64_RELOC_TLV => {
                try addTlvPtrEntry(macho_file, target);
            },
            else => {},
        }
    }
}

fn addTlvPtrEntry(macho_file: *MachO, target: MachO.SymbolWithLoc) !void {
    const target_sym = macho_file.getSymbol(target);
    if (!target_sym.undf()) return;
    if (macho_file.tlv_ptr_table.contains(target)) return;

    const gpa = macho_file.base.allocator;
    const atom_index = try macho_file.createTlvPtrAtom();
    const tlv_ptr_index = @intCast(u32, macho_file.tlv_ptr_entries.items.len);
    try macho_file.tlv_ptr_entries.append(gpa, .{
        .target = target,
        .atom_index = atom_index,
    });
    try macho_file.tlv_ptr_table.putNoClobber(gpa, target, tlv_ptr_index);
}

fn addGotEntry(macho_file: *MachO, target: MachO.SymbolWithLoc) !void {
    if (macho_file.got_table.contains(target)) return;
    const gpa = macho_file.base.allocator;
    const atom_index = try macho_file.createGotAtom();
    const got_index = @intCast(u32, macho_file.got_entries.items.len);
    try macho_file.got_entries.append(gpa, .{
        .target = target,
        .atom_index = atom_index,
    });
    try macho_file.got_table.putNoClobber(gpa, target, got_index);
}

fn addStub(macho_file: *MachO, target: MachO.SymbolWithLoc) !void {
    const target_sym = macho_file.getSymbol(target);
    if (!target_sym.undf()) return;
    if (macho_file.stubs_table.contains(target)) return;

    const gpa = macho_file.base.allocator;
    _ = try macho_file.createStubHelperAtom();
    _ = try macho_file.createLazyPointerAtom();
    const atom_index = try macho_file.createStubAtom();
    const stubs_index = @intCast(u32, macho_file.stubs.items.len);
    try macho_file.stubs.append(gpa, .{
        .target = target,
        .atom_index = atom_index,
    });
    try macho_file.stubs_table.putNoClobber(gpa, target, stubs_index);
}

pub fn resolveRelocs(
    macho_file: *MachO,
    atom_index: AtomIndex,
    atom_code: []u8,
    atom_relocs: []align(1) const macho.relocation_info,
    reverse_lookup: []u32,
) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const arch = macho_file.options.target.cpu_arch.?;
    const atom = macho_file.getAtom(atom_index);
    assert(atom.getFile() != null); // synthetic atoms do not have relocs

    log.debug("resolving relocations in ATOM(%{d}, '{s}')", .{
        atom.sym_index,
        macho_file.getSymbolName(atom.getSymbolWithLoc()),
    });

    const ctx = getRelocContext(macho_file, atom_index);

    return switch (arch) {
        .aarch64 => resolveRelocsArm64(macho_file, atom_index, atom_code, atom_relocs, reverse_lookup, ctx),
        .x86_64 => resolveRelocsX86(macho_file, atom_index, atom_code, atom_relocs, reverse_lookup, ctx),
        else => unreachable,
    };
}

pub fn getRelocTargetAddress(macho_file: *MachO, rel: macho.relocation_info, target: SymbolWithLoc, is_tlv: bool) !u64 {
    const target_atom_index = getRelocTargetAtomIndex(macho_file, rel, target) orelse {
        // If there is no atom for target, we still need to check for special, atom-less
        // symbols such as `___dso_handle`.
        const target_name = macho_file.getSymbolName(target);
        const atomless_sym = macho_file.getSymbol(target);
        log.debug("    | atomless target '{s}'", .{target_name});
        return atomless_sym.n_value;
    };
    const target_atom = macho_file.getAtom(target_atom_index);
    log.debug("    | target ATOM(%{d}, '{s}') in object({?})", .{
        target_atom.sym_index,
        macho_file.getSymbolName(target_atom.getSymbolWithLoc()),
        target_atom.file,
    });
    const target_sym = macho_file.getSymbol(target_atom.getSymbolWithLoc());
    assert(target_sym.n_desc != MachO.N_DEAD);

    // If `target` is contained within the target atom, pull its address value.
    const offset = if (target_atom.getFile() != null) blk: {
        const object = macho_file.objects.items[target_atom.getFile().?];
        break :blk if (object.getSourceSymbol(target.sym_index)) |_|
            Atom.calcInnerSymbolOffset(macho_file, target_atom_index, target.sym_index)
        else
            0; // section alias
    } else 0;
    const base_address: u64 = if (is_tlv) base_address: {
        // For TLV relocations, the value specified as a relocation is the displacement from the
        // TLV initializer (either value in __thread_data or zero-init in __thread_bss) to the first
        // defined TLV template init section in the following order:
        // * wrt to __thread_data if defined, then
        // * wrt to __thread_bss
        const sect_id: u16 = sect_id: {
            if (macho_file.getSectionByName("__DATA", "__thread_data")) |i| {
                break :sect_id i;
            } else if (macho_file.getSectionByName("__DATA", "__thread_bss")) |i| {
                break :sect_id i;
            } else {
                log.err("threadlocal variables present but no initializer sections found", .{});
                log.err("  __thread_data not found", .{});
                log.err("  __thread_bss not found", .{});
                return error.FailedToResolveRelocationTarget;
            }
        };
        break :base_address macho_file.sections.items(.header)[sect_id].addr;
    } else 0;
    return target_sym.n_value + offset - base_address;
}

fn resolveRelocsArm64(
    macho_file: *MachO,
    atom_index: AtomIndex,
    atom_code: []u8,
    atom_relocs: []align(1) const macho.relocation_info,
    reverse_lookup: []u32,
    context: RelocContext,
) !void {
    const atom = macho_file.getAtom(atom_index);
    const object = macho_file.objects.items[atom.getFile().?];

    var addend: ?i64 = null;
    var subtractor: ?SymbolWithLoc = null;

    for (atom_relocs) |rel| {
        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);

        switch (rel_type) {
            .ARM64_RELOC_ADDEND => {
                assert(addend == null);

                log.debug("  RELA({s}) @ {x} => {x}", .{ @tagName(rel_type), rel.r_address, rel.r_symbolnum });

                addend = rel.r_symbolnum;
                continue;
            },
            .ARM64_RELOC_SUBTRACTOR => {
                assert(subtractor == null);

                log.debug("  RELA({s}) @ {x} => %{d} in object({d})", .{
                    @tagName(rel_type),
                    rel.r_address,
                    rel.r_symbolnum,
                    atom.file,
                });

                subtractor = parseRelocTarget(macho_file, atom_index, rel, reverse_lookup);
                continue;
            },
            else => {},
        }

        const target = parseRelocTarget(macho_file, atom_index, rel, reverse_lookup);
        const rel_offset = @intCast(u32, rel.r_address - context.base_offset);

        log.debug("  RELA({s}) @ {x} => %{d} ('{s}') in object({?})", .{
            @tagName(rel_type),
            rel.r_address,
            target.sym_index,
            macho_file.getSymbolName(target),
            target.file,
        });

        const source_addr = blk: {
            const source_sym = macho_file.getSymbol(atom.getSymbolWithLoc());
            break :blk source_sym.n_value + rel_offset;
        };
        const is_tlv = is_tlv: {
            const source_sym = macho_file.getSymbol(atom.getSymbolWithLoc());
            const header = macho_file.sections.items(.header)[source_sym.n_sect - 1];
            break :is_tlv header.type() == macho.S_THREAD_LOCAL_VARIABLES;
        };
        const target_addr = try getRelocTargetAddress(macho_file, rel, target, is_tlv);

        log.debug("    | source_addr = 0x{x}", .{source_addr});

        switch (rel_type) {
            .ARM64_RELOC_BRANCH26 => {
                const actual_target = if (macho_file.getStubsAtomIndexForSymbol(target)) |stub_atom_index| inner: {
                    const stub_atom = macho_file.getAtom(stub_atom_index);
                    break :inner stub_atom.getSymbolWithLoc();
                } else target;
                log.debug("  source {s} (object({?})), target {s} (object({?}))", .{
                    macho_file.getSymbolName(atom.getSymbolWithLoc()),
                    atom.file,
                    macho_file.getSymbolName(target),
                    macho_file.getAtom(getRelocTargetAtomIndex(macho_file, rel, target).?).file,
                });

                const displacement = if (calcPcRelativeDisplacementArm64(
                    source_addr,
                    macho_file.getSymbol(actual_target).n_value,
                )) |disp| blk: {
                    log.debug("    | target_addr = 0x{x}", .{macho_file.getSymbol(actual_target).n_value});
                    break :blk disp;
                } else |_| blk: {
                    const thunk_index = macho_file.thunk_table.get(atom_index).?;
                    const thunk = macho_file.thunks.items[thunk_index];
                    const thunk_sym = macho_file.getSymbol(thunk.getTrampolineForSymbol(
                        macho_file,
                        actual_target,
                    ).?);
                    log.debug("    | target_addr = 0x{x}", .{thunk_sym.n_value});
                    break :blk try calcPcRelativeDisplacementArm64(source_addr, thunk_sym.n_value);
                };

                const code = atom_code[rel_offset..][0..4];
                var inst = aarch64.Instruction{
                    .unconditional_branch_immediate = mem.bytesToValue(meta.TagPayload(
                        aarch64.Instruction,
                        aarch64.Instruction.unconditional_branch_immediate,
                    ), code),
                };
                inst.unconditional_branch_immediate.imm26 = @truncate(u26, @bitCast(u28, displacement >> 2));
                mem.writeIntLittle(u32, code, inst.toU32());
            },

            .ARM64_RELOC_PAGE21,
            .ARM64_RELOC_GOT_LOAD_PAGE21,
            .ARM64_RELOC_TLVP_LOAD_PAGE21,
            => {
                const adjusted_target_addr = @intCast(u64, @intCast(i64, target_addr) + (addend orelse 0));

                log.debug("    | target_addr = 0x{x}", .{adjusted_target_addr});

                const pages = @bitCast(u21, calcNumberOfPages(source_addr, adjusted_target_addr));
                const code = atom_code[rel_offset..][0..4];
                var inst = aarch64.Instruction{
                    .pc_relative_address = mem.bytesToValue(meta.TagPayload(
                        aarch64.Instruction,
                        aarch64.Instruction.pc_relative_address,
                    ), code),
                };
                inst.pc_relative_address.immhi = @truncate(u19, pages >> 2);
                inst.pc_relative_address.immlo = @truncate(u2, pages);
                mem.writeIntLittle(u32, code, inst.toU32());
                addend = null;
            },

            .ARM64_RELOC_PAGEOFF12 => {
                const adjusted_target_addr = @intCast(u64, @intCast(i64, target_addr) + (addend orelse 0));

                log.debug("    | target_addr = 0x{x}", .{adjusted_target_addr});

                const code = atom_code[rel_offset..][0..4];
                if (isArithmeticOp(code)) {
                    const off = try calcPageOffset(adjusted_target_addr, .arithmetic);
                    var inst = aarch64.Instruction{
                        .add_subtract_immediate = mem.bytesToValue(meta.TagPayload(
                            aarch64.Instruction,
                            aarch64.Instruction.add_subtract_immediate,
                        ), code),
                    };
                    inst.add_subtract_immediate.imm12 = off;
                    mem.writeIntLittle(u32, code, inst.toU32());
                } else {
                    var inst = aarch64.Instruction{
                        .load_store_register = mem.bytesToValue(meta.TagPayload(
                            aarch64.Instruction,
                            aarch64.Instruction.load_store_register,
                        ), code),
                    };
                    const off = try calcPageOffset(adjusted_target_addr, switch (inst.load_store_register.size) {
                        0 => if (inst.load_store_register.v == 1) PageOffsetInstKind.load_store_128 else PageOffsetInstKind.load_store_8,
                        1 => .load_store_16,
                        2 => .load_store_32,
                        3 => .load_store_64,
                    });
                    inst.load_store_register.offset = off;
                    mem.writeIntLittle(u32, code, inst.toU32());
                }
                addend = null;
            },

            .ARM64_RELOC_GOT_LOAD_PAGEOFF12 => {
                const code = atom_code[rel_offset..][0..4];
                const adjusted_target_addr = @intCast(u64, @intCast(i64, target_addr) + (addend orelse 0));

                log.debug("    | target_addr = 0x{x}", .{adjusted_target_addr});

                const off = try calcPageOffset(adjusted_target_addr, .load_store_64);
                var inst: aarch64.Instruction = .{
                    .load_store_register = mem.bytesToValue(meta.TagPayload(
                        aarch64.Instruction,
                        aarch64.Instruction.load_store_register,
                    ), code),
                };
                inst.load_store_register.offset = off;
                mem.writeIntLittle(u32, code, inst.toU32());
                addend = null;
            },

            .ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => {
                const code = atom_code[rel_offset..][0..4];
                const adjusted_target_addr = @intCast(u64, @intCast(i64, target_addr) + (addend orelse 0));

                log.debug("    | target_addr = 0x{x}", .{adjusted_target_addr});

                const RegInfo = struct {
                    rd: u5,
                    rn: u5,
                    size: u2,
                };
                const reg_info: RegInfo = blk: {
                    if (isArithmeticOp(code)) {
                        const inst = mem.bytesToValue(meta.TagPayload(
                            aarch64.Instruction,
                            aarch64.Instruction.add_subtract_immediate,
                        ), code);
                        break :blk .{
                            .rd = inst.rd,
                            .rn = inst.rn,
                            .size = inst.sf,
                        };
                    } else {
                        const inst = mem.bytesToValue(meta.TagPayload(
                            aarch64.Instruction,
                            aarch64.Instruction.load_store_register,
                        ), code);
                        break :blk .{
                            .rd = inst.rt,
                            .rn = inst.rn,
                            .size = inst.size,
                        };
                    }
                };

                var inst = if (macho_file.tlv_ptr_table.contains(target)) aarch64.Instruction{
                    .load_store_register = .{
                        .rt = reg_info.rd,
                        .rn = reg_info.rn,
                        .offset = try calcPageOffset(adjusted_target_addr, .load_store_64),
                        .opc = 0b01,
                        .op1 = 0b01,
                        .v = 0,
                        .size = reg_info.size,
                    },
                } else aarch64.Instruction{
                    .add_subtract_immediate = .{
                        .rd = reg_info.rd,
                        .rn = reg_info.rn,
                        .imm12 = try calcPageOffset(adjusted_target_addr, .arithmetic),
                        .sh = 0,
                        .s = 0,
                        .op = 0,
                        .sf = @truncate(u1, reg_info.size),
                    },
                };
                mem.writeIntLittle(u32, code, inst.toU32());
                addend = null;
            },

            .ARM64_RELOC_POINTER_TO_GOT => {
                log.debug("    | target_addr = 0x{x}", .{target_addr});
                const result = math.cast(i32, @intCast(i64, target_addr) - @intCast(i64, source_addr)) orelse
                    return error.Overflow;
                mem.writeIntLittle(u32, atom_code[rel_offset..][0..4], @bitCast(u32, result));
            },

            .ARM64_RELOC_UNSIGNED => {
                var ptr_addend = if (rel.r_length == 3)
                    mem.readIntLittle(i64, atom_code[rel_offset..][0..8])
                else
                    mem.readIntLittle(i32, atom_code[rel_offset..][0..4]);

                if (rel.r_extern == 0) {
                    const base_addr = if (target.sym_index > object.source_address_lookup.len)
                        @intCast(i64, object.getSourceSection(@intCast(u16, rel.r_symbolnum - 1)).addr)
                    else
                        object.source_address_lookup[target.sym_index];
                    ptr_addend -= base_addr;
                }

                const result = blk: {
                    if (subtractor) |sub| {
                        const sym = macho_file.getSymbol(sub);
                        break :blk @intCast(i64, target_addr) - @intCast(i64, sym.n_value) + ptr_addend;
                    } else {
                        break :blk @intCast(i64, target_addr) + ptr_addend;
                    }
                };
                log.debug("    | target_addr = 0x{x}", .{result});

                if (rel.r_length == 3) {
                    mem.writeIntLittle(u64, atom_code[rel_offset..][0..8], @bitCast(u64, result));
                } else {
                    mem.writeIntLittle(u32, atom_code[rel_offset..][0..4], @truncate(u32, @bitCast(u64, result)));
                }

                subtractor = null;
            },

            .ARM64_RELOC_ADDEND => unreachable,
            .ARM64_RELOC_SUBTRACTOR => unreachable,
        }
    }
}

fn resolveRelocsX86(
    macho_file: *MachO,
    atom_index: AtomIndex,
    atom_code: []u8,
    atom_relocs: []align(1) const macho.relocation_info,
    reverse_lookup: []u32,
    context: RelocContext,
) !void {
    const atom = macho_file.getAtom(atom_index);
    const object = macho_file.objects.items[atom.getFile().?];

    var subtractor: ?SymbolWithLoc = null;

    for (atom_relocs) |rel| {
        const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);

        switch (rel_type) {
            .X86_64_RELOC_SUBTRACTOR => {
                assert(subtractor == null);

                log.debug("  RELA({s}) @ {x} => %{d} in object({d})", .{
                    @tagName(rel_type),
                    rel.r_address,
                    rel.r_symbolnum,
                    atom.file,
                });

                subtractor = parseRelocTarget(macho_file, atom_index, rel, reverse_lookup);
                continue;
            },
            else => {},
        }

        const target = parseRelocTarget(macho_file, atom_index, rel, reverse_lookup);
        const rel_offset = @intCast(u32, rel.r_address - context.base_offset);

        log.debug("  RELA({s}) @ {x} => %{d} in object({?})", .{
            @tagName(rel_type),
            rel.r_address,
            target.sym_index,
            target.file,
        });

        const source_addr = blk: {
            const source_sym = macho_file.getSymbol(atom.getSymbolWithLoc());
            break :blk source_sym.n_value + rel_offset;
        };
        const is_tlv = is_tlv: {
            const source_sym = macho_file.getSymbol(atom.getSymbolWithLoc());
            const header = macho_file.sections.items(.header)[source_sym.n_sect - 1];
            break :is_tlv header.type() == macho.S_THREAD_LOCAL_VARIABLES;
        };

        log.debug("    | source_addr = 0x{x}", .{source_addr});

        const target_addr = try getRelocTargetAddress(macho_file, rel, target, is_tlv);

        switch (rel_type) {
            .X86_64_RELOC_BRANCH => {
                const addend = mem.readIntLittle(i32, atom_code[rel_offset..][0..4]);
                const adjusted_target_addr = @intCast(u64, @intCast(i64, target_addr) + addend);

                log.debug("    | target_addr = 0x{x}", .{adjusted_target_addr});

                const disp = try calcPcRelativeDisplacementX86(source_addr, adjusted_target_addr, 0);
                mem.writeIntLittle(i32, atom_code[rel_offset..][0..4], disp);
            },

            .X86_64_RELOC_GOT,
            .X86_64_RELOC_GOT_LOAD,
            => {
                const addend = mem.readIntLittle(i32, atom_code[rel_offset..][0..4]);
                const adjusted_target_addr = @intCast(u64, @intCast(i64, target_addr) + addend);
                log.debug("    | target_addr = 0x{x}", .{adjusted_target_addr});
                const disp = try calcPcRelativeDisplacementX86(source_addr, adjusted_target_addr, 0);
                mem.writeIntLittle(i32, atom_code[rel_offset..][0..4], disp);
            },

            .X86_64_RELOC_TLV => {
                const addend = mem.readIntLittle(i32, atom_code[rel_offset..][0..4]);
                const adjusted_target_addr = @intCast(u64, @intCast(i64, target_addr) + addend);
                log.debug("    | target_addr = 0x{x}", .{adjusted_target_addr});
                const disp = try calcPcRelativeDisplacementX86(source_addr, adjusted_target_addr, 0);

                if (macho_file.tlv_ptr_table.get(target) == null) {
                    // We need to rewrite the opcode from movq to leaq.
                    var disassembler = Disassembler.init(atom_code[rel_offset - 3 ..]);
                    const inst = (try disassembler.next()) orelse unreachable;
                    assert(inst.enc == .rm);
                    assert(inst.tag == .mov);
                    const rm = inst.data.rm;
                    const dst = rm.reg;
                    const src = rm.reg_or_mem.mem;

                    var stream = std.io.fixedBufferStream(atom_code[rel_offset - 3 ..][0..7]);
                    const writer = stream.writer();

                    const new_inst = Instruction{
                        .tag = .lea,
                        .enc = .rm,
                        .data = Instruction.Data.rm(dst, RegisterOrMemory.mem(.{
                            .ptr_size = src.ptr_size,
                            .scale_index = src.scale_index,
                            .base = src.base,
                            .disp = disp,
                        })),
                    };
                    try new_inst.encode(writer);
                } else {
                    mem.writeIntLittle(i32, atom_code[rel_offset..][0..4], disp);
                }
            },

            .X86_64_RELOC_SIGNED,
            .X86_64_RELOC_SIGNED_1,
            .X86_64_RELOC_SIGNED_2,
            .X86_64_RELOC_SIGNED_4,
            => {
                const correction: u3 = switch (rel_type) {
                    .X86_64_RELOC_SIGNED => 0,
                    .X86_64_RELOC_SIGNED_1 => 1,
                    .X86_64_RELOC_SIGNED_2 => 2,
                    .X86_64_RELOC_SIGNED_4 => 4,
                    else => unreachable,
                };
                var addend = mem.readIntLittle(i32, atom_code[rel_offset..][0..4]) + correction;

                if (rel.r_extern == 0) {
                    const base_addr = if (target.sym_index > object.source_address_lookup.len)
                        @intCast(i64, object.getSourceSection(@intCast(u16, rel.r_symbolnum - 1)).addr)
                    else
                        object.source_address_lookup[target.sym_index];
                    addend += @intCast(i32, @intCast(i64, context.base_addr) + rel.r_address + 4 -
                        @intCast(i64, base_addr));
                }

                const adjusted_target_addr = @intCast(u64, @intCast(i64, target_addr) + addend);
                log.debug("    | target_addr = 0x{x}", .{adjusted_target_addr});

                const disp = try calcPcRelativeDisplacementX86(source_addr, adjusted_target_addr, correction);
                mem.writeIntLittle(i32, atom_code[rel_offset..][0..4], disp);
            },

            .X86_64_RELOC_UNSIGNED => {
                var addend = if (rel.r_length == 3)
                    mem.readIntLittle(i64, atom_code[rel_offset..][0..8])
                else
                    mem.readIntLittle(i32, atom_code[rel_offset..][0..4]);

                if (rel.r_extern == 0) {
                    const base_addr = if (target.sym_index > object.source_address_lookup.len)
                        @intCast(i64, object.getSourceSection(@intCast(u16, rel.r_symbolnum - 1)).addr)
                    else
                        object.source_address_lookup[target.sym_index];
                    addend -= base_addr;
                }

                const result = blk: {
                    if (subtractor) |sub| {
                        const sym = macho_file.getSymbol(sub);
                        break :blk @intCast(i64, target_addr) - @intCast(i64, sym.n_value) + addend;
                    } else {
                        break :blk @intCast(i64, target_addr) + addend;
                    }
                };
                log.debug("    | target_addr = 0x{x}", .{result});

                if (rel.r_length == 3) {
                    mem.writeIntLittle(u64, atom_code[rel_offset..][0..8], @bitCast(u64, result));
                } else {
                    mem.writeIntLittle(u32, atom_code[rel_offset..][0..4], @truncate(u32, @bitCast(u64, result)));
                }

                subtractor = null;
            },

            .X86_64_RELOC_SUBTRACTOR => unreachable,
        }
    }
}

inline fn isArithmeticOp(inst: *const [4]u8) bool {
    const group_decode = @truncate(u5, inst[3]);
    return ((group_decode >> 2) == 4);
}

pub fn getAtomCode(macho_file: *MachO, atom_index: AtomIndex) []const u8 {
    const atom = macho_file.getAtom(atom_index);
    assert(atom.getFile() != null); // Synthetic atom shouldn't need to inquire for code.
    const object = macho_file.objects.items[atom.getFile().?];
    const source_sym = object.getSourceSymbol(atom.sym_index) orelse {
        // If there was no matching symbol present in the source symtab, this means
        // we are dealing with either an entire section, or part of it, but also
        // starting at the beginning.
        const nbase = @intCast(u32, object.in_symtab.?.len);
        const sect_id = @intCast(u16, atom.sym_index - nbase);
        const source_sect = object.getSourceSection(sect_id);
        assert(!source_sect.isZerofill());
        const code = object.getSectionContents(source_sect);
        return code[0..atom.size];
    };
    const source_sect = object.getSourceSection(source_sym.n_sect - 1);
    assert(!source_sect.isZerofill());
    const offset = source_sym.n_value - source_sect.addr;
    const code = object.getSectionContents(source_sect);
    return code[offset..][0..atom.size];
}

pub fn getAtomRelocs(macho_file: *MachO, atom_index: AtomIndex) []align(1) const macho.relocation_info {
    const atom = macho_file.getAtom(atom_index);
    assert(atom.getFile() != null); // Synthetic atom shouldn't need to unique for relocs.
    const object = macho_file.objects.items[atom.getFile().?];
    const cache = object.relocs_lookup[atom.sym_index];

    const source_sect = if (object.getSourceSymbol(atom.sym_index)) |source_sym| blk: {
        const source_sect = object.getSourceSection(source_sym.n_sect - 1);
        assert(!source_sect.isZerofill());
        break :blk source_sect;
    } else blk: {
        // If there was no matching symbol present in the source symtab, this means
        // we are dealing with either an entire section, or part of it, but also
        // starting at the beginning.
        const nbase = @intCast(u32, object.in_symtab.?.len);
        const sect_id = @intCast(u16, atom.sym_index - nbase);
        const source_sect = object.getSourceSection(sect_id);
        assert(!source_sect.isZerofill());
        break :blk source_sect;
    };

    const relocs = object.getRelocs(source_sect);
    return relocs[cache.start..][0..cache.len];
}

pub fn calcPcRelativeDisplacementX86(source_addr: u64, target_addr: u64, correction: u3) error{Overflow}!i32 {
    const disp = @intCast(i64, target_addr) - @intCast(i64, source_addr + 4 + correction);
    return math.cast(i32, disp) orelse error.Overflow;
}

pub fn calcPcRelativeDisplacementArm64(source_addr: u64, target_addr: u64) error{Overflow}!i28 {
    const disp = @intCast(i64, target_addr) - @intCast(i64, source_addr);
    return math.cast(i28, disp) orelse error.Overflow;
}

pub fn calcNumberOfPages(source_addr: u64, target_addr: u64) i21 {
    const source_page = @intCast(i32, source_addr >> 12);
    const target_page = @intCast(i32, target_addr >> 12);
    const pages = @intCast(i21, target_page - source_page);
    return pages;
}

const PageOffsetInstKind = enum {
    arithmetic,
    load_store_8,
    load_store_16,
    load_store_32,
    load_store_64,
    load_store_128,
};

pub fn calcPageOffset(target_addr: u64, kind: PageOffsetInstKind) !u12 {
    const narrowed = @truncate(u12, target_addr);
    return switch (kind) {
        .arithmetic, .load_store_8 => narrowed,
        .load_store_16 => try math.divExact(u12, narrowed, 2),
        .load_store_32 => try math.divExact(u12, narrowed, 4),
        .load_store_64 => try math.divExact(u12, narrowed, 8),
        .load_store_128 => try math.divExact(u12, narrowed, 16),
    };
}
