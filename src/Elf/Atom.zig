/// Address allocated for this Atom.
value: u64 = 0,

/// Name of this Atom.
name: u32 = 0,

/// Index into linker's input file table.
file: u32 = 0,

/// Size of this atom
size: u32 = 0,

/// Alignment of this atom as a power of two.
alignment: u8 = 0,

/// Index of the input section.
shndx: u16 = 0,

/// Index of the output section.
out_shndx: u16 = 0,

/// Index of the input section containing this atom's relocs.
relocs_shndx: u16 = 0,

/// Index of this atom in the linker's atoms table.
atom_index: Index = 0,

/// Specifies whether this atom is alive or has been garbage collected.
alive: bool = true,

/// Specifies if the atom has been visited during garbage collection.
visited: bool = false,

/// Start index of FDEs referencing this atom.
fde_start: u32 = 0,

/// End index of FDEs referencing this atom.
fde_end: u32 = 0,

pub const Index = u32;

pub fn getName(self: Atom, elf_file: *Elf) [:0]const u8 {
    return elf_file.string_intern.getAssumeExists(self.name);
}

pub fn getCode(self: Atom, elf_file: *Elf) []const u8 {
    const object = self.getObject(elf_file);
    return object.getShdrContents(self.shndx);
}

/// Returns atom's code and optionally uncompresses data if required (for compressed sections).
/// Caller owns the memory.
pub fn getCodeUncompressAlloc(self: Atom, elf_file: *Elf) ![]u8 {
    const gpa = elf_file.base.allocator;
    const data = self.getCode(elf_file);
    const shdr = self.getInputShdr(elf_file);
    if (shdr.sh_flags & elf.SHF_COMPRESSED != 0) {
        const chdr = @as(*align(1) const elf.Elf64_Chdr, @ptrCast(data.ptr)).*;
        switch (chdr.ch_type) {
            .ZLIB => {
                var stream = std.io.fixedBufferStream(data[@sizeOf(elf.Elf64_Chdr)..]);
                var zlib_stream = try std.compress.zlib.decompressStream(gpa, stream.reader());
                defer zlib_stream.deinit();
                const decomp = try gpa.alloc(u8, chdr.ch_size);
                const nread = try zlib_stream.reader().readAll(decomp);
                if (nread != decomp.len) {
                    return error.Io;
                }
                return decomp;
            },
            else => @panic("TODO unhandled compression scheme"),
        }
    } else return gpa.dupe(u8, data);
}

pub fn getObject(self: Atom, elf_file: *Elf) *Object {
    return elf_file.getFile(self.file).?.object;
}

pub fn getInputShdr(self: Atom, elf_file: *Elf) elf.Elf64_Shdr {
    const object = self.getObject(elf_file);
    return object.getShdr(self.shndx);
}

pub fn getPriority(self: Atom, elf_file: *Elf) u64 {
    const object = self.getObject(elf_file);
    return (@as(u64, @intCast(object.index)) << 32) | @as(u64, @intCast(self.shndx));
}

pub fn getRelocs(self: Atom, elf_file: *Elf) []align(1) const elf.Elf64_Rela {
    if (self.relocs_shndx == @as(u16, @bitCast(@as(i16, -1)))) return &[0]elf.Elf64_Rela{};
    const object = self.getObject(elf_file);
    return object.getRelocs(self.relocs_shndx);
}

pub fn getFdes(self: Atom, elf_file: *Elf) []Fde {
    if (self.fde_start == self.fde_end) return &[0]Fde{};
    const object = self.getObject(elf_file);
    return object.fdes.items[self.fde_start..self.fde_end];
}

pub fn markFdesDead(self: Atom, elf_file: *Elf) void {
    for (self.getFdes(elf_file)) |*fde| {
        fde.alive = false;
    }
}

pub fn initOutputSection(self: *Atom, elf_file: *Elf) !void {
    const shdr = self.getInputShdr(elf_file);
    const name = blk: {
        const name = self.getName(elf_file);
        if (shdr.sh_flags & elf.SHF_MERGE != 0) break :blk name;
        const sh_name_prefixes: []const [:0]const u8 = &.{
            ".text",       ".data.rel.ro", ".data", ".rodata", ".bss.rel.ro",       ".bss",
            ".init_array", ".fini_array",  ".tbss", ".tdata",  ".gcc_except_table", ".ctors",
            ".dtors",      ".gnu.warning",
        };
        inline for (sh_name_prefixes) |prefix| {
            if (std.mem.eql(u8, name, prefix) or std.mem.startsWith(u8, name, prefix ++ ".")) {
                break :blk prefix;
            }
        }
        break :blk name;
    };
    const @"type" = switch (shdr.sh_type) {
        elf.SHT_NULL => unreachable,
        elf.SHT_PROGBITS => blk: {
            if (std.mem.eql(u8, name, ".init_array") or std.mem.startsWith(u8, name, ".init_array."))
                break :blk elf.SHT_INIT_ARRAY;
            if (std.mem.eql(u8, name, ".fini_array") or std.mem.startsWith(u8, name, ".fini_array."))
                break :blk elf.SHT_FINI_ARRAY;
            break :blk shdr.sh_type;
        },
        elf.SHT_X86_64_UNWIND => elf.SHT_PROGBITS,
        else => shdr.sh_type,
    };
    const flags = blk: {
        const flags = shdr.sh_flags & ~@as(u64, elf.SHF_COMPRESSED | elf.SHF_GROUP | elf.SHF_GNU_RETAIN);
        break :blk switch (@"type") {
            elf.SHT_INIT_ARRAY, elf.SHT_FINI_ARRAY => flags | elf.SHF_WRITE,
            else => flags,
        };
    };
    const out_shndx = elf_file.getSectionByName(name) orelse try elf_file.addSection(.{
        .type = @"type",
        .flags = flags,
        .name = name,
    });
    if (mem.eql(u8, ".text", name)) {
        elf_file.text_sect_index = out_shndx;
    }
    self.out_shndx = out_shndx;
}

pub fn scanRelocs(self: Atom, elf_file: *Elf) !void {
    const object = self.getObject(elf_file);
    const relocs = self.getRelocs(elf_file);
    var i: usize = 0;
    while (i < relocs.len) : (i += 1) {
        const rel = relocs[i];

        if (rel.r_type() == elf.R_X86_64_NONE) continue;
        if (try self.reportUndefSymbol(rel, elf_file)) continue;

        const symbol = object.getSymbol(rel.r_sym(), elf_file);
        const is_shared = elf_file.options.output_mode == .lib;

        if (symbol.isIFunc(elf_file)) {
            symbol.flags.got = true;
            symbol.flags.plt = true;
        }

        // While traversing relocations, mark symbols that require special handling such as
        // pointer indirection via GOT, or a stub trampoline via PLT.
        switch (rel.r_type()) {
            elf.R_X86_64_64 => {
                self.scanReloc(symbol, rel, getDynAbsRelocAction(symbol, elf_file), elf_file);
            },

            elf.R_X86_64_32,
            elf.R_X86_64_32S,
            => {
                self.scanReloc(symbol, rel, getAbsRelocAction(symbol, elf_file), elf_file);
            },

            elf.R_X86_64_GOT32,
            elf.R_X86_64_GOT64,
            elf.R_X86_64_GOTPC32,
            elf.R_X86_64_GOTPC64,
            elf.R_X86_64_GOTPCREL,
            elf.R_X86_64_GOTPCREL64,
            elf.R_X86_64_GOTPCRELX,
            elf.R_X86_64_REX_GOTPCRELX,
            => {
                symbol.flags.got = true;
            },

            elf.R_X86_64_PLT32,
            elf.R_X86_64_PLTOFF64,
            => {
                if (symbol.flags.import) {
                    symbol.flags.plt = true;
                }
            },

            elf.R_X86_64_PC32 => {
                self.scanReloc(symbol, rel, getPcRelocAction(symbol, elf_file), elf_file);
            },

            elf.R_X86_64_TLSGD => {
                // TODO verify followed by appropriate relocation such as PLT32 __tls_get_addr

                if (elf_file.options.static or
                    (elf_file.options.relax and !symbol.flags.import and !is_shared))
                {
                    // Relax if building with -static flag as __tls_get_addr() will not be present in libc.a
                    // We skip the next relocation.
                    i += 1;
                } else if (elf_file.options.relax and !symbol.flags.import and is_shared) {
                    @panic("TODO");
                } else {
                    symbol.flags.tlsgd = true;
                }
            },

            elf.R_X86_64_TLSLD => {
                // TODO verify followed by appropriate relocation such as PLT32 __tls_get_addr

                if (elf_file.options.static or (elf_file.options.relax and !is_shared)) {
                    // Relax if building with -static flag as __tls_get_addr() will not be present in libc.a
                    // We skip the next relocation.
                    i += 1;
                } else {
                    elf_file.needs_tlsld = true;
                }
            },

            elf.R_X86_64_GOTTPOFF => {
                const should_relax = elf_file.options.relax and !is_shared and !symbol.flags.import;
                if (!should_relax) {
                    @panic("TODO");
                }
            },

            elf.R_X86_64_GOTPC32_TLSDESC => @panic("TODO"),

            elf.R_X86_64_TPOFF32,
            elf.R_X86_64_TPOFF64,
            => {
                if (is_shared) self.picError(symbol, rel, elf_file);
            },

            elf.R_X86_64_GOTOFF64,
            elf.R_X86_64_DTPOFF32,
            elf.R_X86_64_DTPOFF64,
            elf.R_X86_64_SIZE32,
            elf.R_X86_64_SIZE64,
            elf.R_X86_64_TLSDESC_CALL,
            => {},

            else => elf_file.base.fatal("{s}: unknown relocation type: {}", .{
                self.getName(elf_file),
                fmtRelocType(rel.r_type()),
            }),
        }
    }
}

fn scanReloc(self: Atom, symbol: *Symbol, rel: elf.Elf64_Rela, action: RelocAction, elf_file: *Elf) void {
    const is_writeable = self.getInputShdr(elf_file).sh_flags & elf.SHF_WRITE != 0;
    const object = self.getObject(elf_file);

    switch (action) {
        .none => {},

        .@"error" => if (symbol.isAbs(elf_file))
            self.noPicError(symbol, rel, elf_file)
        else
            self.picError(symbol, rel, elf_file),

        .copyrel => {
            if (elf_file.options.z_nocopyreloc) {
                if (symbol.isAbs(elf_file))
                    self.noPicError(symbol, rel, elf_file)
                else
                    self.picError(symbol, rel, elf_file);
            }
            symbol.flags.copy_rel = true;
        },

        .dyn_copyrel => {
            if (is_writeable or elf_file.options.z_nocopyreloc) {
                self.checkTextReloc(symbol, elf_file);
                object.num_dynrelocs += 1;
            } else {
                symbol.flags.copy_rel = true;
            }
        },

        .plt => {
            symbol.flags.plt = true;
        },

        .cplt => {
            symbol.flags.plt = true;
            symbol.flags.is_canonical = true;
        },

        .dyn_cplt => {
            if (is_writeable) {
                object.num_dynrelocs += 1;
            } else {
                symbol.flags.plt = true;
                symbol.flags.is_canonical = true;
            }
        },

        .dynrel => {
            self.checkTextReloc(symbol, elf_file);
            object.num_dynrelocs += 1;
        },

        .baserel => {
            self.checkTextReloc(symbol, elf_file);
            object.num_dynrelocs += 1;
        },

        .ifunc => self.unhandledRelocError(symbol, rel, action, elf_file),
    }
}

inline fn checkTextReloc(self: Atom, symbol: *const Symbol, elf_file: *Elf) void {
    const is_writeable = self.getInputShdr(elf_file).sh_flags & elf.SHF_WRITE != 0;
    if (!is_writeable) {
        if (elf_file.options.z_text) {
            elf_file.base.fatal("{s}: {s}: relocation against symbol '{s}' in read-only section", .{
                self.getObject(elf_file).fmtPath(),
                self.getName(elf_file),
                symbol.getName(elf_file),
            });
        } else {
            // TODO
            elf_file.base.fatal("{s}: {s}: TODO handle relocations in read-only section", .{
                self.getObject(elf_file).fmtPath(),
                self.getName(elf_file),
            });
        }
    }
}

inline fn unhandledRelocError(
    self: Atom,
    symbol: *const Symbol,
    rel: elf.Elf64_Rela,
    action: RelocAction,
    elf_file: *Elf,
) void {
    elf_file.base.fatal("{s}: {s}: unhandled {} relocation at offset 0x{x} against symbol '{s}': action {s}", .{
        self.getObject(elf_file).fmtPath(),
        self.getName(elf_file),
        fmtRelocType(rel.r_type()),
        rel.r_offset,
        symbol.getName(elf_file),
        @tagName(action),
    });
}

inline fn noPicError(self: Atom, symbol: *const Symbol, rel: elf.Elf64_Rela, elf_file: *Elf) void {
    elf_file.base.fatal(
        "{s}: {s}: {} relocation at offset 0x{x} against symbol '{s}' cannot be used; recompile with -fno-PIC",
        .{
            self.getObject(elf_file).fmtPath(),
            self.getName(elf_file),
            fmtRelocType(rel.r_type()),
            rel.r_offset,
            symbol.getName(elf_file),
        },
    );
}

inline fn picError(self: Atom, symbol: *const Symbol, rel: elf.Elf64_Rela, elf_file: *Elf) void {
    elf_file.base.fatal(
        "{s}: {s}: {} relocation at offset 0x{x} against symbol '{s}' cannot be used; recompile with -fPIC",
        .{
            self.getObject(elf_file).fmtPath(),
            self.getName(elf_file),
            fmtRelocType(rel.r_type()),
            rel.r_offset,
            symbol.getName(elf_file),
        },
    );
}

const RelocAction = enum {
    none,
    @"error",
    copyrel,
    dyn_copyrel,
    plt,
    dyn_cplt,
    cplt,
    dynrel,
    baserel,
    ifunc,
};

fn getPcRelocAction(symbol: *const Symbol, elf_file: *Elf) RelocAction {
    // zig fmt: off
    const table: [3][4]RelocAction = .{
        //  Abs       Local   Import data  Import func
        .{ .@"error", .none,  .@"error",   .plt  }, // Shared object
        .{ .@"error", .none,  .copyrel,    .plt  }, // PIE
        .{ .none,     .none,  .copyrel,    .cplt }, // Non-PIE
    };
    // zig fmt: on
    const output = getOutputType(elf_file);
    const data = getDataType(symbol, elf_file);
    return table[output][data];
}

fn getAbsRelocAction(symbol: *const Symbol, elf_file: *Elf) RelocAction {
    // zig fmt: off
    const table: [3][4]RelocAction = .{
        //  Abs    Local       Import data  Import func
        .{ .none,  .@"error",  .@"error",   .@"error"  }, // Shared object
        .{ .none,  .@"error",  .@"error",   .@"error"  }, // PIE
        .{ .none,  .none,      .copyrel,    .cplt      }, // Non-PIE
    };
    // zig fmt: on
    const output = getOutputType(elf_file);
    const data = getDataType(symbol, elf_file);
    return table[output][data];
}

fn getDynAbsRelocAction(symbol: *const Symbol, elf_file: *Elf) RelocAction {
    if (symbol.isIFunc(elf_file)) return .ifunc;
    // zig fmt: off
    const table: [3][4]RelocAction = .{
        //  Abs    Local       Import data   Import func
        .{ .none,  .baserel,  .dynrel,       .dynrel    }, // Shared object
        .{ .none,  .baserel,  .dynrel,       .dynrel    }, // PIE
        .{ .none,  .none,     .dyn_copyrel,  .dyn_cplt  }, // Non-PIE
    };
    // zig fmt: on
    const output = getOutputType(elf_file);
    const data = getDataType(symbol, elf_file);
    return table[output][data];
}

inline fn getOutputType(elf_file: *Elf) u2 {
    return switch (elf_file.options.output_mode) {
        .lib => 0,
        .exe => if (elf_file.options.pie) 1 else 2,
    };
}

inline fn getDataType(symbol: *const Symbol, elf_file: *Elf) u2 {
    if (symbol.isAbs(elf_file)) return 0;
    if (!symbol.flags.import) return 1;
    if (symbol.getType(elf_file) != elf.STT_FUNC) return 2;
    return 3;
}

fn reportUndefSymbol(self: Atom, rel: elf.Elf64_Rela, elf_file: *Elf) !bool {
    const object = self.getObject(elf_file);
    const sym = object.getSymbol(rel.r_sym(), elf_file);
    const s_rel_sym = object.symtab[rel.r_sym()];

    // Check for violation of One Definition Rule for COMDATs.
    if (sym.getFile(elf_file) == null) {
        elf_file.base.fatal("{}: {s}: {s} refers to a discarded COMDAT section", .{
            object.fmtPath(),
            self.getName(elf_file),
            sym.getName(elf_file),
        });
        return true;
    }

    // Next, report any undefined non-weak symbols that are not imports.
    const s_sym = sym.getSourceSymbol(elf_file);
    if (s_rel_sym.st_shndx == elf.SHN_UNDEF and
        s_rel_sym.st_bind() == elf.STB_GLOBAL and
        sym.sym_idx > 0 and
        !sym.flags.import and
        s_sym.st_shndx == elf.SHN_UNDEF)
    {
        const gpa = elf_file.base.allocator;
        const gop = try elf_file.undefs.getOrPut(gpa, object.symbols.items[rel.r_sym()]);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{};
        }
        try gop.value_ptr.append(gpa, self.atom_index);
    }

    return false;
}

pub fn resolveRelocsAlloc(self: Atom, elf_file: *Elf, writer: anytype) !void {
    assert(self.getInputShdr(elf_file).sh_flags & elf.SHF_ALLOC != 0);
    const gpa = elf_file.base.allocator;
    const code = try self.getCodeUncompressAlloc(elf_file);
    defer gpa.free(code);
    const relocs = self.getRelocs(elf_file);
    const object = self.getObject(elf_file);

    relocs_log.debug("{x}: {s}", .{ self.value, self.getName(elf_file) });

    var stream = std.io.fixedBufferStream(code);
    const cwriter = stream.writer();

    var i: usize = 0;
    while (i < relocs.len) : (i += 1) {
        const rel = relocs[i];
        const r_type = rel.r_type();

        if (r_type == elf.R_X86_64_NONE) continue;

        const target = object.getSymbol(rel.r_sym(), elf_file);

        // We will use equation format to resolve relocations:
        // https://intezer.com/blog/malware-analysis/executable-and-linkable-format-101-part-3-relocations/
        //
        // Address of the source atom.
        const P = @as(i64, @intCast(self.value + rel.r_offset));
        // Addend from the relocation.
        const A = rel.r_addend;
        // Address of the target symbol - can be address of the symbol within an atom or address of PLT stub.
        const S = @as(i64, @intCast(target.getAddress(.{}, elf_file)));
        // Address of the global offset table.
        const GOT = blk: {
            const shndx = if (elf_file.got_plt_sect_index) |shndx|
                shndx
            else if (elf_file.got_sect_index) |shndx|
                shndx
            else
                null;
            break :blk if (shndx) |index| @as(i64, @intCast(elf_file.getSectionAddress(index))) else 0;
        };
        // Relative offset to the start of the global offset table.
        const G = @as(i64, @intCast(target.getGotAddress(elf_file))) - GOT;
        // Address of the thread pointer.
        const TP = @as(i64, @intCast(elf_file.getTpAddress()));
        // Address of the dynamic thread pointer.
        const DTP = @as(i64, @intCast(elf_file.getDtpAddress()));

        relocs_log.debug("  {s}: {x}: [{x} => {x}] G({x}) ({s})", .{
            fmtRelocType(r_type),
            rel.r_offset,
            P,
            S + A,
            G + GOT + A,
            target.getName(elf_file),
        });

        try stream.seekTo(rel.r_offset);

        switch (r_type) {
            elf.R_X86_64_NONE => unreachable,
            elf.R_X86_64_64 => {
                try self.resolveDynAbsReloc(
                    target,
                    rel,
                    getDynAbsRelocAction(target, elf_file),
                    elf_file,
                    cwriter,
                );
            },

            elf.R_X86_64_PLT32,
            elf.R_X86_64_PC32,
            => try cwriter.writeIntLittle(i32, @as(i32, @intCast(S + A - P))),

            elf.R_X86_64_GOTPCREL => try cwriter.writeIntLittle(i32, @as(i32, @intCast(G + GOT + A - P))),
            elf.R_X86_64_GOTPC32 => try cwriter.writeIntLittle(i32, @as(i32, @intCast(GOT + A - P))),
            elf.R_X86_64_GOTPC64 => try cwriter.writeIntLittle(i64, GOT + A - P),

            elf.R_X86_64_GOTPCRELX => {
                if (!target.flags.import and !target.isIFunc(elf_file) and !target.isAbs(elf_file)) blk: {
                    relaxGotpcrelx(code[rel.r_offset - 3 ..]) catch break :blk;
                    try cwriter.writeIntLittle(i32, @as(i32, @intCast(S + A - P)));
                    continue;
                }
                try cwriter.writeIntLittle(i32, @as(i32, @intCast(G + GOT + A - P)));
            },

            elf.R_X86_64_REX_GOTPCRELX => {
                if (!target.flags.import and !target.isIFunc(elf_file) and !target.isAbs(elf_file)) blk: {
                    relaxRexGotpcrelx(code[rel.r_offset - 3 ..]) catch break :blk;
                    try cwriter.writeIntLittle(i32, @as(i32, @intCast(S + A - P)));
                    continue;
                }
                try cwriter.writeIntLittle(i32, @as(i32, @intCast(G + GOT + A - P)));
            },

            elf.R_X86_64_32 => try cwriter.writeIntLittle(u32, @as(u32, @truncate(@as(u64, @intCast(S + A))))),
            elf.R_X86_64_32S => try cwriter.writeIntLittle(i32, @as(i32, @truncate(S + A))),

            elf.R_X86_64_TPOFF32 => try cwriter.writeIntLittle(i32, @as(i32, @truncate(S + A - TP))),
            elf.R_X86_64_TPOFF64 => try cwriter.writeIntLittle(i64, S + A - TP),
            elf.R_X86_64_DTPOFF32 => try cwriter.writeIntLittle(i32, @as(i32, @truncate(S + A - DTP))),
            elf.R_X86_64_DTPOFF64 => try cwriter.writeIntLittle(i64, S + A - DTP),

            elf.R_X86_64_GOTTPOFF => {
                blk: {
                    var inst_code = code[rel.r_offset - 3 ..];
                    const old_inst = disassemble(inst_code) orelse break :blk;
                    switch (old_inst.encoding.mnemonic) {
                        .mov => {
                            const inst = try Instruction.new(old_inst.prefix, .mov, &.{
                                old_inst.ops[0],
                                // TODO: hack to force imm32s in the assembler
                                .{ .imm = Immediate.s(-129) },
                            });
                            relocs_log.debug("    relaxing {} => {}", .{ old_inst.encoding, inst.encoding });
                            try encode(&.{inst}, inst_code);
                            try cwriter.writeIntLittle(i32, @as(i32, @intCast(S - TP)));
                        },
                        else => break :blk,
                    }
                    continue;
                }
                elf_file.base.fatal("TODO could not rewrite GOTTPOFF", .{});
            },

            elf.R_X86_64_TLSGD => {
                if (target.flags.tlsgd) {
                    elf_file.base.fatal("TODO get TLSGD address of the symbol '{s}'", .{target.getName(elf_file)});
                } else {
                    try relaxTlsGdToLe(
                        relocs[i .. i + 2],
                        @as(i32, @intCast(S - TP)),
                        elf_file,
                        &stream,
                    );
                    i += 1;
                }
            },

            elf.R_X86_64_TLSLD => {
                if (elf_file.got.emit_tlsld) {
                    try cwriter.writeIntLittle(i32, @as(i32, @intCast(@as(i64, @intCast(elf_file.getTlsLdAddress())) + A - P)));
                } else {
                    try relaxTlsLdToLe(
                        relocs[i .. i + 2],
                        @as(i32, @intCast(TP - @as(i64, @intCast(elf_file.getTlsAddress())))),
                        elf_file,
                        &stream,
                    );
                    i += 1;
                }
            },

            else => elf_file.base.fatal("unhandled relocation type: {}", .{fmtRelocType(r_type)}),
        }
    }

    try writer.writeAll(code);
}

fn resolveDynAbsReloc(
    self: Atom,
    target: *const Symbol,
    rel: elf.Elf64_Rela,
    action: RelocAction,
    elf_file: *Elf,
    writer: anytype,
) !void {
    const P = self.value + rel.r_offset;
    const A = rel.r_addend;
    const S = @as(i64, @intCast(target.getAddress(.{}, elf_file)));
    const is_writeable = self.getInputShdr(elf_file).sh_flags & elf.SHF_WRITE != 0;
    const object = self.getObject(elf_file);

    try elf_file.rela_dyn.ensureUnusedCapacity(elf_file.base.allocator, object.num_dynrelocs);

    switch (action) {
        .@"error",
        .plt,
        => unreachable,

        .copyrel,
        .cplt,
        .none,
        => try writer.writeIntLittle(i32, @as(i32, @truncate(S + A))),

        .dyn_copyrel => {
            if (is_writeable or elf_file.options.z_nocopyreloc) {
                elf_file.addRelaDynAssumeCapacity(.{
                    .offset = P,
                    .sym = target.getExtra(elf_file).?.dynamic,
                    .type = elf.R_X86_64_64,
                    .addend = A,
                });
            } else {
                try writer.writeIntLittle(i32, @as(i32, @truncate(S + A)));
            }
        },

        .dyn_cplt => {
            if (is_writeable) {
                elf_file.addRelaDynAssumeCapacity(.{
                    .offset = P,
                    .sym = target.getExtra(elf_file).?.dynamic,
                    .type = elf.R_X86_64_64,
                    .addend = A,
                });
            } else {
                try writer.writeIntLittle(i32, @as(i32, @truncate(S + A)));
            }
        },

        .dynrel => {
            elf_file.addRelaDynAssumeCapacity(.{
                .offset = P,
                .sym = target.getExtra(elf_file).?.dynamic,
                .type = elf.R_X86_64_64,
                .addend = A,
            });
        },

        .baserel => {
            elf_file.addRelaDynAssumeCapacity(.{
                .offset = P,
                .type = elf.R_X86_64_RELATIVE,
                .addend = S + A,
            });
        },

        .ifunc => self.unhandledRelocError(target, rel, action, elf_file),
    }
}

pub fn resolveRelocsNonAlloc(self: Atom, elf_file: *Elf, writer: anytype) !void {
    assert(self.getInputShdr(elf_file).sh_flags & elf.SHF_ALLOC == 0);
    const gpa = elf_file.base.allocator;
    const code = try self.getCodeUncompressAlloc(elf_file);
    defer gpa.free(code);
    const relocs = self.getRelocs(elf_file);
    const object = self.getObject(elf_file);

    relocs_log.debug("{x}: {s}", .{ self.value, self.getName(elf_file) });

    var stream = std.io.fixedBufferStream(code);
    const cwriter = stream.writer();

    var i: usize = 0;
    while (i < relocs.len) : (i += 1) {
        const rel = relocs[i];
        const r_type = rel.r_type();

        if (r_type == elf.R_X86_64_NONE) continue;
        if (try self.reportUndefSymbol(rel, elf_file)) continue;

        const target = object.getSymbol(rel.r_sym(), elf_file);

        // We will use equation format to resolve relocations:
        // https://intezer.com/blog/malware-analysis/executable-and-linkable-format-101-part-3-relocations/
        //
        const P = self.value + rel.r_offset;
        // Addend from the relocation.
        const A = rel.r_addend;
        // Address of the target symbol - can be address of the symbol within an atom or address of PLT stub.
        const S = @as(i64, @intCast(target.getAddress(.{}, elf_file)));
        // Address of the global offset table.
        const GOT = if (elf_file.got_sect_index) |shndx|
            @as(i64, @intCast(elf_file.getSectionAddress(shndx)))
        else
            0;
        // Address of the dynamic thread pointer.
        const DTP = @as(i64, @intCast(elf_file.getDtpAddress()));

        relocs_log.debug("  {s}: {x}: [{x} => {x}] ({s})", .{
            fmtRelocType(r_type),
            rel.r_offset,
            P,
            S + A,
            target.getName(elf_file),
        });

        try stream.seekTo(rel.r_offset);

        switch (r_type) {
            elf.R_X86_64_NONE => unreachable,
            elf.R_X86_64_8 => try cwriter.writeIntLittle(u8, @as(u8, @bitCast(@as(i8, @intCast(S + A))))),
            elf.R_X86_64_16 => try cwriter.writeIntLittle(u16, @as(u16, @bitCast(@as(i16, @intCast(S + A))))),
            elf.R_X86_64_32 => try cwriter.writeIntLittle(u32, @as(u32, @bitCast(@as(i32, @intCast(S + A))))),
            elf.R_X86_64_32S => try cwriter.writeIntLittle(i32, @as(i32, @intCast(S + A))),
            elf.R_X86_64_64 => try cwriter.writeIntLittle(i64, S + A),
            elf.R_X86_64_DTPOFF32 => try cwriter.writeIntLittle(i32, @as(i32, @intCast(S + A - DTP))),
            elf.R_X86_64_DTPOFF64 => try cwriter.writeIntLittle(i64, S + A - DTP),
            elf.R_X86_64_GOTOFF64 => try cwriter.writeIntLittle(i64, S + A - GOT),
            elf.R_X86_64_GOTPC64 => try cwriter.writeIntLittle(i64, GOT + A),
            elf.R_X86_64_SIZE32 => {
                const size = @as(i64, @intCast(target.getSourceSymbol(elf_file).st_size));
                try cwriter.writeIntLittle(u32, @as(u32, @bitCast(@as(i32, @intCast(size + A)))));
            },
            elf.R_X86_64_SIZE64 => {
                const size = @as(i64, @intCast(target.getSourceSymbol(elf_file).st_size));
                try cwriter.writeIntLittle(i64, @as(i64, @intCast(size + A)));
            },
            else => elf_file.base.fatal("{s}: invalid relocation type for non-alloc section: {}", .{
                self.getName(elf_file),
                fmtRelocType(r_type),
            }),
        }
    }

    try writer.writeAll(code);
}

fn relaxGotpcrelx(code: []u8) !void {
    const old_inst = disassemble(code) orelse return error.RelaxFail;
    const inst = switch (old_inst.encoding.mnemonic) {
        .call => try Instruction.new(old_inst.prefix, .call, &.{
            // TODO: hack to force imm32s in the assembler
            .{ .imm = Immediate.s(-129) },
        }),
        .jmp => try Instruction.new(old_inst.prefix, .jmp, &.{
            // TODO: hack to force imm32s in the assembler
            .{ .imm = Immediate.s(-129) },
        }),
        else => return error.RelaxFail,
    };
    relocs_log.debug("    relaxing {} => {}", .{ old_inst.encoding, inst.encoding });
    const nop = try Instruction.new(.none, .nop, &.{});
    encode(&.{ nop, inst }, code) catch return error.RelaxFail;
}

fn relaxRexGotpcrelx(code: []u8) !void {
    const old_inst = disassemble(code) orelse return error.RelaxFail;
    switch (old_inst.encoding.mnemonic) {
        .mov => {
            const inst = try Instruction.new(old_inst.prefix, .lea, &old_inst.ops);
            relocs_log.debug("    relaxing {} => {}", .{ old_inst.encoding, inst.encoding });
            encode(&.{inst}, code) catch return error.RelaxFail;
        },
        else => return error.RelaxFail,
    }
}

fn relaxTlsGdToLe(rels: []align(1) const elf.Elf64_Rela, value: i32, elf_file: *Elf, stream: anytype) !void {
    assert(rels.len == 2);
    const writer = stream.writer();
    switch (rels[1].r_type()) {
        elf.R_X86_64_PC32,
        elf.R_X86_64_PLT32,
        => {
            var insts = [_]u8{
                0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, // movq %fs:0,%rax
                0x48, 0x81, 0xc0, 0, 0, 0, 0, // add $tp_offset, %rax
            };
            mem.writeIntLittle(i32, insts[12..][0..4], value);
            try stream.seekBy(-4);
            try writer.writeAll(&insts);
        },

        else => elf_file.base.fatal("TODO rewrite {} when followed by {}", .{
            fmtRelocType(rels[0].r_type()),
            fmtRelocType(rels[1].r_type()),
        }),
    }
}

fn relaxTlsLdToLe(rels: []align(1) const elf.Elf64_Rela, value: i32, elf_file: *Elf, stream: anytype) !void {
    assert(rels.len == 2);
    const writer = stream.writer();
    switch (rels[1].r_type()) {
        elf.R_X86_64_PC32,
        elf.R_X86_64_PLT32,
        => {
            var insts = [_]u8{
                0x31, 0xc0, // xor %eax, %eax
                0x64, 0x48, 0x8b, 0, // mov %fs:(%rax), %rax
                0x48, 0x2d, 0, 0, 0, 0, // sub $tls_size, %rax
            };
            mem.writeIntLittle(i32, insts[8..][0..4], value);
            try stream.seekBy(-3);
            try writer.writeAll(&insts);
        },

        else => elf_file.base.fatal("TODO rewrite {} when followed by {}", .{
            fmtRelocType(rels[0].r_type()),
            fmtRelocType(rels[1].r_type()),
        }),
    }
}

fn disassemble(code: []const u8) ?Instruction {
    var disas = Disassembler.init(code);
    const inst = disas.next() catch return null;
    return inst;
}

fn encode(insts: []const Instruction, code: []u8) !void {
    var stream = std.io.fixedBufferStream(code);
    const writer = stream.writer();
    for (insts) |inst| {
        try inst.encode(writer, .{});
    }
}

pub fn fmtRelocType(r_type: u32) std.fmt.Formatter(formatRelocType) {
    return .{ .data = r_type };
}

fn formatRelocType(
    r_type: u32,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const str = switch (r_type) {
        elf.R_X86_64_NONE => "R_X86_64_NONE",
        elf.R_X86_64_64 => "R_X86_64_64",
        elf.R_X86_64_PC32 => "R_X86_64_PC32",
        elf.R_X86_64_GOT32 => "R_X86_64_GOT32",
        elf.R_X86_64_PLT32 => "R_X86_64_PLT32",
        elf.R_X86_64_COPY => "R_X86_64_COPY",
        elf.R_X86_64_GLOB_DAT => "R_X86_64_GLOB_DAT",
        elf.R_X86_64_JUMP_SLOT => "R_X86_64_JUMP_SLOT",
        elf.R_X86_64_RELATIVE => "R_X86_64_RELATIVE",
        elf.R_X86_64_GOTPCREL => "R_X86_64_GOTPCREL",
        elf.R_X86_64_32 => "R_X86_64_32",
        elf.R_X86_64_32S => "R_X86_64_32S",
        elf.R_X86_64_16 => "R_X86_64_16",
        elf.R_X86_64_PC16 => "R_X86_64_PC16",
        elf.R_X86_64_8 => "R_X86_64_8",
        elf.R_X86_64_PC8 => "R_X86_64_PC8",
        elf.R_X86_64_DTPMOD64 => "R_X86_64_DTPMOD64",
        elf.R_X86_64_DTPOFF64 => "R_X86_64_DTPOFF64",
        elf.R_X86_64_TPOFF64 => "R_X86_64_TPOFF64",
        elf.R_X86_64_TLSGD => "R_X86_64_TLSGD",
        elf.R_X86_64_TLSLD => "R_X86_64_TLSLD",
        elf.R_X86_64_DTPOFF32 => "R_X86_64_DTPOFF32",
        elf.R_X86_64_GOTTPOFF => "R_X86_64_GOTTPOFF",
        elf.R_X86_64_TPOFF32 => "R_X86_64_TPOFF32",
        elf.R_X86_64_PC64 => "R_X86_64_PC64",
        elf.R_X86_64_GOTOFF64 => "R_X86_64_GOTOFF64",
        elf.R_X86_64_GOTPC32 => "R_X86_64_GOTPC32",
        elf.R_X86_64_GOT64 => "R_X86_64_GOT64",
        elf.R_X86_64_GOTPCREL64 => "R_X86_64_GOTPCREL64",
        elf.R_X86_64_GOTPC64 => "R_X86_64_GOTPC64",
        elf.R_X86_64_GOTPLT64 => "R_X86_64_GOTPLT64",
        elf.R_X86_64_PLTOFF64 => "R_X86_64_PLTOFF64",
        elf.R_X86_64_SIZE32 => "R_X86_64_SIZE32",
        elf.R_X86_64_SIZE64 => "R_X86_64_SIZE64",
        elf.R_X86_64_GOTPC32_TLSDESC => "R_X86_64_GOTPC32_TLSDESC",
        elf.R_X86_64_TLSDESC_CALL => "R_X86_64_TLSDESC_CALL",
        elf.R_X86_64_TLSDESC => "R_X86_64_TLSDESC",
        elf.R_X86_64_IRELATIVE => "R_X86_64_IRELATIVE",
        elf.R_X86_64_RELATIVE64 => "R_X86_64_RELATIVE64",
        elf.R_X86_64_GOTPCRELX => "R_X86_64_GOTPCRELX",
        elf.R_X86_64_REX_GOTPCRELX => "R_X86_64_REX_GOTPCRELX",
        elf.R_X86_64_NUM => "R_X86_64_NUM",
        else => "R_X86_64_UNKNOWN",
    };
    try writer.print("{s}", .{str});
}

pub fn format(
    atom: Atom,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = atom;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compileError("do not format symbols directly");
}

pub fn fmt(atom: Atom, elf_file: *Elf) std.fmt.Formatter(format2) {
    return .{ .data = .{
        .atom = atom,
        .elf_file = elf_file,
    } };
}

const FormatContext = struct {
    atom: Atom,
    elf_file: *Elf,
};

fn format2(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    const atom = ctx.atom;
    const elf_file = ctx.elf_file;
    try writer.print("atom({d}) : {s} : @{x} : sect({d}) : align({x}) : size({x})", .{
        atom.atom_index, atom.getName(elf_file), atom.value,
        atom.out_shndx,  atom.alignment,         atom.size,
    });
    if (atom.fde_start != atom.fde_end) {
        try writer.writeAll(" : fdes{ ");
        for (atom.getFdes(elf_file), atom.fde_start..) |fde, i| {
            try writer.print("{d}", .{i});
            if (!fde.alive) try writer.writeAll("([*])");
            if (i < atom.fde_end - 1) try writer.writeAll(", ");
        }
        try writer.writeAll(" }");
    }
    if (elf_file.options.gc_sections and !atom.alive) {
        try writer.writeAll(" : [*]");
    }
}

const Atom = @This();

const std = @import("std");
const assert = std.debug.assert;
const dis_x86_64 = @import("dis_x86_64");
const elf = std.elf;
const log = std.log.scoped(.elf);
const relocs_log = std.log.scoped(.relocs);
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const Disassembler = dis_x86_64.Disassembler;
const Elf = @import("../Elf.zig");
const Fde = @import("eh_frame.zig").Fde;
const Instruction = dis_x86_64.Instruction;
const Immediate = dis_x86_64.Immediate;
const Object = @import("Object.zig");
const Symbol = @import("Symbol.zig");
