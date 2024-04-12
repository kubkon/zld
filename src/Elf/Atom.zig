/// Address allocated for this Atom.
value: u64 = 0,

/// Name of this Atom.
name: u32 = 0,

/// Index into linker's input file table.
file: File.Index = 0,

/// Size of this atom
size: u64 = 0,

/// Alignment of this atom as a power of two.
alignment: u8 = 0,

/// Index of the input section.
shndx: u32 = 0,

/// Index of the output section.
out_shndx: u32 = 0,

/// Index of the input section containing this atom's relocs.
relocs_shndx: u32 = 0,

/// Index of this atom in the linker's atoms table.
atom_index: Index = 0,

flags: Flags = .{},

extra: u32 = 0,

pub fn getName(self: Atom, elf_file: *Elf) [:0]const u8 {
    return elf_file.string_intern.getAssumeExists(self.name);
}

pub fn getAddress(self: Atom, elf_file: *Elf) u64 {
    const shdr = elf_file.sections.items(.shdr)[self.out_shndx];
    return shdr.sh_addr + self.value;
}

/// Returns atom's code and optionally uncompresses data if required (for compressed sections).
/// Caller owns the memory.
pub fn getCodeUncompressAlloc(self: Atom, elf_file: *Elf) ![]u8 {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = elf_file.base.allocator;
    const shdr = self.getInputShdr(elf_file);
    const object = self.getObject(elf_file);
    const file = elf_file.getFileHandle(object.file_handle);
    const data = try object.preadShdrContentsAlloc(gpa, file, self.shndx);
    defer if (shdr.sh_flags & elf.SHF_COMPRESSED != 0) gpa.free(data);

    if (shdr.sh_flags & elf.SHF_COMPRESSED != 0) {
        const chdr = @as(*align(1) const elf.Elf64_Chdr, @ptrCast(data.ptr)).*;
        switch (chdr.ch_type) {
            .ZLIB => {
                var stream = std.io.fixedBufferStream(data[@sizeOf(elf.Elf64_Chdr)..]);
                var zlib_stream = std.compress.zlib.decompressor(stream.reader());
                const decomp = try gpa.alloc(u8, chdr.ch_size);
                const nread = try zlib_stream.reader().readAll(decomp);
                if (nread != decomp.len) {
                    return error.InputOutput;
                }
                return decomp;
            },
            else => @panic("TODO unhandled compression scheme"),
        }
    }

    return data;
}

pub fn getObject(self: Atom, elf_file: *Elf) *Object {
    return elf_file.getFile(self.file).?.object;
}

pub fn getInputShdr(self: Atom, elf_file: *Elf) elf.Elf64_Shdr {
    const object = self.getObject(elf_file);
    return object.shdrs.items[self.shndx];
}

pub fn getPriority(self: Atom, elf_file: *Elf) u64 {
    const object = self.getObject(elf_file);
    return (@as(u64, @intCast(object.index)) << 32) | @as(u64, @intCast(self.shndx));
}

pub fn getRelocs(self: Atom, elf_file: *Elf) []const elf.Elf64_Rela {
    if (self.relocs_shndx == 0) return &[0]elf.Elf64_Rela{};
    const extra = self.getExtra(elf_file).?;
    const object = self.getObject(elf_file);
    return object.relocs.items[extra.rel_index..][0..extra.rel_count];
}

pub fn getThunk(self: Atom, elf_file: *Elf) *Thunk {
    assert(self.flags.thunk);
    const extra = self.getExtra(elf_file).?;
    return elf_file.getThunk(extra.thunk);
}

const AddExtraOpts = struct {
    thunk: ?u32 = null,
    fde_start: ?u32 = null,
    fde_count: ?u32 = null,
    rel_index: ?u32 = null,
    rel_count: ?u32 = null,
};

pub fn addExtra(atom: *Atom, opts: AddExtraOpts, elf_file: *Elf) !void {
    if (atom.getExtra(elf_file) == null) {
        atom.extra = try elf_file.addAtomExtra(.{});
    }
    var extra = atom.getExtra(elf_file).?;
    inline for (@typeInfo(@TypeOf(opts)).Struct.fields) |field| {
        if (@field(opts, field.name)) |x| {
            @field(extra, field.name) = x;
        }
    }
    atom.setExtra(extra, elf_file);
}

pub inline fn getExtra(atom: Atom, elf_file: *Elf) ?Extra {
    return elf_file.getAtomExtra(atom.extra);
}

pub inline fn setExtra(atom: Atom, extra: Extra, elf_file: *Elf) void {
    elf_file.setAtomExtra(atom.extra, extra);
}

pub fn writeRelocs(self: Atom, elf_file: *Elf, out_relocs: *std.ArrayList(elf.Elf64_Rela)) !void {
    const tracy = trace(@src());
    defer tracy.end();

    relocs_log.debug("0x{x}: {s}", .{ self.getAddress(elf_file), self.getName(elf_file) });

    const cpu_arch = elf_file.options.cpu_arch.?;
    const object = self.getObject(elf_file);
    for (self.getRelocs(elf_file)) |rel| {
        const target = object.getSymbol(rel.r_sym(), elf_file);
        const r_type = rel.r_type();
        const r_offset = self.value + rel.r_offset;
        var r_addend = rel.r_addend;
        var r_sym: u32 = 0;
        switch (target.getType(elf_file)) {
            elf.STT_SECTION => if (target.getMergeSubsection(elf_file)) |msub| {
                r_addend += @intCast(target.getAddress(.{}, elf_file));
                r_sym = elf_file.sections.items(.sym_index)[msub.getMergeSection(elf_file).out_shndx];
            } else {
                r_addend += @intCast(target.getAddress(.{}, elf_file));
                r_sym = elf_file.sections.items(.sym_index)[target.shndx];
            },
            else => {
                r_sym = target.getOutputSymtabIndex(elf_file) orelse 0;
            },
        }

        relocs_log.debug("  {s}: [{x} => {d}({s})] + {x}", .{
            relocation.fmtRelocType(r_type, cpu_arch),
            r_offset,
            r_sym,
            target.getName(elf_file),
            r_addend,
        });

        out_relocs.appendAssumeCapacity(.{
            .r_offset = r_offset,
            .r_addend = r_addend,
            .r_info = (@as(u64, @intCast(r_sym)) << 32) | r_type,
        });
    }
}

pub fn getFdes(self: Atom, elf_file: *Elf) []Fde {
    if (!self.flags.fde) return &[0]Fde{};
    const extra = self.getExtra(elf_file).?;
    const object = self.getObject(elf_file);
    return object.fdes.items[extra.fde_start..][0..extra.fde_count];
}

pub fn markFdesDead(self: Atom, elf_file: *Elf) void {
    for (self.getFdes(elf_file)) |*fde| {
        fde.alive = false;
    }
}

pub fn scanRelocs(self: Atom, elf_file: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const cpu_arch = elf_file.options.cpu_arch.?;
    const object = self.getObject(elf_file);
    const relocs = self.getRelocs(elf_file);
    const code = try self.getCodeUncompressAlloc(elf_file);
    defer elf_file.base.allocator.free(code);

    var has_reloc_errors = false;
    var it = RelocsIterator{ .relocs = relocs };
    while (it.next()) |rel| {
        const r_kind = relocation.decode(rel.r_type(), cpu_arch);

        if (r_kind == .none) continue;
        if (try self.reportUndefSymbol(rel, elf_file)) continue;

        const symbol = object.getSymbol(rel.r_sym(), elf_file);

        if (symbol.isIFunc(elf_file)) {
            symbol.flags.got = true;
            symbol.flags.plt = true;
        }

        // While traversing relocations, mark symbols that require special handling such as
        // pointer indirection via GOT, or a stub trampoline via PLT.
        switch (cpu_arch) {
            .x86_64 => x86_64.scanReloc(self, elf_file, rel, symbol, code, &it) catch {
                has_reloc_errors = true;
            },
            .aarch64 => aarch64.scanReloc(self, elf_file, rel, symbol, code, &it) catch {
                has_reloc_errors = true;
            },
            .riscv64 => riscv.scanReloc(self, elf_file, rel, symbol, code, &it) catch {
                has_reloc_errors = true;
            },
            else => |arch| {
                elf_file.base.fatal("TODO support {s} architecture", .{@tagName(arch)});
                return error.UnhandledCpuArch;
            },
        }
    }
    if (has_reloc_errors) return error.RelocError;
}

fn scanReloc(self: Atom, symbol: *Symbol, rel: elf.Elf64_Rela, action: RelocAction, elf_file: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const is_writeable = self.getInputShdr(elf_file).sh_flags & elf.SHF_WRITE != 0;
    const object = self.getObject(elf_file);

    switch (action) {
        .none => {},

        .@"error" => if (symbol.isAbs(elf_file))
            try self.noPicError(symbol, rel, elf_file)
        else
            try self.picError(symbol, rel, elf_file),

        .copyrel => {
            if (elf_file.options.z_nocopyreloc) {
                if (symbol.isAbs(elf_file))
                    try self.noPicError(symbol, rel, elf_file)
                else
                    try self.picError(symbol, rel, elf_file);
            }
            symbol.flags.copy_rel = true;
        },

        .dyn_copyrel => {
            if (is_writeable or elf_file.options.z_nocopyreloc) {
                try self.textReloc(symbol, elf_file);
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

        .dynrel, .baserel, .ifunc => {
            try self.textReloc(symbol, elf_file);
            object.num_dynrelocs += 1;

            if (action == .ifunc) elf_file.num_ifunc_dynrelocs += 1;
        },
    }
}

inline fn textReloc(self: Atom, symbol: *const Symbol, elf_file: *Elf) !void {
    const is_writeable = self.getInputShdr(elf_file).sh_flags & elf.SHF_WRITE != 0;
    if (!is_writeable) {
        if (elf_file.options.z_text) {
            elf_file.base.fatal("{s}: {s}: relocation against symbol '{s}' in read-only section", .{
                self.getObject(elf_file).fmtPath(),
                self.getName(elf_file),
                symbol.getName(elf_file),
            });
            return error.RelocError;
        } else {
            elf_file.has_text_reloc = true;
        }
    }
}

inline fn noPicError(self: Atom, symbol: *const Symbol, rel: elf.Elf64_Rela, elf_file: *Elf) !void {
    elf_file.base.fatal(
        "{s}: {s}: {} relocation at offset 0x{x} against symbol '{s}' cannot be used; recompile with -fno-PIC",
        .{
            self.getObject(elf_file).fmtPath(),
            self.getName(elf_file),
            relocation.fmtRelocType(rel.r_type(), elf_file.options.cpu_arch.?),
            rel.r_offset,
            symbol.getName(elf_file),
        },
    );
    return error.RelocError;
}

inline fn picError(self: Atom, symbol: *const Symbol, rel: elf.Elf64_Rela, elf_file: *Elf) !void {
    elf_file.base.fatal(
        "{s}: {s}: {} relocation at offset 0x{x} against symbol '{s}' cannot be used; recompile with -fPIC",
        .{
            self.getObject(elf_file).fmtPath(),
            self.getName(elf_file),
            relocation.fmtRelocType(rel.r_type(), elf_file.options.cpu_arch.?),
            rel.r_offset,
            symbol.getName(elf_file),
        },
    );
    return error.RelocError;
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
    if (elf_file.options.shared) return 0;
    return if (elf_file.options.pie) 1 else 2;
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
    const s_rel_sym = object.symtab.items[rel.r_sym()];

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
        return true;
    }

    return false;
}

pub fn resolveRelocsAlloc(self: Atom, elf_file: *Elf, writer: anytype) !void {
    const tracy = trace(@src());
    defer tracy.end();

    assert(self.getInputShdr(elf_file).sh_flags & elf.SHF_ALLOC != 0);

    const gpa = elf_file.base.allocator;
    const code = try self.getCodeUncompressAlloc(elf_file);
    defer gpa.free(code);
    const relocs = self.getRelocs(elf_file);
    const object = self.getObject(elf_file);
    const cpu_arch = elf_file.options.cpu_arch.?;

    relocs_log.debug("{x}: {s}", .{ self.getAddress(elf_file), self.getName(elf_file) });

    var stream = std.io.fixedBufferStream(code);

    var has_reloc_errors = false;
    var it = RelocsIterator{ .relocs = relocs };
    while (it.next()) |rel| {
        const r_kind = relocation.decode(rel.r_type(), cpu_arch);
        if (r_kind == .none) continue;

        const target = object.getSymbol(rel.r_sym(), elf_file);

        // We will use equation format to resolve relocations:
        // https://intezer.com/blog/malware-analysis/executable-and-linkable-format-101-part-3-relocations/
        //
        // Address of the source atom.
        const P = @as(i64, @intCast(self.getAddress(elf_file) + rel.r_offset));
        // Addend from the relocation.
        const A = rel.r_addend;
        // Address of the target symbol - can be address of the symbol within an atom or address of PLT stub.
        const S = @as(i64, @intCast(target.getAddress(.{}, elf_file)));
        // Address of the global offset table.
        const GOT = @as(i64, @intCast(elf_file.getGotAddress()));
        // Relative offset to the start of the global offset table.
        const G = @as(i64, @intCast(target.getGotAddress(elf_file))) - GOT;
        // Address of the thread pointer.
        const TP = @as(i64, @intCast(elf_file.getTpAddress()));
        // Address of the dynamic thread pointer.
        const DTP = @as(i64, @intCast(elf_file.getDtpAddress()));

        relocs_log.debug("  {s}: {x}: [{x} => {x}] G({x}) ({s})", .{
            relocation.fmtRelocType(rel.r_type(), cpu_arch),
            rel.r_offset,
            P,
            S + A,
            G + GOT + A,
            target.getName(elf_file),
        });

        try stream.seekTo(rel.r_offset);

        const args = ResolveArgs{ P, A, S, GOT, G, TP, DTP };

        switch (cpu_arch) {
            .x86_64 => x86_64.resolveRelocAlloc(self, elf_file, rel, target, args, &it, code, &stream) catch |err| switch (err) {
                error.RelocError => has_reloc_errors = true,
                else => |e| return e,
            },
            .aarch64 => aarch64.resolveRelocAlloc(self, elf_file, rel, target, args, &it, code, &stream) catch |err| switch (err) {
                error.RelocError => has_reloc_errors = true,
                else => |e| return e,
            },
            .riscv64 => riscv.resolveRelocAlloc(self, elf_file, rel, target, args, &it, code, &stream) catch |err| switch (err) {
                error.RelocError => has_reloc_errors = true,
                else => |e| return e,
            },
            else => |arch| {
                elf_file.base.fatal("TODO support {s} architecture", .{@tagName(arch)});
                return error.UnhandledCpuArch;
            },
        }
    }

    try writer.writeAll(code);

    if (has_reloc_errors) return error.RelocError;
}

fn resolveDynAbsReloc(
    self: Atom,
    target: *const Symbol,
    rel: elf.Elf64_Rela,
    action: RelocAction,
    elf_file: *Elf,
    writer: anytype,
) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const cpu_arch = elf_file.options.cpu_arch.?;
    const P = self.getAddress(elf_file) + rel.r_offset;
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
        => try writer.writeInt(i32, @as(i32, @truncate(S + A)), .little),

        .dyn_copyrel => {
            if (is_writeable or elf_file.options.z_nocopyreloc) {
                elf_file.addRelaDynAssumeCapacity(.{
                    .offset = P,
                    .sym = target.getExtra(elf_file).?.dynamic,
                    .type = relocation.encode(.abs, cpu_arch),
                    .addend = A,
                });
                try applyDynamicReloc(A, elf_file, writer);
            } else {
                try writer.writeInt(i32, @as(i32, @truncate(S + A)), .little);
            }
        },

        .dyn_cplt => {
            if (is_writeable) {
                elf_file.addRelaDynAssumeCapacity(.{
                    .offset = P,
                    .sym = target.getExtra(elf_file).?.dynamic,
                    .type = relocation.encode(.abs, cpu_arch),
                    .addend = A,
                });
                try applyDynamicReloc(A, elf_file, writer);
            } else {
                try writer.writeInt(i32, @as(i32, @truncate(S + A)), .little);
            }
        },

        .dynrel => {
            elf_file.addRelaDynAssumeCapacity(.{
                .offset = P,
                .sym = target.getExtra(elf_file).?.dynamic,
                .type = relocation.encode(.abs, cpu_arch),
                .addend = A,
            });
            try applyDynamicReloc(A, elf_file, writer);
        },

        .baserel => {
            elf_file.addRelaDynAssumeCapacity(.{
                .offset = P,
                .type = relocation.encode(.rel, cpu_arch),
                .addend = S + A,
            });
            try applyDynamicReloc(S + A, elf_file, writer);
        },

        .ifunc => {
            const S_ = @as(i64, @intCast(target.getAddress(.{ .plt = false }, elf_file)));
            elf_file.addRelaDynAssumeCapacity(.{
                .offset = P,
                .type = relocation.encode(.irel, cpu_arch),
                .addend = S_ + A,
            });
            try applyDynamicReloc(S_ + A, elf_file, writer);
        },
    }
}

inline fn applyDynamicReloc(value: i64, elf_file: *Elf, writer: anytype) !void {
    if (elf_file.options.apply_dynamic_relocs) {
        try writer.writeInt(i64, value, .little);
    }
}

pub fn resolveRelocsNonAlloc(self: Atom, elf_file: *Elf, writer: anytype) !void {
    const tracy = trace(@src());
    defer tracy.end();

    assert(self.getInputShdr(elf_file).sh_flags & elf.SHF_ALLOC == 0);

    const gpa = elf_file.base.allocator;
    const code = try self.getCodeUncompressAlloc(elf_file);
    defer gpa.free(code);
    const relocs = self.getRelocs(elf_file);
    const object = self.getObject(elf_file);
    const cpu_arch = elf_file.options.cpu_arch.?;

    relocs_log.debug("{x}: {s}", .{ self.value, self.getName(elf_file) });

    var stream = std.io.fixedBufferStream(code);

    var has_reloc_errors = false;
    var it = RelocsIterator{ .relocs = relocs };
    while (it.next()) |rel| {
        const r_kind = relocation.decode(rel.r_type(), cpu_arch);
        if (r_kind == .none) continue;
        if (try self.reportUndefSymbol(rel, elf_file)) continue;

        const target = object.getSymbol(rel.r_sym(), elf_file);

        const P = @as(i64, @intCast(self.getAddress(elf_file) + rel.r_offset));
        const A = rel.r_addend;
        const S = @as(i64, @intCast(target.getAddress(.{}, elf_file)));
        const GOT = @as(i64, @intCast(elf_file.getGotAddress()));
        const DTP = @as(i64, @intCast(elf_file.getDtpAddress()));

        relocs_log.debug("  {s}: {x}: [{x} => {x}] ({s})", .{
            relocation.fmtRelocType(rel.r_type(), cpu_arch),
            rel.r_offset,
            P,
            S + A,
            target.getName(elf_file),
        });

        try stream.seekTo(rel.r_offset);

        const args = ResolveArgs{ 0, A, S, GOT, 0, 0, DTP };

        switch (cpu_arch) {
            .x86_64 => x86_64.resolveRelocNonAlloc(self, elf_file, rel, target, args, &it, code, &stream) catch |err| switch (err) {
                error.RelocError => has_reloc_errors = true,
                else => |e| return e,
            },
            .aarch64 => aarch64.resolveRelocNonAlloc(self, elf_file, rel, target, args, &it, code, &stream) catch |err| switch (err) {
                error.RelocError => has_reloc_errors = true,
                else => |e| return e,
            },
            .riscv64 => riscv.resolveRelocNonAlloc(self, elf_file, rel, target, args, &it, code, &stream) catch |err| switch (err) {
                error.RelocError => has_reloc_errors = true,
                else => |e| return e,
            },
            else => |arch| {
                elf_file.base.fatal("TODO support {s} architecture", .{@tagName(arch)});
                return error.UnhandledCpuArch;
            },
        }
    }

    try writer.writeAll(code);

    if (has_reloc_errors) return error.RelocError;
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
        atom.atom_index, atom.getName(elf_file), atom.getAddress(elf_file),
        atom.out_shndx,  atom.alignment,         atom.size,
    });
    if (atom.flags.fde) {
        try writer.writeAll(" : fdes{ ");
        const extra = atom.getExtra(elf_file).?;
        for (atom.getFdes(elf_file), extra.fde_start..) |fde, i| {
            try writer.print("{d}", .{i});
            if (!fde.alive) try writer.writeAll("([*])");
            if (i - extra.fde_start < extra.fde_count - 1) try writer.writeAll(", ");
        }
        try writer.writeAll(" }");
    }
    if (!atom.flags.alive) {
        try writer.writeAll(" : [*]");
    }
}

pub const Index = u32;

pub const Flags = packed struct {
    /// Specifies whether this atom is alive or has been garbage collected.
    alive: bool = true,

    /// Specifies if the atom has been visited during garbage collection.
    visited: bool = false,

    /// Whether this atom has a range extension thunk.
    thunk: bool = false,

    /// Whether this atom has FDE records.
    fde: bool = false,
};

const ResolveArgs = struct { i64, i64, i64, i64, i64, i64, i64 };

const x86_64 = struct {
    fn scanReloc(
        atom: Atom,
        elf_file: *Elf,
        rel: elf.Elf64_Rela,
        symbol: *Symbol,
        code: []u8,
        it: *RelocsIterator,
    ) !void {
        const tracy = trace(@src());
        defer tracy.end();

        const r_type: elf.R_X86_64 = @enumFromInt(rel.r_type());
        const is_shared = elf_file.options.shared;

        switch (r_type) {
            .@"64" => {
                try atom.scanReloc(symbol, rel, getDynAbsRelocAction(symbol, elf_file), elf_file);
            },

            .@"32",
            .@"32S",
            => {
                try atom.scanReloc(symbol, rel, getAbsRelocAction(symbol, elf_file), elf_file);
            },

            .GOT32,
            .GOT64,
            .GOTPC32,
            .GOTPC64,
            .GOTPCREL,
            .GOTPCREL64,
            .GOTPCRELX,
            .REX_GOTPCRELX,
            => {
                symbol.flags.got = true;
            },

            .PLT32,
            .PLTOFF64,
            => {
                if (symbol.flags.import) {
                    symbol.flags.plt = true;
                }
            },

            .PC32 => {
                try atom.scanReloc(symbol, rel, getPcRelocAction(symbol, elf_file), elf_file);
            },

            .TLSGD => {
                // TODO verify followed by appropriate relocation such as PLT32 __tls_get_addr

                if (elf_file.options.static or
                    (elf_file.options.relax and !symbol.flags.import and !is_shared))
                {
                    // Relax if building with -static flag as __tls_get_addr() will not be present in libc.a
                    // We skip the next relocation.
                    it.skip(1);
                } else if (elf_file.options.relax and !symbol.flags.import and is_shared and
                    elf_file.options.z_nodlopen)
                {
                    symbol.flags.gottp = true;
                    it.skip(1);
                } else {
                    symbol.flags.tlsgd = true;
                }
            },

            .TLSLD => {
                // TODO verify followed by appropriate relocation such as PLT32 __tls_get_addr

                if (elf_file.options.static or (elf_file.options.relax and !is_shared)) {
                    // Relax if building with -static flag as __tls_get_addr() will not be present in libc.a
                    // We skip the next relocation.
                    it.skip(1);
                } else {
                    elf_file.got.flags.needs_tlsld = true;
                }
            },

            .GOTTPOFF => {
                const should_relax = blk: {
                    if (!elf_file.options.relax or is_shared or symbol.flags.import) break :blk false;
                    relaxGotTpOff(code[rel.r_offset - 3 ..]) catch break :blk false;
                    break :blk true;
                };
                if (!should_relax) {
                    symbol.flags.gottp = true;
                }
            },

            .GOTPC32_TLSDESC => {
                const should_relax = elf_file.options.static or
                    (elf_file.options.relax and !is_shared and !symbol.flags.import);
                if (!should_relax) {
                    symbol.flags.tlsdesc = true;
                }
            },

            .TPOFF32,
            .TPOFF64,
            => {
                if (is_shared) try atom.picError(symbol, rel, elf_file);
            },

            .GOTOFF64,
            .DTPOFF32,
            .DTPOFF64,
            .SIZE32,
            .SIZE64,
            .TLSDESC_CALL,
            => {},

            else => {
                elf_file.base.fatal("{s}: unknown relocation type: {}", .{
                    atom.getName(elf_file),
                    relocation.fmtRelocType(rel.r_type(), .x86_64),
                });
                return error.RelocError;
            },
        }
    }

    fn resolveRelocAlloc(
        atom: Atom,
        elf_file: *Elf,
        rel: elf.Elf64_Rela,
        target: *const Symbol,
        args: ResolveArgs,
        it: *RelocsIterator,
        code: []u8,
        stream: anytype,
    ) !void {
        const tracy = trace(@src());
        defer tracy.end();

        const r_type: elf.R_X86_64 = @enumFromInt(rel.r_type());

        try stream.seekTo(rel.r_offset);
        const cwriter = stream.writer();

        const P, const A, const S, const GOT, const G, const TP, const DTP = args;

        switch (r_type) {
            .NONE => unreachable,
            .@"64" => {
                try atom.resolveDynAbsReloc(
                    target,
                    rel,
                    getDynAbsRelocAction(target, elf_file),
                    elf_file,
                    cwriter,
                );
            },

            .PLT32,
            .PC32,
            => try cwriter.writeInt(i32, @as(i32, @intCast(S + A - P)), .little),

            .GOTPCREL => try cwriter.writeInt(i32, @as(i32, @intCast(G + GOT + A - P)), .little),
            .GOTPC32 => try cwriter.writeInt(i32, @as(i32, @intCast(GOT + A - P)), .little),
            .GOTPC64 => try cwriter.writeInt(i64, GOT + A - P, .little),

            .GOTPCRELX => {
                if (!target.flags.import and !target.isIFunc(elf_file) and !target.isAbs(elf_file)) blk: {
                    relaxGotpcrelx(code[rel.r_offset - 2 ..]) catch break :blk;
                    try cwriter.writeInt(i32, @as(i32, @intCast(S + A - P)), .little);
                    return;
                }
                try cwriter.writeInt(i32, @as(i32, @intCast(G + GOT + A - P)), .little);
            },

            .REX_GOTPCRELX => {
                if (!target.flags.import and !target.isIFunc(elf_file) and !target.isAbs(elf_file)) blk: {
                    relaxRexGotpcrelx(code[rel.r_offset - 3 ..]) catch break :blk;
                    try cwriter.writeInt(i32, @as(i32, @intCast(S + A - P)), .little);
                    return;
                }
                try cwriter.writeInt(i32, @as(i32, @intCast(G + GOT + A - P)), .little);
            },

            .@"32" => try cwriter.writeInt(u32, @as(u32, @truncate(@as(u64, @intCast(S + A)))), .little),
            .@"32S" => try cwriter.writeInt(i32, @as(i32, @truncate(S + A)), .little),

            .TPOFF32 => try cwriter.writeInt(i32, @as(i32, @truncate(S + A - TP)), .little),
            .TPOFF64 => try cwriter.writeInt(i64, S + A - TP, .little),
            .DTPOFF32 => try cwriter.writeInt(i32, @as(i32, @truncate(S + A - DTP)), .little),
            .DTPOFF64 => try cwriter.writeInt(i64, S + A - DTP, .little),

            .GOTTPOFF => {
                if (target.flags.gottp) {
                    const S_ = @as(i64, @intCast(target.getGotTpAddress(elf_file)));
                    try cwriter.writeInt(i32, @as(i32, @intCast(S_ + A - P)), .little);
                } else {
                    try relaxGotTpOff(code[rel.r_offset - 3 ..]);
                    try cwriter.writeInt(i32, @as(i32, @intCast(S - TP)), .little);
                }
            },

            .TLSGD => {
                if (target.flags.tlsgd) {
                    const S_ = @as(i64, @intCast(target.getTlsGdAddress(elf_file)));
                    try cwriter.writeInt(i32, @as(i32, @intCast(S_ + A - P)), .little);
                } else if (target.flags.gottp) {
                    const S_ = @as(i64, @intCast(target.getGotTpAddress(elf_file)));
                    try relaxTlsGdToIe(&.{ rel, it.next().? }, @intCast(S_ - P), elf_file, stream);
                } else {
                    try relaxTlsGdToLe(&.{ rel, it.next().? }, @as(i32, @intCast(S - TP)), elf_file, stream);
                }
            },

            .TLSLD => {
                if (elf_file.got.tlsld_index) |entry_index| {
                    const tlsld_entry = elf_file.got.entries.items[entry_index];
                    const S_ = @as(i64, @intCast(tlsld_entry.getAddress(elf_file)));
                    try cwriter.writeInt(i32, @as(i32, @intCast(S_ + A - P)), .little);
                } else {
                    try relaxTlsLdToLe(
                        &.{ rel, it.next().? },
                        @as(i32, @intCast(TP - @as(i64, @intCast(elf_file.getTlsAddress())))),
                        elf_file,
                        stream,
                    );
                }
            },

            .GOTPC32_TLSDESC => {
                if (target.flags.tlsdesc) {
                    const S_ = @as(i64, @intCast(target.getTlsDescAddress(elf_file)));
                    try cwriter.writeInt(i32, @as(i32, @intCast(S_ + A - P)), .little);
                } else {
                    try relaxGotPcTlsDesc(code[rel.r_offset - 3 ..]);
                    try cwriter.writeInt(i32, @as(i32, @intCast(S - TP)), .little);
                }
            },

            .TLSDESC_CALL => if (!target.flags.tlsdesc) {
                // call -> nop
                try cwriter.writeAll(&.{ 0x66, 0x90 });
            },

            else => {
                elf_file.base.fatal("unhandled relocation type: {}", .{
                    relocation.fmtRelocType(rel.r_type(), .x86_64),
                });
                return error.RelocError;
            },
        }
    }

    fn resolveRelocNonAlloc(
        atom: Atom,
        elf_file: *Elf,
        rel: elf.Elf64_Rela,
        target: *const Symbol,
        args: ResolveArgs,
        it: *RelocsIterator,
        code: []u8,
        stream: anytype,
    ) !void {
        const tracy = trace(@src());
        defer tracy.end();
        _ = it;
        _ = code;

        const r_type: elf.R_X86_64 = @enumFromInt(rel.r_type());

        try stream.seekTo(rel.r_offset);
        const cwriter = stream.writer();

        _, const A, const S, const GOT, _, _, const DTP = args;

        switch (r_type) {
            .NONE => unreachable,
            .@"8" => try cwriter.writeInt(u8, @as(u8, @bitCast(@as(i8, @intCast(S + A)))), .little),
            .@"16" => try cwriter.writeInt(u16, @as(u16, @bitCast(@as(i16, @intCast(S + A)))), .little),
            .@"32" => try cwriter.writeInt(u32, @as(u32, @bitCast(@as(i32, @intCast(S + A)))), .little),
            .@"32S" => try cwriter.writeInt(i32, @as(i32, @intCast(S + A)), .little),
            .@"64" => try cwriter.writeInt(i64, S + A, .little),
            .DTPOFF32 => try cwriter.writeInt(i32, @as(i32, @intCast(S + A - DTP)), .little),
            .DTPOFF64 => try cwriter.writeInt(i64, S + A - DTP, .little),
            .GOTOFF64 => try cwriter.writeInt(i64, S + A - GOT, .little),
            .GOTPC64 => try cwriter.writeInt(i64, GOT + A, .little),
            .SIZE32 => {
                const size = @as(i64, @intCast(target.getSourceSymbol(elf_file).st_size));
                try cwriter.writeInt(u32, @as(u32, @bitCast(@as(i32, @intCast(size + A)))), .little);
            },
            .SIZE64 => {
                const size = @as(i64, @intCast(target.getSourceSymbol(elf_file).st_size));
                try cwriter.writeInt(i64, @as(i64, @intCast(size + A)), .little);
            },
            else => {
                elf_file.base.fatal("{s}: invalid relocation type for non-alloc section: {}", .{
                    atom.getName(elf_file),
                    relocation.fmtRelocType(rel.r_type(), .x86_64),
                });
                return error.RelocError;
            },
        }
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

    fn relaxTlsGdToIe(rels: []align(1) const elf.Elf64_Rela, value: i32, elf_file: *Elf, stream: anytype) !void {
        assert(rels.len == 2);
        const writer = stream.writer();
        const rel: elf.R_X86_64 = @enumFromInt(rels[1].r_type());
        switch (rel) {
            .PC32,
            .PLT32,
            => {
                var insts = [_]u8{
                    0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, // movq %fs:0,%rax
                    0x48, 0x03, 0x05, 0, 0, 0, 0, // add foo@gottpoff(%rip), %rax
                };
                mem.writeInt(i32, insts[12..][0..4], value - 12, .little);
                try stream.seekBy(-4);
                try writer.writeAll(&insts);
            },

            else => {
                elf_file.base.fatal("TODO rewrite {} when followed by {}", .{
                    relocation.fmtRelocType(rels[0].r_type(), .x86_64),
                    relocation.fmtRelocType(rels[1].r_type(), .x86_64),
                });
                return error.RelocError;
            },
        }
    }

    fn relaxTlsGdToLe(rels: []align(1) const elf.Elf64_Rela, value: i32, elf_file: *Elf, stream: anytype) !void {
        assert(rels.len == 2);
        const writer = stream.writer();
        const rel: elf.R_X86_64 = @enumFromInt(rels[1].r_type());
        switch (rel) {
            .PC32,
            .PLT32,
            .GOTPCREL,
            .GOTPCRELX,
            => {
                var insts = [_]u8{
                    0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, // movq %fs:0,%rax
                    0x48, 0x81, 0xc0, 0, 0, 0, 0, // add $tp_offset, %rax
                };
                mem.writeInt(i32, insts[12..][0..4], value, .little);
                try stream.seekBy(-4);
                try writer.writeAll(&insts);
            },

            else => {
                elf_file.base.fatal("TODO rewrite {} when followed by {}", .{
                    relocation.fmtRelocType(rels[0].r_type(), .x86_64),
                    relocation.fmtRelocType(rels[1].r_type(), .x86_64),
                });
                return error.RelocError;
            },
        }
    }

    fn relaxTlsLdToLe(rels: []align(1) const elf.Elf64_Rela, value: i32, elf_file: *Elf, stream: anytype) !void {
        assert(rels.len == 2);
        const writer = stream.writer();
        const rel: elf.R_X86_64 = @enumFromInt(rels[1].r_type());
        switch (rel) {
            .PC32,
            .PLT32,
            => {
                var insts = [_]u8{
                    0x31, 0xc0, // xor %eax, %eax
                    0x64, 0x48, 0x8b, 0, // mov %fs:(%rax), %rax
                    0x48, 0x2d, 0, 0, 0, 0, // sub $tls_size, %rax
                };
                mem.writeInt(i32, insts[8..][0..4], value, .little);
                try stream.seekBy(-3);
                try writer.writeAll(&insts);
            },

            .GOTPCREL,
            .GOTPCRELX,
            => {
                var insts = [_]u8{
                    0x31, 0xc0, // xor %eax, %eax
                    0x64, 0x48, 0x8b, 0, // mov %fs:(%rax), %rax
                    0x48, 0x2d, 0, 0, 0, 0, // sub $tls_size, %rax
                    0x90, // nop
                };
                mem.writeInt(i32, insts[8..][0..4], value, .little);
                try stream.seekBy(-3);
                try writer.writeAll(&insts);
            },

            else => {
                elf_file.base.fatal("TODO rewrite {} when followed by {}", .{
                    relocation.fmtRelocType(rels[0].r_type(), .x86_64),
                    relocation.fmtRelocType(rels[1].r_type(), .x86_64),
                });
                return error.RelocError;
            },
        }
    }

    fn relaxGotTpOff(code: []u8) !void {
        const old_inst = disassemble(code) orelse return error.RelaxFail;
        switch (old_inst.encoding.mnemonic) {
            .mov => {
                const inst = try Instruction.new(old_inst.prefix, .mov, &.{
                    old_inst.ops[0],
                    // TODO: hack to force imm32s in the assembler
                    .{ .imm = Immediate.s(-129) },
                });
                relocs_log.debug("    relaxing {} => {}", .{ old_inst.encoding, inst.encoding });
                encode(&.{inst}, code) catch return error.RelaxFail;
            },
            else => return error.RelaxFail,
        }
    }

    fn relaxGotPcTlsDesc(code: []u8) !void {
        const old_inst = disassemble(code) orelse return error.RelaxFail;
        switch (old_inst.encoding.mnemonic) {
            .lea => {
                const inst = try Instruction.new(old_inst.prefix, .mov, &.{
                    old_inst.ops[0],
                    // TODO: hack to force imm32s in the assembler
                    .{ .imm = Immediate.s(-129) },
                });
                relocs_log.debug("    relaxing {} => {}", .{ old_inst.encoding, inst.encoding });
                encode(&.{inst}, code) catch return error.RelaxFail;
            },
            else => return error.RelaxFail,
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

    const dis_x86_64 = @import("dis_x86_64");
    const Disassembler = dis_x86_64.Disassembler;
    const Instruction = dis_x86_64.Instruction;
    const Immediate = dis_x86_64.Immediate;
};

const aarch64 = struct {
    fn scanReloc(
        atom: Atom,
        elf_file: *Elf,
        rel: elf.Elf64_Rela,
        symbol: *Symbol,
        code: []u8,
        it: *RelocsIterator,
    ) !void {
        const tracy = trace(@src());
        defer tracy.end();
        _ = code;
        _ = it;

        const r_type: elf.R_AARCH64 = @enumFromInt(rel.r_type());
        const is_shared = elf_file.options.shared;

        switch (r_type) {
            .ABS64 => {
                try atom.scanReloc(symbol, rel, getDynAbsRelocAction(symbol, elf_file), elf_file);
            },

            .ADR_PREL_PG_HI21 => {
                try atom.scanReloc(symbol, rel, getPcRelocAction(symbol, elf_file), elf_file);
            },

            .ADR_GOT_PAGE => {
                // TODO: relax if possible
                symbol.flags.got = true;
            },

            .LD64_GOT_LO12_NC,
            .LD64_GOTPAGE_LO15,
            => {
                symbol.flags.got = true;
            },

            .CALL26,
            .JUMP26,
            => {
                if (symbol.flags.import) {
                    symbol.flags.plt = true;
                }
            },

            .TLSLE_ADD_TPREL_HI12,
            .TLSLE_ADD_TPREL_LO12_NC,
            => {
                if (is_shared) try atom.picError(symbol, rel, elf_file);
            },

            .TLSIE_ADR_GOTTPREL_PAGE21,
            .TLSIE_LD64_GOTTPREL_LO12_NC,
            => {
                symbol.flags.gottp = true;
            },

            .TLSGD_ADR_PAGE21,
            .TLSGD_ADD_LO12_NC,
            => {
                symbol.flags.tlsgd = true;
            },

            .TLSDESC_ADR_PAGE21,
            .TLSDESC_LD64_LO12,
            .TLSDESC_ADD_LO12,
            .TLSDESC_CALL,
            => {
                const should_relax = elf_file.options.static or
                    (elf_file.options.relax and !is_shared and !symbol.flags.import);
                if (!should_relax) {
                    symbol.flags.tlsdesc = true;
                }
            },

            .ADD_ABS_LO12_NC,
            .ADR_PREL_LO21,
            .LDST8_ABS_LO12_NC,
            .LDST16_ABS_LO12_NC,
            .LDST32_ABS_LO12_NC,
            .LDST64_ABS_LO12_NC,
            .LDST128_ABS_LO12_NC,
            .PREL32,
            .PREL64,
            => {},

            else => {
                elf_file.base.fatal("{s}: unknown relocation type: {}", .{
                    atom.getName(elf_file),
                    relocation.fmtRelocType(rel.r_type(), .aarch64),
                });
                return error.RelocError;
            },
        }
    }

    fn resolveRelocAlloc(
        atom: Atom,
        elf_file: *Elf,
        rel: elf.Elf64_Rela,
        target: *const Symbol,
        args: ResolveArgs,
        it: *RelocsIterator,
        code_buffer: []u8,
        stream: anytype,
    ) !void {
        const tracy = trace(@src());
        defer tracy.end();
        _ = it;

        const r_type: elf.R_AARCH64 = @enumFromInt(rel.r_type());

        try stream.seekTo(rel.r_offset);
        const cwriter = stream.writer();
        const code = code_buffer[rel.r_offset..][0..4];
        const object = atom.getObject(elf_file);

        const P, const A, const S, const GOT, const G, const TP, const DTP = args;
        _ = DTP;

        switch (r_type) {
            .NONE => unreachable,
            .ABS64 => {
                try atom.resolveDynAbsReloc(
                    target,
                    rel,
                    getDynAbsRelocAction(target, elf_file),
                    elf_file,
                    cwriter,
                );
            },

            .PREL32 => {
                const value = math.cast(i32, S + A - P) orelse return error.Overflow;
                mem.writeInt(u32, code, @bitCast(value), .little);
            },

            .PREL64 => {
                const value = S + A - P;
                mem.writeInt(u64, code_buffer[rel.r_offset..][0..8], @bitCast(value), .little);
            },

            .CALL26,
            .JUMP26,
            => {
                const disp: i28 = math.cast(i28, S + A - P) orelse blk: {
                    const thunk = atom.getThunk(elf_file);
                    const target_index = object.symbols.items[rel.r_sym()];
                    const S_: i64 = @intCast(thunk.getTargetAddress(target_index, elf_file));
                    break :blk math.cast(i28, S_ + A - P) orelse return error.Overflow;
                };
                aarch64_util.writeBranchImm(disp, code);
            },

            .ADR_PREL_PG_HI21 => {
                // TODO: check for relaxation of ADRP+ADD
                const saddr = @as(u64, @intCast(P));
                const taddr = @as(u64, @intCast(S + A));
                const pages = @as(u21, @bitCast(try aarch64_util.calcNumberOfPages(saddr, taddr)));
                aarch64_util.writeAdrpInst(pages, code);
            },

            .ADR_GOT_PAGE => if (target.flags.got) {
                const saddr = @as(u64, @intCast(P));
                const taddr = @as(u64, @intCast(G + GOT + A));
                const pages = @as(u21, @bitCast(try aarch64_util.calcNumberOfPages(saddr, taddr)));
                aarch64_util.writeAdrpInst(pages, code);
            } else {
                // TODO: relax
                elf_file.base.fatal("{s}: {x}: TODO relax ADR_GOT_PAGE", .{
                    atom.getName(elf_file),
                    rel.r_offset,
                });
            },

            .LD64_GOT_LO12_NC => {
                assert(target.flags.got);
                const taddr = @as(u64, @intCast(G + GOT + A));
                aarch64_util.writeLoadStoreRegInst(@divExact(@as(u12, @truncate(taddr)), 8), code);
            },

            .ADD_ABS_LO12_NC => {
                const taddr = @as(u64, @intCast(S + A));
                aarch64_util.writeAddImmInst(@truncate(taddr), code);
            },

            .LDST8_ABS_LO12_NC,
            .LDST16_ABS_LO12_NC,
            .LDST32_ABS_LO12_NC,
            .LDST64_ABS_LO12_NC,
            .LDST128_ABS_LO12_NC,
            => {
                // TODO: NC means no overflow check
                const taddr = @as(u64, @intCast(S + A));
                const offset: u12 = switch (r_type) {
                    .LDST8_ABS_LO12_NC => @truncate(taddr),
                    .LDST16_ABS_LO12_NC => @divExact(@as(u12, @truncate(taddr)), 2),
                    .LDST32_ABS_LO12_NC => @divExact(@as(u12, @truncate(taddr)), 4),
                    .LDST64_ABS_LO12_NC => @divExact(@as(u12, @truncate(taddr)), 8),
                    .LDST128_ABS_LO12_NC => @divExact(@as(u12, @truncate(taddr)), 16),
                    else => unreachable,
                };
                aarch64_util.writeLoadStoreRegInst(offset, code);
            },

            .TLSLE_ADD_TPREL_HI12 => {
                const value = math.cast(i12, (S + A - TP) >> 12) orelse return error.Overflow;
                aarch64_util.writeAddImmInst(@bitCast(value), code);
            },

            .TLSLE_ADD_TPREL_LO12_NC => {
                const value: i12 = @truncate(S + A - TP);
                aarch64_util.writeAddImmInst(@bitCast(value), code);
            },

            .TLSIE_ADR_GOTTPREL_PAGE21 => {
                const S_: i64 = @intCast(target.getGotTpAddress(elf_file));
                const saddr: u64 = @intCast(P);
                const taddr: u64 = @intCast(S_ + A);
                relocs_log.debug("      [{x} => {x}]", .{ P, taddr });
                const pages: u21 = @bitCast(try aarch64_util.calcNumberOfPages(saddr, taddr));
                aarch64_util.writeAdrpInst(pages, code);
            },

            .TLSIE_LD64_GOTTPREL_LO12_NC => {
                const S_: i64 = @intCast(target.getGotTpAddress(elf_file));
                const taddr: u64 = @intCast(S_ + A);
                relocs_log.debug("      [{x} => {x}]", .{ P, taddr });
                const offset: u12 = try math.divExact(u12, @truncate(taddr), 8);
                aarch64_util.writeLoadStoreRegInst(offset, code);
            },

            .TLSGD_ADR_PAGE21 => {
                const S_: i64 = @intCast(target.getTlsGdAddress(elf_file));
                const saddr: u64 = @intCast(P);
                const taddr: u64 = @intCast(S_ + A);
                relocs_log.debug("      [{x} => {x}]", .{ P, taddr });
                const pages: u21 = @bitCast(try aarch64_util.calcNumberOfPages(saddr, taddr));
                aarch64_util.writeAdrpInst(pages, code);
            },

            .TLSGD_ADD_LO12_NC => {
                const S_: i64 = @intCast(target.getTlsGdAddress(elf_file));
                const taddr: u64 = @intCast(S_ + A);
                relocs_log.debug("      [{x} => {x}]", .{ P, taddr });
                const offset: u12 = @truncate(taddr);
                aarch64_util.writeAddImmInst(offset, code);
            },

            .TLSDESC_ADR_PAGE21 => {
                if (target.flags.tlsdesc) {
                    const S_: i64 = @intCast(target.getTlsDescAddress(elf_file));
                    const saddr: u64 = @intCast(P);
                    const taddr: u64 = @intCast(S_ + A);
                    relocs_log.debug("      [{x} => {x}]", .{ P, taddr });
                    const pages: u21 = @bitCast(try aarch64_util.calcNumberOfPages(saddr, taddr));
                    aarch64_util.writeAdrpInst(pages, code);
                } else {
                    relocs_log.debug("      relaxing adrp => nop", .{});
                    mem.writeInt(u32, code, Instruction.nop().toU32(), .little);
                }
            },

            .TLSDESC_LD64_LO12 => {
                if (target.flags.tlsdesc) {
                    const S_: i64 = @intCast(target.getTlsDescAddress(elf_file));
                    const taddr: u64 = @intCast(S_ + A);
                    relocs_log.debug("      [{x} => {x}]", .{ P, taddr });
                    const offset: u12 = try math.divExact(u12, @truncate(taddr), 8);
                    aarch64_util.writeLoadStoreRegInst(offset, code);
                } else {
                    relocs_log.debug("      relaxing ldr => nop", .{});
                    mem.writeInt(u32, code, Instruction.nop().toU32(), .little);
                }
            },

            .TLSDESC_ADD_LO12 => {
                if (target.flags.tlsdesc) {
                    const S_: i64 = @intCast(target.getTlsDescAddress(elf_file));
                    const taddr: u64 = @intCast(S_ + A);
                    relocs_log.debug("      [{x} => {x}]", .{ P, taddr });
                    const offset: u12 = @truncate(taddr);
                    aarch64_util.writeAddImmInst(offset, code);
                } else {
                    const old_inst = Instruction{
                        .add_subtract_immediate = mem.bytesToValue(std.meta.TagPayload(
                            Instruction,
                            Instruction.add_subtract_immediate,
                        ), code),
                    };
                    const rd: Register = @enumFromInt(old_inst.add_subtract_immediate.rd);
                    relocs_log.debug("      relaxing add({s}) => movz(x0, {x})", .{ @tagName(rd), S + A - TP });
                    const value: u16 = @bitCast(math.cast(i16, (S + A - TP) >> 16) orelse return error.Overflow);
                    mem.writeInt(u32, code, Instruction.movz(.x0, value, 16).toU32(), .little);
                }
            },

            .TLSDESC_CALL => if (!target.flags.tlsdesc) {
                const old_inst = Instruction{
                    .unconditional_branch_register = mem.bytesToValue(std.meta.TagPayload(
                        Instruction,
                        Instruction.unconditional_branch_register,
                    ), code),
                };
                const rn: Register = @enumFromInt(old_inst.unconditional_branch_register.rn);
                relocs_log.debug("      relaxing br({s}) => movk(x0, {x})", .{ @tagName(rn), S + A - TP });
                const value: u16 = @bitCast(@as(i16, @truncate(S + A - TP)));
                mem.writeInt(u32, code, Instruction.movk(.x0, value, 0).toU32(), .little);
            },

            else => {
                elf_file.base.fatal("unhandled relocation type: {}", .{
                    relocation.fmtRelocType(rel.r_type(), .aarch64),
                });
                return error.RelocError;
            },
        }
    }

    fn resolveRelocNonAlloc(
        atom: Atom,
        elf_file: *Elf,
        rel: elf.Elf64_Rela,
        target: *const Symbol,
        args: ResolveArgs,
        it: *RelocsIterator,
        code: []u8,
        stream: anytype,
    ) !void {
        const tracy = trace(@src());
        defer tracy.end();
        _ = it;
        _ = code;
        _ = target;

        const r_type: elf.R_AARCH64 = @enumFromInt(rel.r_type());

        try stream.seekTo(rel.r_offset);
        const cwriter = stream.writer();

        _, const A, const S, _, _, _, _ = args;

        switch (r_type) {
            .NONE => unreachable,
            .ABS32 => try cwriter.writeInt(i32, @as(i32, @intCast(S + A)), .little),
            .ABS64 => try cwriter.writeInt(i64, S + A, .little),
            else => {
                elf_file.base.fatal("{s}: invalid relocation type for non-alloc section: {}", .{
                    atom.getName(elf_file),
                    relocation.fmtRelocType(rel.r_type(), .aarch64),
                });
                return error.RelocError;
            },
        }
    }

    const aarch64_util = @import("../aarch64.zig");
    const Instruction = aarch64_util.Instruction;
    const Register = aarch64_util.Register;
};

const riscv = struct {
    fn scanReloc(
        atom: Atom,
        elf_file: *Elf,
        rel: elf.Elf64_Rela,
        symbol: *Symbol,
        code: []u8,
        it: *RelocsIterator,
    ) !void {
        const tracy = trace(@src());
        defer tracy.end();
        _ = code;
        _ = it;

        const r_type: elf.R_RISCV = @enumFromInt(rel.r_type());

        switch (r_type) {
            .@"64" => {
                try atom.scanReloc(symbol, rel, getDynAbsRelocAction(symbol, elf_file), elf_file);
            },

            .HI20 => {
                try atom.scanReloc(symbol, rel, getAbsRelocAction(symbol, elf_file), elf_file);
            },

            .CALL_PLT => if (symbol.flags.import) {
                symbol.flags.plt = true;
            },

            .GOT_HI20 => {
                symbol.flags.got = true;
            },

            .PCREL_HI20,
            .PCREL_LO12_I,
            .PCREL_LO12_S,
            .LO12_I,
            .ADD32,
            .SUB32,
            => {},

            else => {
                elf_file.base.fatal("{s}: unknown relocation type: {}", .{
                    atom.getName(elf_file),
                    relocation.fmtRelocType(rel.r_type(), .riscv64),
                });
                return error.RelocError;
            },
        }
    }

    fn resolveRelocAlloc(
        atom: Atom,
        elf_file: *Elf,
        rel: elf.Elf64_Rela,
        target: *const Symbol,
        args: ResolveArgs,
        it: *RelocsIterator,
        code: []u8,
        stream: anytype,
    ) !void {
        const tracy = trace(@src());
        defer tracy.end();

        const r_type: elf.R_RISCV = @enumFromInt(rel.r_type());

        try stream.seekTo(rel.r_offset);
        const cwriter = stream.writer();

        const P, const A, const S, const GOT, const G, const TP, const DTP = args;
        _ = TP;
        _ = DTP;

        switch (r_type) {
            .NONE => unreachable,

            .@"64" => {
                try atom.resolveDynAbsReloc(
                    target,
                    rel,
                    getDynAbsRelocAction(target, elf_file),
                    elf_file,
                    cwriter,
                );
            },

            .ADD32 => riscv_util.writeAddend(i32, .add, code[rel.r_offset..][0..4], S + A),
            .SUB32 => riscv_util.writeAddend(i32, .sub, code[rel.r_offset..][0..4], S + A),

            .HI20 => {
                const value: u32 = @bitCast(math.cast(i32, S + A) orelse return error.Overflow);
                riscv_util.writeInstU(code[rel.r_offset..][0..4], value);
            },

            .LO12_I => {
                const value: u32 = @bitCast(math.cast(i32, S + A) orelse return error.Overflow);
                riscv_util.writeInstI(code[rel.r_offset..][0..4], value);
            },

            .GOT_HI20 => {
                assert(target.flags.got);
                const disp: u32 = @bitCast(math.cast(i32, G + GOT + A - P) orelse return error.Overflow);
                riscv_util.writeInstU(code[rel.r_offset..][0..4], disp);
            },

            .CALL_PLT => {
                // TODO: relax
                const disp: u32 = @bitCast(math.cast(i32, S + A - P) orelse return error.Overflow);
                riscv_util.writeInstU(code[rel.r_offset..][0..4], disp); // auipc
                riscv_util.writeInstI(code[rel.r_offset + 4 ..][0..4], disp); // jalr
            },

            .PCREL_HI20 => {
                const disp: u32 = @bitCast(math.cast(i32, S + A - P) orelse return error.Overflow);
                riscv_util.writeInstU(code[rel.r_offset..][0..4], disp);
            },

            .PCREL_LO12_I,
            .PCREL_LO12_S,
            => {
                assert(A == 0); // according to the spec
                // We need to find the paired reloc for this relocation.
                const object = atom.getObject(elf_file);
                const pos = it.pos;
                const atom_addr = atom.getAddress(elf_file);
                const pair = while (it.prev()) |pair| {
                    if (S == atom_addr + pair.r_offset) break pair;
                } else {
                    // TODO: search forward too
                    elf_file.base.fatal("{s}: {x}: TODO search forward for matching HI20 reloc", .{
                        atom.getName(elf_file),
                        rel.r_offset,
                    });
                    return error.RelocError;
                };
                it.pos = pos;
                const target_ = object.getSymbol(pair.r_sym(), elf_file);
                const S_ = @as(i64, @intCast(target_.getAddress(.{}, elf_file)));
                const A_ = pair.r_addend;
                const P_ = @as(i64, @intCast(atom_addr + pair.r_offset));
                const G_ = @as(i64, @intCast(target_.getGotAddress(elf_file))) - GOT;
                const disp = switch (@as(elf.R_RISCV, @enumFromInt(pair.r_type()))) {
                    .PCREL_HI20 => math.cast(i32, S_ + A_ - P_) orelse return error.Overflow,
                    .GOT_HI20 => math.cast(i32, G_ + GOT + A_ - P_) orelse return error.Overflow,
                    else => unreachable,
                };
                relocs_log.debug("      [{x} => {x}]", .{ P_, disp + P_ });
                switch (r_type) {
                    .PCREL_LO12_I => riscv_util.writeInstI(code[rel.r_offset..][0..4], @bitCast(disp)),
                    .PCREL_LO12_S => riscv_util.writeInstS(code[rel.r_offset..][0..4], @bitCast(disp)),
                    else => unreachable,
                }
            },

            else => {
                elf_file.base.fatal("unhandled relocation type: {}", .{
                    relocation.fmtRelocType(rel.r_type(), .riscv64),
                });
                return error.RelocError;
            },
        }
    }

    fn resolveRelocNonAlloc(
        atom: Atom,
        elf_file: *Elf,
        rel: elf.Elf64_Rela,
        target: *const Symbol,
        args: ResolveArgs,
        it: *RelocsIterator,
        code: []u8,
        stream: anytype,
    ) !void {
        const tracy = trace(@src());
        defer tracy.end();
        _ = target;
        _ = it;

        const r_type: elf.R_RISCV = @enumFromInt(rel.r_type());

        try stream.seekTo(rel.r_offset);
        const cwriter = stream.writer();

        _, const A, const S, const GOT, _, _, const DTP = args;
        _ = GOT;
        _ = DTP;

        switch (r_type) {
            .NONE => unreachable,

            .@"32" => try cwriter.writeInt(i32, @as(i32, @intCast(S + A)), .little),
            .@"64" => try cwriter.writeInt(i64, S + A, .little),

            .ADD8 => riscv_util.writeAddend(i8, .add, code[rel.r_offset..][0..1], S + A),
            .SUB8 => riscv_util.writeAddend(i8, .sub, code[rel.r_offset..][0..1], S + A),
            .ADD16 => riscv_util.writeAddend(i16, .add, code[rel.r_offset..][0..2], S + A),
            .SUB16 => riscv_util.writeAddend(i16, .sub, code[rel.r_offset..][0..2], S + A),
            .ADD32 => riscv_util.writeAddend(i32, .add, code[rel.r_offset..][0..4], S + A),
            .SUB32 => riscv_util.writeAddend(i32, .sub, code[rel.r_offset..][0..4], S + A),
            .ADD64 => riscv_util.writeAddend(i64, .add, code[rel.r_offset..][0..8], S + A),
            .SUB64 => riscv_util.writeAddend(i64, .sub, code[rel.r_offset..][0..8], S + A),

            .SET8 => mem.writeInt(i8, code[rel.r_offset..][0..1], @as(i8, @truncate(S + A)), .little),
            .SET16 => mem.writeInt(i16, code[rel.r_offset..][0..2], @as(i16, @truncate(S + A)), .little),
            .SET32 => mem.writeInt(i32, code[rel.r_offset..][0..4], @as(i32, @truncate(S + A)), .little),

            .SET6 => riscv_util.writeSetSub6(.set, code[rel.r_offset..][0..1], S + A),
            .SUB6 => riscv_util.writeSetSub6(.sub, code[rel.r_offset..][0..1], S + A),

            else => {
                elf_file.base.fatal("{s}: invalid relocation type for non-alloc section: {}", .{
                    atom.getName(elf_file),
                    relocation.fmtRelocType(rel.r_type(), .riscv64),
                });
                return error.RelocError;
            },
        }
    }

    const riscv_util = @import("../riscv.zig");
};

const RelocsIterator = struct {
    relocs: []const elf.Elf64_Rela,
    pos: i64 = -1,

    fn next(it: *RelocsIterator) ?elf.Elf64_Rela {
        it.pos += 1;
        if (it.pos >= it.relocs.len) return null;
        return it.relocs[@intCast(it.pos)];
    }

    fn prev(it: *RelocsIterator) ?elf.Elf64_Rela {
        if (it.pos == -1) return null;
        const rel = it.relocs[@intCast(it.pos)];
        it.pos -= 1;
        return rel;
    }

    fn skip(it: *RelocsIterator, num: usize) void {
        assert(num > 0);
        it.pos += @intCast(num);
    }
};

pub const Extra = struct {
    /// Index of the range extension thunk of this atom.
    thunk: u32 = 0,

    /// Start index of FDEs referencing this atom.
    fde_start: u32 = 0,

    /// Count of FDEs referencing this atom.
    fde_count: u32 = 0,

    /// Start index of relocations belonging to this atom.
    rel_index: u32 = 0,

    /// Count of relocations belonging to this atom.
    rel_count: u32 = 0,
};

const Atom = @This();

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const log = std.log.scoped(.elf);
const relocs_log = std.log.scoped(.relocs);
const relocation = @import("relocation.zig");
const math = std.math;
const mem = std.mem;
const trace = @import("../tracy.zig").trace;

const Allocator = mem.Allocator;
const Elf = @import("../Elf.zig");
const Fde = @import("eh_frame.zig").Fde;
const File = @import("file.zig").File;
const Object = @import("Object.zig");
const Symbol = @import("Symbol.zig");
const Thunk = @import("thunks.zig").Thunk;
