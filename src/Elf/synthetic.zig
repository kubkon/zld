pub const DynamicSection = struct {
    needed: std.ArrayListUnmanaged(u32) = .{},
    rpath: u32 = 0,

    pub fn deinit(dt: *DynamicSection, allocator: Allocator) void {
        dt.needed.deinit(allocator);
    }

    pub fn addNeeded(dt: *DynamicSection, shared: *SharedObject, elf_file: *Elf) !void {
        const gpa = elf_file.base.allocator;
        const off = try elf_file.dynstrtab.insert(gpa, shared.getSoname());
        try dt.needed.append(gpa, off);
    }

    pub fn setRpath(dt: *DynamicSection, rpath_list: []const []const u8, elf_file: *Elf) !void {
        if (rpath_list.len == 0) return;
        const gpa = elf_file.base.allocator;
        var rpath = std.ArrayList(u8).init(gpa);
        defer rpath.deinit();
        for (rpath_list, 0..) |path, i| {
            if (i > 0) try rpath.append(':');
            try rpath.appendSlice(path);
        }
        dt.rpath = try elf_file.dynstrtab.insert(gpa, rpath.items);
    }

    fn getFlags(dt: DynamicSection, elf_file: *Elf) ?u64 {
        _ = dt;
        var flags: u64 = 0;
        if (elf_file.options.z_now) {
            flags |= 8; // TODO add elf.DF_BIND_NOW;
        }
        return if (flags > 0) flags else null;
    }

    fn getFlags1(dt: DynamicSection, elf_file: *Elf) ?u64 {
        _ = dt;
        var flags_1: u64 = 0;
        if (elf_file.options.z_now) {
            flags_1 |= 1; // TODO add elf.DF_1_NOW;
        }
        return if (flags_1 > 0) flags_1 else null;
    }

    pub fn size(dt: DynamicSection, elf_file: *Elf) usize {
        var nentries: usize = 0;
        nentries += dt.needed.items.len; // NEEDED
        if (dt.rpath > 0) nentries += 1; // RUNPATH
        if (elf_file.getSectionByName(".init") != null) nentries += 1; // INIT
        if (elf_file.getSectionByName(".fini") != null) nentries += 1; // FINI
        if (elf_file.getSectionByName(".init_array") != null) nentries += 2; // INIT_ARRAY
        if (elf_file.getSectionByName(".fini_array") != null) nentries += 2; // FINI_ARRAY
        if (elf_file.rela_dyn_sect_index != null) nentries += 3; // RELA
        if (elf_file.rela_plt_sect_index != null) nentries += 3; // JMPREL
        if (elf_file.got_plt_sect_index != null) nentries += 1; // PLTGOT
        nentries += 1; // HASH
        nentries += 1; // SYMTAB
        nentries += 1; // SYMENT
        nentries += 1; // STRTAB
        nentries += 1; // STRSZ
        nentries += 1; // NULL
        if (dt.getFlags(elf_file) != null) nentries += 1; // FLAGS
        if (dt.getFlags1(elf_file) != null) nentries += 1; // FLAGS_1
        nentries += 1; // DEBUG
        return nentries * @sizeOf(elf.Elf64_Dyn);
    }

    pub fn write(dt: DynamicSection, elf_file: *Elf, writer: anytype) !void {
        // NEEDED
        for (dt.needed.items) |off| {
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_NEEDED, .d_val = off });
        }

        // RUNPATH
        // TODO add option in Options to revert to old RPATH tag
        if (dt.rpath > 0) {
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_RUNPATH, .d_val = dt.rpath });
        }

        // INIT
        if (elf_file.getSectionByName(".init")) |shndx| {
            const addr = elf_file.sections.items(.shdr)[shndx].sh_addr;
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_INIT, .d_val = addr });
        }

        // FINI
        if (elf_file.getSectionByName(".fini")) |shndx| {
            const addr = elf_file.sections.items(.shdr)[shndx].sh_addr;
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_FINI, .d_val = addr });
        }

        // INIT_ARRAY
        if (elf_file.getSectionByName(".init_array")) |shndx| {
            const shdr = elf_file.sections.items(.shdr)[shndx];
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_INIT_ARRAY, .d_val = shdr.sh_addr });
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_INIT_ARRAYSZ, .d_val = shdr.sh_size });
        }

        // FINI_ARRAY
        if (elf_file.getSectionByName(".fini_array")) |shndx| {
            const shdr = elf_file.sections.items(.shdr)[shndx];
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_FINI_ARRAY, .d_val = shdr.sh_addr });
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_FINI_ARRAYSZ, .d_val = shdr.sh_size });
        }

        // RELA
        if (elf_file.rela_dyn_sect_index) |shndx| {
            const shdr = elf_file.sections.items(.shdr)[shndx];
            const relasz = elf_file.got.sizeRela(elf_file);
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_RELA, .d_val = shdr.sh_addr });
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_RELASZ, .d_val = relasz });
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_RELAENT, .d_val = shdr.sh_entsize });
        }

        // JMPREL
        if (elf_file.rela_plt_sect_index) |shndx| {
            const shdr = elf_file.sections.items(.shdr)[shndx];
            const relasz = elf_file.plt.sizeRela();
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_JMPREL, .d_val = shdr.sh_addr });
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_PLTRELSZ, .d_val = relasz });
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_PLTREL, .d_val = elf.DT_RELA });
        }

        // PLTGOT
        if (elf_file.got_plt_sect_index) |shndx| {
            const addr = elf_file.sections.items(.shdr)[shndx].sh_addr;
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_PLTGOT, .d_val = addr });
        }

        {
            assert(elf_file.hash_sect_index != null);
            const addr = elf_file.sections.items(.shdr)[elf_file.hash_sect_index.?].sh_addr;
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_HASH, .d_val = addr });
        }

        // SYMTAB + SYMENT
        {
            assert(elf_file.dynsymtab_sect_index != null);
            const shdr = elf_file.sections.items(.shdr)[elf_file.dynsymtab_sect_index.?];
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_SYMTAB, .d_val = shdr.sh_addr });
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_SYMENT, .d_val = shdr.sh_entsize });
        }

        // STRTAB + STRSZ
        {
            assert(elf_file.dynstrtab_sect_index != null);
            const shdr = elf_file.sections.items(.shdr)[elf_file.dynstrtab_sect_index.?];
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_STRTAB, .d_val = shdr.sh_addr });
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_STRSZ, .d_val = shdr.sh_size });
        }

        // FLAGS
        if (dt.getFlags(elf_file)) |flags| {
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_FLAGS, .d_val = flags });
        }
        // FLAGS_1
        if (dt.getFlags1(elf_file)) |flags_1| {
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_FLAGS_1, .d_val = flags_1 });
        }

        // DEBUG
        try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_DEBUG, .d_val = 0 });

        // NULL
        try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_NULL, .d_val = 0 });
    }
};

pub const HashSection = struct {
    buffer: std.ArrayListUnmanaged(u8) = .{},

    pub fn deinit(hs: *HashSection, allocator: Allocator) void {
        hs.buffer.deinit(allocator);
    }

    pub fn generate(hs: *HashSection, elf_file: *Elf) !void {
        if (elf_file.dynsym.count() == 1) return;

        const gpa = elf_file.base.allocator;
        const nsyms = elf_file.dynsym.count();

        var buckets = try gpa.alloc(u32, nsyms);
        defer gpa.free(buckets);
        @memset(buckets, 0);

        var chains = try gpa.alloc(u32, nsyms);
        defer gpa.free(chains);
        @memset(chains, 0);

        for (elf_file.dynsym.symbols.items[1..], 1..) |sym_ref, i| {
            const name = elf_file.dynstrtab.getAssumeExists(sym_ref.off);
            const hash = hasher(name) % buckets.len;
            chains[@intCast(u32, i)] = buckets[hash];
            buckets[hash] = @intCast(u32, i);
        }

        try hs.buffer.ensureTotalCapacityPrecise(gpa, (2 + nsyms * 2) * 4);
        hs.buffer.writer(gpa).writeIntLittle(u32, @intCast(u32, nsyms)) catch unreachable;
        hs.buffer.writer(gpa).writeIntLittle(u32, @intCast(u32, nsyms)) catch unreachable;
        hs.buffer.writer(gpa).writeAll(mem.sliceAsBytes(buckets)) catch unreachable;
        hs.buffer.writer(gpa).writeAll(mem.sliceAsBytes(chains)) catch unreachable;
    }

    pub inline fn size(hs: HashSection) usize {
        return hs.buffer.items.len;
    }

    fn hasher(name: [:0]const u8) u32 {
        var h: u32 = 0;
        var g: u32 = 0;
        for (name) |c| {
            h = (h << 4) + c;
            g = h & 0xf0000000;
            if (g > 0) h ^= g >> 24;
            h &= ~g;
        }
        return h;
    }
};

pub const DynsymSection = struct {
    symbols: std.ArrayListUnmanaged(struct { index: u32, off: u32 }) = .{},

    pub fn deinit(dynsym: *DynsymSection, allocator: Allocator) void {
        dynsym.symbols.deinit(allocator);
    }

    pub fn addSymbol(dynsym: *DynsymSection, sym_index: u32, elf_file: *Elf) !void {
        const gpa = elf_file.base.allocator;
        const index = @intCast(u32, dynsym.symbols.items.len + 1);
        const sym = elf_file.getSymbol(sym_index);
        if (sym.getExtra(elf_file)) |extra| {
            var new_extra = extra;
            new_extra.dynamic = index;
            sym.setExtra(new_extra, elf_file);
        } else try sym.addExtra(.{ .dynamic = index }, elf_file);
        const name = try elf_file.dynstrtab.insert(gpa, sym.getName(elf_file));
        try dynsym.symbols.append(gpa, .{ .index = sym_index, .off = name });
    }

    pub inline fn size(dynsym: DynsymSection) usize {
        return dynsym.count() * @sizeOf(elf.Elf64_Sym);
    }

    pub inline fn count(dynsym: DynsymSection) u32 {
        return @intCast(u32, dynsym.symbols.items.len + 1);
    }

    pub fn write(dynsym: DynsymSection, elf_file: *Elf, writer: anytype) !void {
        try writer.writeStruct(Elf.null_sym);
        for (dynsym.symbols.items) |sym_ref| {
            const sym = elf_file.getSymbol(sym_ref.index);
            const s_sym = sym.getSourceSymbol(elf_file);
            const st_type = switch (s_sym.st_type()) {
                elf.STT_GNU_IFUNC => elf.STT_FUNC,
                else => |st_type| st_type,
            };
            try writer.writeStruct(elf.Elf64_Sym{
                .st_name = sym_ref.off,
                .st_info = (@as(u8, elf.STB_GLOBAL) << 4) | st_type,
                .st_other = s_sym.st_other,
                .st_shndx = elf.SHN_UNDEF,
                .st_value = 0,
                .st_size = 0,
            });
        }
    }
};

pub const GotSection = struct {
    symbols: std.ArrayListUnmanaged(u32) = .{},
    needs_rela: bool = false,
    output_symtab_size: Elf.SymtabSize = .{},

    pub fn deinit(got: *GotSection, allocator: Allocator) void {
        got.symbols.deinit(allocator);
    }

    pub fn addSymbol(got: *GotSection, sym_index: u32, elf_file: *Elf) !void {
        const index = @intCast(u32, got.symbols.items.len);
        const symbol = elf_file.getSymbol(sym_index);
        if (symbol.getExtra(elf_file)) |extra| {
            var new_extra = extra;
            new_extra.got = index;
            symbol.setExtra(new_extra, elf_file);
        } else try symbol.addExtra(.{ .got = index }, elf_file);
        try got.symbols.append(elf_file.base.allocator, sym_index);
    }

    pub fn sizeGot(got: GotSection) usize {
        return got.symbols.items.len * 8;
    }

    pub fn sizeRela(got: GotSection, elf_file: *Elf) usize {
        var size: usize = 0;
        for (got.symbols.items) |sym_index| {
            const sym = elf_file.getSymbol(sym_index);
            if (sym.import) size += @sizeOf(elf.Elf64_Rela);
        }
        return size;
    }

    pub fn writeGot(got: GotSection, elf_file: *Elf, writer: anytype) !void {
        for (got.symbols.items) |sym_index| {
            const sym = elf_file.getSymbol(sym_index);
            const value = if (sym.import) 0 else sym.value;
            try writer.writeIntLittle(u64, value);
        }
    }

    pub fn writeRela(got: GotSection, elf_file: *Elf, writer: anytype) !void {
        for (got.symbols.items, 0..) |sym_index, i| {
            const sym = elf_file.getSymbol(sym_index);
            if (sym.import) {
                const extra = sym.getExtra(elf_file).?;
                const r_offset = elf_file.getGotEntryAddress(@intCast(u32, i));
                const r_sym: u64 = extra.dynamic;
                const r_type: u32 = elf.R_X86_64_GLOB_DAT;
                try writer.writeStruct(elf.Elf64_Rela{
                    .r_offset = r_offset,
                    .r_info = (r_sym << 32) | r_type,
                    .r_addend = 0,
                });
            }
        }
    }

    pub fn calcSymtabSize(got: *GotSection, elf_file: *Elf) !void {
        if (elf_file.options.strip_all) return;

        got.output_symtab_size.nlocals = @intCast(u32, got.symbols.items.len);
        for (got.symbols.items) |sym_index| {
            const sym = elf_file.getSymbol(sym_index);
            got.output_symtab_size.strsize += @intCast(u32, sym.getName(elf_file).len + "$got".len + 1);
        }
    }

    pub fn writeSymtab(got: GotSection, elf_file: *Elf, ctx: Elf.WriteSymtabCtx) !void {
        if (elf_file.options.strip_all) return;

        const gpa = elf_file.base.allocator;

        var ilocal = ctx.ilocal;
        for (got.symbols.items, 0..) |sym_index, i| {
            const sym = elf_file.getSymbol(sym_index);
            const name = try std.fmt.allocPrint(gpa, "{s}$got", .{sym.getName(elf_file)});
            defer gpa.free(name);
            const st_name = try ctx.strtab.insert(gpa, name);
            ctx.symtab[ilocal] = .{
                .st_name = st_name,
                .st_info = elf.STT_OBJECT,
                .st_other = 0,
                .st_shndx = elf_file.got_sect_index.?,
                .st_value = elf_file.getGotEntryAddress(@intCast(u32, i)),
                .st_size = @sizeOf(u64),
            };
            ilocal += 1;
        }
    }
};

pub const PltSection = struct {
    symbols: std.ArrayListUnmanaged(u32) = .{},
    output_symtab_size: Elf.SymtabSize = .{},

    pub const plt_preamble_size = 32;
    pub const got_plt_preamble_size = 24;

    pub fn deinit(plt: *PltSection, allocator: Allocator) void {
        plt.symbols.deinit(allocator);
    }

    pub fn addSymbol(plt: *PltSection, sym_index: u32, elf_file: *Elf) !void {
        const index = @intCast(u32, plt.symbols.items.len);
        const symbol = elf_file.getSymbol(sym_index);
        if (symbol.getExtra(elf_file)) |extra| {
            var new_extra = extra;
            new_extra.plt = index;
            symbol.setExtra(new_extra, elf_file);
        } else try symbol.addExtra(.{ .plt = index }, elf_file);
        try plt.symbols.append(elf_file.base.allocator, sym_index);
    }

    pub fn sizePlt(plt: PltSection) usize {
        return plt_preamble_size + plt.symbols.items.len * 16;
    }

    pub fn sizeGotPlt(plt: PltSection) usize {
        return got_plt_preamble_size + plt.symbols.items.len * 8;
    }

    pub fn sizeRela(plt: PltSection) usize {
        return plt.symbols.items.len * @sizeOf(elf.Elf64_Rela);
    }

    pub fn writePlt(plt: PltSection, elf_file: *Elf, writer: anytype) !void {
        const plt_addr = elf_file.getPltAddress();
        const got_plt_addr = elf_file.getGotPltAddress();
        var preamble = [_]u8{
            0xf3, 0x0f, 0x1e, 0xfa, // endbr64
            0x41, 0x53, // push r11
            0xff, 0x35, 0x00, 0x00, 0x00, 0x00, // push qword ptr [rip] -> .got.plt[1]
            0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp qword ptr [rip] -> .got.plt[2]
        };
        var disp = @intCast(i64, got_plt_addr + 8) - @intCast(i64, plt_addr + 8) - 4;
        mem.writeIntLittle(i32, preamble[8..][0..4], @intCast(i32, disp));
        disp = @intCast(i64, got_plt_addr + 16) - @intCast(i64, plt_addr + 14) - 4;
        mem.writeIntLittle(i32, preamble[14..][0..4], @intCast(i32, disp));
        try writer.writeAll(&preamble);
        try writer.writeByteNTimes(0xcc, plt_preamble_size - preamble.len);

        for (0..plt.symbols.items.len) |i| {
            const target_addr = elf_file.getGotPltEntryAddress(@intCast(u32, i));
            const source_addr = elf_file.getPltEntryAddress(@intCast(u32, i));
            disp = @intCast(i64, target_addr) - @intCast(i64, source_addr + 12) - 4;
            var entry = [_]u8{
                0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                0x41, 0xbb, 0x00, 0x00, 0x00, 0x00, // mov r11d, N
                0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp qword ptr [rip] -> .got.plt[N]
            };
            mem.writeIntLittle(i32, entry[6..][0..4], @intCast(i32, i));
            mem.writeIntLittle(i32, entry[12..][0..4], @intCast(i32, disp));
            try writer.writeAll(&entry);
        }
    }

    pub fn writeGotPlt(plt: PltSection, elf_file: *Elf, writer: anytype) !void {
        {
            // [0]: _DYNAMIC
            const symbol = elf_file.getSymbol(elf_file.dynamic_index.?);
            try writer.writeIntLittle(u64, symbol.value);
        }
        // [1]: 0x0
        // [2]: 0x0
        try writer.writeIntLittle(u64, 0x0);
        try writer.writeIntLittle(u64, 0x0);
        const plt_addr = elf_file.getPltAddress();
        for (0..plt.symbols.items.len) |_| {
            // [N]: .plt
            try writer.writeIntLittle(u64, plt_addr);
        }
    }

    pub fn writeRela(plt: PltSection, elf_file: *Elf, writer: anytype) !void {
        for (plt.symbols.items, 0..) |sym_index, i| {
            const sym = elf_file.getSymbol(sym_index);
            assert(sym.import);
            const extra = sym.getExtra(elf_file).?;
            const r_offset = elf_file.getGotPltEntryAddress(@intCast(u32, i));
            const r_sym: u64 = extra.dynamic;
            const r_type: u32 = elf.R_X86_64_JUMP_SLOT;
            try writer.writeStruct(elf.Elf64_Rela{
                .r_offset = r_offset,
                .r_info = (r_sym << 32) | r_type,
                .r_addend = 0,
            });
        }
    }

    pub fn calcSymtabSize(plt: *PltSection, elf_file: *Elf) !void {
        if (elf_file.options.strip_all) return;

        plt.output_symtab_size.nlocals = @intCast(u32, plt.symbols.items.len);
        for (plt.symbols.items) |sym_index| {
            const sym = elf_file.getSymbol(sym_index);
            plt.output_symtab_size.strsize += @intCast(u32, sym.getName(elf_file).len + "$plt".len + 1);
        }
    }

    pub fn writeSymtab(plt: PltSection, elf_file: *Elf, ctx: Elf.WriteSymtabCtx) !void {
        if (elf_file.options.strip_all) return;

        const gpa = elf_file.base.allocator;

        var ilocal = ctx.ilocal;
        for (plt.symbols.items, 0..) |sym_index, i| {
            const sym = elf_file.getSymbol(sym_index);
            const name = try std.fmt.allocPrint(gpa, "{s}$plt", .{sym.getName(elf_file)});
            defer gpa.free(name);
            const st_name = try ctx.strtab.insert(gpa, name);
            ctx.symtab[ilocal] = .{
                .st_name = st_name,
                .st_info = elf.STT_FUNC,
                .st_other = 0,
                .st_shndx = elf_file.plt_sect_index.?,
                .st_value = elf_file.getPltEntryAddress(@intCast(u32, i)),
                .st_size = 16,
            };
            ilocal += 1;
        }
    }
};

pub const PltGotSection = struct {
    symbols: std.ArrayListUnmanaged(u32) = .{},
    output_symtab_size: Elf.SymtabSize = .{},

    pub fn deinit(plt_got: *PltGotSection, allocator: Allocator) void {
        plt_got.symbols.deinit(allocator);
    }

    pub fn addSymbol(plt_got: *PltGotSection, sym_index: u32, elf_file: *Elf) !void {
        const index = @intCast(u32, plt_got.symbols.items.len);
        const symbol = elf_file.getSymbol(sym_index);
        if (symbol.getExtra(elf_file)) |extra| {
            var new_extra = extra;
            new_extra.plt_got = index;
            symbol.setExtra(new_extra, elf_file);
        } else try symbol.addExtra(.{ .plt_got = index }, elf_file);
        try plt_got.symbols.append(elf_file.base.allocator, sym_index);
    }

    pub fn size(plt_got: PltGotSection) usize {
        return plt_got.symbols.items.len * 16;
    }

    pub fn write(plt_got: PltGotSection, elf_file: *Elf, writer: anytype) !void {
        for (plt_got.symbols.items, 0..) |sym_index, i| {
            const sym = elf_file.getSymbol(sym_index);
            assert(sym.import);
            const extra = sym.getExtra(elf_file).?;
            const target_addr = elf_file.getGotEntryAddress(extra.got);
            const source_addr = elf_file.getPltGotEntryAddress(@intCast(u32, i));
            const disp = @intCast(i64, target_addr) - @intCast(i64, source_addr + 6) - 4;
            var entry = [_]u8{
                0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp qword ptr [rip] -> .got[N]
            };
            mem.writeIntLittle(i32, entry[6..][0..4], @intCast(i32, disp));
            try writer.writeAll(&entry);
        }
    }

    pub fn calcSymtabSize(plt_got: *PltGotSection, elf_file: *Elf) !void {
        if (elf_file.options.strip_all) return;

        plt_got.output_symtab_size.nlocals = @intCast(u32, plt_got.symbols.items.len);
        for (plt_got.symbols.items) |sym_index| {
            const sym = elf_file.getSymbol(sym_index);
            plt_got.output_symtab_size.strsize += @intCast(u32, sym.getName(elf_file).len + "$pltgot".len + 1);
        }
    }

    pub fn writeSymtab(plt_got: PltGotSection, elf_file: *Elf, ctx: Elf.WriteSymtabCtx) !void {
        if (elf_file.options.strip_all) return;

        const gpa = elf_file.base.allocator;

        var ilocal = ctx.ilocal;
        for (plt_got.symbols.items, 0..) |sym_index, i| {
            const sym = elf_file.getSymbol(sym_index);
            const name = try std.fmt.allocPrint(gpa, "{s}$pltgot", .{sym.getName(elf_file)});
            defer gpa.free(name);
            const st_name = try ctx.strtab.insert(gpa, name);
            ctx.symtab[ilocal] = .{
                .st_name = st_name,
                .st_info = elf.STT_FUNC,
                .st_other = 0,
                .st_shndx = elf_file.plt_got_sect_index.?,
                .st_value = elf_file.getPltGotEntryAddress(@intCast(u32, i)),
                .st_size = 16,
            };
            ilocal += 1;
        }
    }
};

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const mem = std.mem;

const Allocator = mem.Allocator;
const Elf = @import("../Elf.zig");
const SharedObject = @import("SharedObject.zig");
