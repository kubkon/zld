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
        if (elf_file.options.pie) {
            flags_1 |= 0x8000000; // TODO add elf.DF_1_PIE;
        }
        return if (flags_1 > 0) flags_1 else null;
    }

    pub fn size(dt: DynamicSection, elf_file: *Elf) usize {
        const is_shared = elf_file.options.output_mode == .lib;
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
        if (elf_file.gnu_hash_sect_index != null) nentries += 1; // GNU_HASH
        nentries += 1; // SYMTAB
        nentries += 1; // SYMENT
        nentries += 1; // STRTAB
        nentries += 1; // STRSZ
        if (elf_file.versym_sect_index != null) nentries += 1; // VERSYM
        if (elf_file.verneed_sect_index != null) nentries += 2; // VERNEED
        if (dt.getFlags(elf_file) != null) nentries += 1; // FLAGS
        if (dt.getFlags1(elf_file) != null) nentries += 1; // FLAGS_1
        if (!is_shared) nentries += 1; // DEBUG
        nentries += 1; // NULL
        return nentries * @sizeOf(elf.Elf64_Dyn);
    }

    pub fn write(dt: DynamicSection, elf_file: *Elf, writer: anytype) !void {
        const is_shared = elf_file.options.output_mode == .lib;

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
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_RELA, .d_val = shdr.sh_addr });
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_RELASZ, .d_val = shdr.sh_size });
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_RELAENT, .d_val = shdr.sh_entsize });
        }

        // JMPREL
        if (elf_file.rela_plt_sect_index) |shndx| {
            const shdr = elf_file.sections.items(.shdr)[shndx];
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_JMPREL, .d_val = shdr.sh_addr });
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_PLTRELSZ, .d_val = shdr.sh_size });
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

        if (elf_file.gnu_hash_sect_index) |shndx| {
            const addr = elf_file.sections.items(.shdr)[shndx].sh_addr;
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_GNU_HASH, .d_val = addr });
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

        // VERSYM
        if (elf_file.versym_sect_index) |shndx| {
            const addr = elf_file.sections.items(.shdr)[shndx].sh_addr;
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_VERSYM, .d_val = addr });
        }

        // VERNEED + VERNEEDNUM
        if (elf_file.verneed_sect_index) |shndx| {
            const addr = elf_file.sections.items(.shdr)[shndx].sh_addr;
            try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_VERNEED, .d_val = addr });
            try writer.writeStruct(elf.Elf64_Dyn{
                .d_tag = elf.DT_VERNEEDNUM,
                .d_val = elf_file.verneed.verneed.items.len,
            });
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
        if (!is_shared) try writer.writeStruct(elf.Elf64_Dyn{ .d_tag = elf.DT_DEBUG, .d_val = 0 });

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

        for (elf_file.dynsym.symbols.items, 1..) |sym_ref, i| {
            const name = elf_file.dynstrtab.getAssumeExists(sym_ref.off);
            const hash = hasher(name) % buckets.len;
            chains[@as(u32, @intCast(i))] = buckets[hash];
            buckets[hash] = @as(u32, @intCast(i));
        }

        try hs.buffer.ensureTotalCapacityPrecise(gpa, (2 + nsyms * 2) * 4);
        hs.buffer.writer(gpa).writeIntLittle(u32, @as(u32, @intCast(nsyms))) catch unreachable;
        hs.buffer.writer(gpa).writeIntLittle(u32, @as(u32, @intCast(nsyms))) catch unreachable;
        hs.buffer.writer(gpa).writeAll(mem.sliceAsBytes(buckets)) catch unreachable;
        hs.buffer.writer(gpa).writeAll(mem.sliceAsBytes(chains)) catch unreachable;
    }

    pub inline fn size(hs: HashSection) usize {
        return hs.buffer.items.len;
    }

    pub fn hasher(name: [:0]const u8) u32 {
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

pub const GnuHashSection = struct {
    num_buckets: u32 = 0,
    num_bloom: u32 = 1,
    num_exports: u32 = 0,

    pub const load_factor = 8;
    pub const header_size = 16;
    pub const bloom_shift = 26;

    fn getExports(elf_file: *Elf) []const DynsymSection.Dynsym {
        const start = for (elf_file.dynsym.symbols.items, 0..) |dsym, i| {
            const sym = elf_file.getSymbol(dsym.index);
            if (sym.flags.@"export") break i;
        } else elf_file.dynsym.symbols.items.len;
        return elf_file.dynsym.symbols.items[start..];
    }

    inline fn bitCeil(x: u64) u64 {
        if (@popCount(x) == 1) return x;
        return @as(u64, @intCast(@as(u128, 1) << (64 - @clz(x))));
    }

    pub fn calcSize(hash: *GnuHashSection, elf_file: *Elf) !void {
        hash.num_exports = @as(u32, @intCast(getExports(elf_file).len));
        if (hash.num_exports > 0) {
            const num_bits = hash.num_exports * 12;
            hash.num_bloom = @as(u32, @intCast(bitCeil(@divTrunc(num_bits, 64))));
        }
    }

    pub fn size(hash: GnuHashSection) usize {
        return header_size + hash.num_bloom * 8 + hash.num_buckets * 4 + hash.num_exports * 4;
    }

    pub fn write(hash: GnuHashSection, elf_file: *Elf, writer: anytype) !void {
        const exports = getExports(elf_file);
        const export_off = elf_file.dynsym.count() - hash.num_exports;

        var counting = std.io.countingWriter(writer);
        const cwriter = counting.writer();

        try cwriter.writeIntLittle(u32, hash.num_buckets);
        try cwriter.writeIntLittle(u32, export_off);
        try cwriter.writeIntLittle(u32, hash.num_bloom);
        try cwriter.writeIntLittle(u32, bloom_shift);

        const gpa = elf_file.base.allocator;
        const hashes = try gpa.alloc(u32, exports.len);
        defer gpa.free(hashes);
        const indices = try gpa.alloc(u32, exports.len);
        defer gpa.free(indices);

        // Compose and write the bloom filter
        const bloom = try gpa.alloc(u64, hash.num_bloom);
        defer gpa.free(bloom);
        @memset(bloom, 0);

        for (exports, 0..) |dsym, i| {
            const sym = elf_file.getSymbol(dsym.index);
            const h = hasher(sym.getName(elf_file));
            hashes[i] = h;
            indices[i] = h % hash.num_buckets;
            const idx = @divTrunc(h, 64) % hash.num_bloom;
            bloom[idx] |= @as(u64, 1) << @as(u6, @intCast(h % 64));
            bloom[idx] |= @as(u64, 1) << @as(u6, @intCast((h >> bloom_shift) % 64));
        }

        try cwriter.writeAll(mem.sliceAsBytes(bloom));

        // Fill in the hash bucket indices
        const buckets = try gpa.alloc(u32, hash.num_buckets);
        defer gpa.free(buckets);
        @memset(buckets, 0);

        for (0..hash.num_exports) |i| {
            if (buckets[indices[i]] == 0) {
                buckets[indices[i]] = @as(u32, @intCast(i + export_off));
            }
        }

        try cwriter.writeAll(mem.sliceAsBytes(buckets));

        // Finally, write the hash table
        const table = try gpa.alloc(u32, hash.num_exports);
        defer gpa.free(table);
        @memset(table, 0);

        for (0..hash.num_exports) |i| {
            const h = hashes[i];
            if (i == exports.len - 1 or indices[i] != indices[i + 1]) {
                table[i] = h | 1;
            } else {
                table[i] = h & ~@as(u32, 1);
            }
        }

        try cwriter.writeAll(mem.sliceAsBytes(table));

        assert(counting.bytes_written == hash.size());
    }

    pub fn hasher(name: [:0]const u8) u32 {
        var h: u32 = 5381;
        for (name) |c| {
            h = (h << 5) +% h +% c;
        }
        return h;
    }
};

pub const DynsymSection = struct {
    symbols: std.ArrayListUnmanaged(Dynsym) = .{},

    pub const Dynsym = struct {
        index: u32,
        off: u32,
    };

    pub fn deinit(dynsym: *DynsymSection, allocator: Allocator) void {
        dynsym.symbols.deinit(allocator);
    }

    pub fn addSymbol(dynsym: *DynsymSection, sym_index: u32, elf_file: *Elf) !void {
        const gpa = elf_file.base.allocator;
        const index = @as(u32, @intCast(dynsym.symbols.items.len + 1));
        const sym = elf_file.getSymbol(sym_index);
        sym.flags.has_dynamic = true;
        if (sym.getExtra(elf_file)) |extra| {
            var new_extra = extra;
            new_extra.dynamic = index;
            sym.setExtra(new_extra, elf_file);
        } else try sym.addExtra(.{ .dynamic = index }, elf_file);
        const name = try elf_file.dynstrtab.insert(gpa, sym.getName(elf_file));
        try dynsym.symbols.append(gpa, .{ .index = sym_index, .off = name });
    }

    pub fn sort(dynsym: *DynsymSection, elf_file: *Elf) void {
        const Sort = struct {
            pub fn lessThan(ctx: *Elf, lhs: Dynsym, rhs: Dynsym) bool {
                const lhs_sym = ctx.getSymbol(lhs.index);
                const rhs_sym = ctx.getSymbol(rhs.index);

                if (lhs_sym.flags.@"export" != rhs_sym.flags.@"export") {
                    return rhs_sym.flags.@"export";
                }

                // TODO cache hash values
                const nbuckets = ctx.gnu_hash.num_buckets;
                const lhs_hash = GnuHashSection.hasher(lhs_sym.getName(ctx)) % nbuckets;
                const rhs_hash = GnuHashSection.hasher(rhs_sym.getName(ctx)) % nbuckets;

                if (lhs_hash == rhs_hash)
                    return lhs_sym.getExtra(ctx).?.dynamic < rhs_sym.getExtra(ctx).?.dynamic;
                return lhs_hash < rhs_hash;
            }
        };

        var num_exports: u32 = 0;
        for (dynsym.symbols.items) |dsym| {
            const sym = elf_file.getSymbol(dsym.index);
            if (sym.flags.@"export") num_exports += 1;
        }

        elf_file.gnu_hash.num_buckets = @divTrunc(num_exports, GnuHashSection.load_factor) + 1;

        std.mem.sort(Dynsym, dynsym.symbols.items, elf_file, Sort.lessThan);

        for (dynsym.symbols.items, 1..) |dsym, index| {
            const sym = elf_file.getSymbol(dsym.index);
            var extra = sym.getExtra(elf_file).?;
            extra.dynamic = @as(u32, @intCast(index));
            sym.setExtra(extra, elf_file);
        }
    }

    pub inline fn size(dynsym: DynsymSection) usize {
        return dynsym.count() * @sizeOf(elf.Elf64_Sym);
    }

    pub inline fn count(dynsym: DynsymSection) u32 {
        return @as(u32, @intCast(dynsym.symbols.items.len + 1));
    }

    pub fn write(dynsym: DynsymSection, elf_file: *Elf, writer: anytype) !void {
        try writer.writeStruct(Elf.null_sym);
        for (dynsym.symbols.items) |sym_ref| {
            const sym = elf_file.getSymbol(sym_ref.index);
            try writer.writeStruct(sym.asElfSym(sym_ref.off, elf_file));
        }
    }
};

pub const VerneedSection = struct {
    verneed: std.ArrayListUnmanaged(elf.Elf64_Verneed) = .{},
    vernaux: std.ArrayListUnmanaged(elf.Elf64_Vernaux) = .{},
    index: elf.Elf64_Versym = Elf.VER_NDX_GLOBAL + 1,

    pub fn deinit(vern: *VerneedSection, allocator: Allocator) void {
        vern.verneed.deinit(allocator);
        vern.vernaux.deinit(allocator);
    }

    pub fn generate(vern: *VerneedSection, elf_file: *Elf) !void {
        const dynsyms = elf_file.dynsym.symbols.items;
        var versyms = elf_file.versym.items;

        const SymWithVersion = struct {
            idx: usize,
            shared: u32,
            version: elf.Elf64_Versym,

            fn getSoname(this: @This(), ctx: *Elf) []const u8 {
                const shared = ctx.getFile(this.shared).?.shared;
                return shared.getSoname();
            }

            fn getVersionString(this: @This(), ctx: *Elf) [:0]const u8 {
                const shared = ctx.getFile(this.shared).?.shared;
                return shared.getVersionString(this.version);
            }

            pub fn lessThan(ctx: *Elf, lhs: @This(), rhs: @This()) bool {
                if (lhs.shared == rhs.shared) return lhs.version < rhs.version;
                return mem.lessThan(u8, lhs.getSoname(ctx), rhs.getSoname(ctx));
            }
        };

        const gpa = elf_file.base.allocator;
        var verneed = std.ArrayList(SymWithVersion).init(gpa);
        defer verneed.deinit();
        try verneed.ensureTotalCapacity(dynsyms.len);

        for (dynsyms, 1..) |dynsym, i| {
            const symbol = elf_file.getSymbol(dynsym.index);
            if (symbol.flags.import and symbol.ver_idx & Elf.VERSYM_VERSION > Elf.VER_NDX_GLOBAL) {
                const shared = symbol.getFile(elf_file).?.shared;
                verneed.appendAssumeCapacity(.{
                    .idx = i,
                    .shared = shared.index,
                    .version = symbol.ver_idx,
                });
            }
        }

        mem.sort(SymWithVersion, verneed.items, elf_file, SymWithVersion.lessThan);

        var last = verneed.items[0];
        var last_verneed = try vern.addVerneed(last.getSoname(elf_file), elf_file);
        var last_vernaux = try vern.addVernaux(last_verneed, last.getVersionString(elf_file), elf_file);
        versyms[last.idx] = last_vernaux.vna_other;

        for (verneed.items[1..]) |ver| {
            if (ver.shared == last.shared) {
                if (ver.version != last.version) {
                    last_vernaux = try vern.addVernaux(last_verneed, ver.getVersionString(elf_file), elf_file);
                }
            } else {
                last_verneed = try vern.addVerneed(ver.getSoname(elf_file), elf_file);
                last_vernaux = try vern.addVernaux(last_verneed, ver.getVersionString(elf_file), elf_file);
            }
            last = ver;
            versyms[ver.idx] = last_vernaux.vna_other;
        }

        // Fixup offsets
        var count: usize = 0;
        var verneed_off: u32 = 0;
        var vernaux_off: u32 = @as(u32, @intCast(vern.verneed.items.len)) * @sizeOf(elf.Elf64_Verneed);
        for (vern.verneed.items, 0..) |*vsym, vsym_i| {
            if (vsym_i < vern.verneed.items.len - 1) vsym.vn_next = @sizeOf(elf.Elf64_Verneed);
            vsym.vn_aux = vernaux_off - verneed_off;
            var inner_off: u32 = 0;
            for (vern.vernaux.items[count..][0..vsym.vn_cnt], 0..) |*vaux, vaux_i| {
                if (vaux_i < vsym.vn_cnt - 1) vaux.vna_next = @sizeOf(elf.Elf64_Vernaux);
                inner_off += @sizeOf(elf.Elf64_Vernaux);
            }
            vernaux_off += inner_off;
            verneed_off += @sizeOf(elf.Elf64_Verneed);
            count += vsym.vn_cnt;
        }
    }

    fn addVerneed(vern: *VerneedSection, soname: []const u8, elf_file: *Elf) !*elf.Elf64_Verneed {
        const gpa = elf_file.base.allocator;
        const sym = try vern.verneed.addOne(gpa);
        sym.* = .{
            .vn_version = 1,
            .vn_cnt = 0,
            .vn_file = try elf_file.dynstrtab.insert(gpa, soname),
            .vn_aux = 0,
            .vn_next = 0,
        };
        return sym;
    }

    fn addVernaux(
        vern: *VerneedSection,
        verneed_sym: *elf.Elf64_Verneed,
        version: [:0]const u8,
        elf_file: *Elf,
    ) !elf.Elf64_Vernaux {
        const gpa = elf_file.base.allocator;
        const sym = try vern.vernaux.addOne(gpa);
        sym.* = .{
            .vna_hash = HashSection.hasher(version),
            .vna_flags = 0,
            .vna_other = vern.index,
            .vna_name = try elf_file.dynstrtab.insert(gpa, version),
            .vna_next = 0,
        };
        verneed_sym.vn_cnt += 1;
        vern.index += 1;
        return sym.*;
    }

    pub fn size(vern: VerneedSection) usize {
        return vern.verneed.items.len * @sizeOf(elf.Elf64_Verneed) + vern.vernaux.items.len * @sizeOf(elf.Elf64_Vernaux);
    }

    pub fn write(vern: VerneedSection, writer: anytype) !void {
        try writer.writeAll(mem.sliceAsBytes(vern.verneed.items));
        try writer.writeAll(mem.sliceAsBytes(vern.vernaux.items));
    }
};

pub const GotSection = struct {
    symbols: std.ArrayListUnmanaged(GotSymbol) = .{},
    needs_rela: bool = false,
    emit_tlsld: bool = false,
    output_symtab_size: Elf.SymtabSize = .{},
    next_index: u32 = 0,

    const GotSymbol = union(enum) {
        got: u32,
        tlsgd: u32,

        pub inline fn getIndex(gt: GotSymbol) u32 {
            return switch (gt) {
                inline else => |x| x,
            };
        }
    };

    pub fn deinit(got: *GotSection, allocator: Allocator) void {
        got.symbols.deinit(allocator);
    }

    pub fn addGotSymbol(got: *GotSection, sym_index: u32, elf_file: *Elf) !void {
        const index = got.next_index;
        const symbol = elf_file.getSymbol(sym_index);
        if (symbol.getExtra(elf_file)) |extra| {
            var new_extra = extra;
            new_extra.got = index;
            symbol.setExtra(new_extra, elf_file);
        } else try symbol.addExtra(.{ .got = index }, elf_file);
        try got.symbols.append(elf_file.base.allocator, .{ .got = sym_index });
        got.next_index += 1;
    }

    pub fn addTlsGdSymbol(got: *GotSection, sym_index: u32, elf_file: *Elf) !void {
        const index = got.next_index;
        const symbol = elf_file.getSymbol(sym_index);
        if (symbol.getExtra(elf_file)) |extra| {
            var new_extra = extra;
            new_extra.tlsgd = index;
            symbol.setExtra(new_extra, elf_file);
        } else try symbol.addExtra(.{ .tlsgd = index }, elf_file);
        try got.symbols.append(elf_file.base.allocator, .{ .tlsgd = sym_index });
        got.next_index += 2;
    }

    pub fn size(got: GotSection) usize {
        var s: usize = 0;
        for (got.symbols.items) |sym| switch (sym) {
            .got => s += 8,
            .tlsgd => s += 16,
        };
        if (got.emit_tlsld) s += 8;
        return s;
    }

    pub fn write(got: GotSection, elf_file: *Elf, writer: anytype) !void {
        const is_shared = elf_file.options.output_mode == .lib;

        for (got.symbols.items) |sym| {
            const symbol = elf_file.getSymbol(sym.getIndex());
            switch (sym) {
                .got => {
                    const value = if (symbol.flags.import) 0 else symbol.value;
                    try writer.writeIntLittle(u64, value);
                },
                .tlsgd => {
                    if (symbol.flags.import) {
                        try writer.writeIntLittle(u64, 0);
                        try writer.writeIntLittle(u64, 0);
                    } else {
                        try writer.writeIntLittle(u64, if (is_shared) @as(u64, 0) else 1);
                        try writer.writeIntLittle(u64, symbol.getAddress(.{}, elf_file) - elf_file.getDtpAddress());
                    }
                },
            }
        }

        if (got.emit_tlsld) {
            try writer.writeIntLittle(u64, 1); // TODO we assume executable output here
        }
    }

    pub fn addRela(got: GotSection, elf_file: *Elf) !void {
        const is_shared = elf_file.options.output_mode == .lib;
        try elf_file.rela_dyn.ensureUnusedCapacity(elf_file.base.allocator, got.numRela(elf_file));

        for (got.symbols.items) |sym| {
            const symbol = elf_file.getSymbol(sym.getIndex());
            const extra = symbol.getExtra(elf_file).?;

            switch (sym) {
                .got => {
                    const offset = symbol.getGotAddress(elf_file);

                    if (symbol.flags.import) {
                        elf_file.addRelaDynAssumeCapacity(.{
                            .offset = offset,
                            .sym = extra.dynamic,
                            .type = elf.R_X86_64_GLOB_DAT,
                        });
                        continue;
                    }

                    if (symbol.isIFunc(elf_file)) {
                        elf_file.addRelaDynAssumeCapacity(.{
                            .offset = offset,
                            .type = elf.R_X86_64_IRELATIVE,
                            .addend = @intCast(symbol.getAddress(.{ .plt = false }, elf_file)),
                        });
                        continue;
                    }

                    if (elf_file.options.pic and !symbol.isAbs(elf_file)) {
                        elf_file.addRelaDynAssumeCapacity(.{
                            .offset = offset,
                            .type = elf.R_X86_64_RELATIVE,
                            .addend = @intCast(symbol.getAddress(.{ .plt = false }, elf_file)),
                        });
                    }
                },
                .tlsgd => {
                    const offset = symbol.getTlsGdAddress(elf_file);

                    if (symbol.flags.import) {
                        elf_file.addRelaDynAssumeCapacity(.{
                            .offset = offset,
                            .sym = extra.dynamic,
                            .type = elf.R_X86_64_DTPMOD64,
                        });
                        elf_file.addRelaDynAssumeCapacity(.{
                            .offset = offset + 8,
                            .sym = extra.dynamic,
                            .type = elf.R_X86_64_DTPOFF64,
                        });
                    } else if (is_shared) {
                        elf_file.addRelaDynAssumeCapacity(.{
                            .offset = offset,
                            .sym = extra.dynamic,
                            .type = elf.R_X86_64_DTPMOD64,
                        });
                    }
                },
            }
        }
    }

    pub fn numRela(got: GotSection, elf_file: *Elf) usize {
        const is_shared = elf_file.options.output_mode == .lib;
        var num: usize = 0;
        for (got.symbols.items) |sym| {
            const symbol = elf_file.getSymbol(sym.getIndex());
            switch (sym) {
                .got => if (symbol.flags.import or
                    symbol.isIFunc(elf_file) or (elf_file.options.pic and !symbol.isAbs(elf_file)))
                {
                    num += 1;
                },
                .tlsgd => if (symbol.flags.import) {
                    num += 2;
                } else if (is_shared) {
                    num += 1;
                },
            }
        }
        return num;
    }

    pub fn calcSymtabSize(got: *GotSection, elf_file: *Elf) !void {
        if (elf_file.options.strip_all) return;

        got.output_symtab_size.nlocals = @as(u32, @intCast(got.symbols.items.len));
        for (got.symbols.items) |sym| {
            const suffix_len = switch (sym) {
                .tlsgd => "$tlsgd".len,
                .got => "$got".len,
            };
            const symbol = elf_file.getSymbol(sym.getIndex());
            const name_len = symbol.getName(elf_file).len;
            got.output_symtab_size.strsize += @as(u32, @intCast(name_len + suffix_len + 1));
        }

        if (got.emit_tlsld) {
            got.output_symtab_size.nlocals += 1;
            got.output_symtab_size.strsize += @as(u32, @intCast("$tlsld".len + 1));
        }
    }

    pub fn writeSymtab(got: GotSection, elf_file: *Elf, ctx: Elf.WriteSymtabCtx) !void {
        if (elf_file.options.strip_all) return;

        const gpa = elf_file.base.allocator;

        var ilocal = ctx.ilocal;
        for (got.symbols.items) |sym| {
            const suffix = switch (sym) {
                .tlsgd => "$tlsgd",
                .got => "$got",
            };
            const symbol = elf_file.getSymbol(sym.getIndex());
            const name = try std.fmt.allocPrint(gpa, "{s}{s}", .{ symbol.getName(elf_file), suffix });
            defer gpa.free(name);
            const st_name = try ctx.strtab.insert(gpa, name);
            const st_value = switch (sym) {
                .tlsgd => symbol.getTlsGdAddress(elf_file),
                .got => symbol.getGotAddress(elf_file),
            };
            const st_size: u64 = switch (sym) {
                .tlsgd => 16,
                .got => 8,
            };
            ctx.symtab[ilocal] = .{
                .st_name = st_name,
                .st_info = elf.STT_OBJECT,
                .st_other = 0,
                .st_shndx = elf_file.got_sect_index.?,
                .st_value = st_value,
                .st_size = st_size,
            };
            ilocal += 1;
        }

        if (got.emit_tlsld) {
            const st_name = try ctx.strtab.insert(gpa, "$tlsld");
            ctx.symtab[ilocal] = .{
                .st_name = st_name,
                .st_info = elf.STT_OBJECT,
                .st_other = 0,
                .st_shndx = elf_file.got_sect_index.?,
                .st_value = elf_file.getTlsLdAddress(),
                .st_size = @sizeOf(u64),
            };
            ilocal += 1;
        }
    }
};

pub const PltSection = struct {
    symbols: std.ArrayListUnmanaged(u32) = .{},
    output_symtab_size: Elf.SymtabSize = .{},

    pub const preamble_size = 32;

    pub fn deinit(plt: *PltSection, allocator: Allocator) void {
        plt.symbols.deinit(allocator);
    }

    pub fn addSymbol(plt: *PltSection, sym_index: u32, elf_file: *Elf) !void {
        const index = @as(u32, @intCast(plt.symbols.items.len));
        const symbol = elf_file.getSymbol(sym_index);
        if (symbol.getExtra(elf_file)) |extra| {
            var new_extra = extra;
            new_extra.plt = index;
            symbol.setExtra(new_extra, elf_file);
        } else try symbol.addExtra(.{ .plt = index }, elf_file);
        try plt.symbols.append(elf_file.base.allocator, sym_index);
    }

    pub fn size(plt: PltSection) usize {
        return preamble_size + plt.symbols.items.len * 16;
    }

    pub fn write(plt: PltSection, elf_file: *Elf, writer: anytype) !void {
        const plt_addr = elf_file.getSectionAddress(elf_file.plt_sect_index.?);
        const got_plt_addr = elf_file.getSectionAddress(elf_file.got_plt_sect_index.?);
        var preamble = [_]u8{
            0xf3, 0x0f, 0x1e, 0xfa, // endbr64
            0x41, 0x53, // push r11
            0xff, 0x35, 0x00, 0x00, 0x00, 0x00, // push qword ptr [rip] -> .got.plt[1]
            0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp qword ptr [rip] -> .got.plt[2]
        };
        var disp = @as(i64, @intCast(got_plt_addr + 8)) - @as(i64, @intCast(plt_addr + 8)) - 4;
        mem.writeIntLittle(i32, preamble[8..][0..4], @as(i32, @intCast(disp)));
        disp = @as(i64, @intCast(got_plt_addr + 16)) - @as(i64, @intCast(plt_addr + 14)) - 4;
        mem.writeIntLittle(i32, preamble[14..][0..4], @as(i32, @intCast(disp)));
        try writer.writeAll(&preamble);
        try writer.writeByteNTimes(0xcc, preamble_size - preamble.len);

        for (0..plt.symbols.items.len) |i| {
            const target_addr = elf_file.getGotPltEntryAddress(@as(u32, @intCast(i)));
            const source_addr = elf_file.getPltEntryAddress(@as(u32, @intCast(i)));
            disp = @as(i64, @intCast(target_addr)) - @as(i64, @intCast(source_addr + 12)) - 4;
            var entry = [_]u8{
                0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                0x41, 0xbb, 0x00, 0x00, 0x00, 0x00, // mov r11d, N
                0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp qword ptr [rip] -> .got.plt[N]
            };
            mem.writeIntLittle(i32, entry[6..][0..4], @as(i32, @intCast(i)));
            mem.writeIntLittle(i32, entry[12..][0..4], @as(i32, @intCast(disp)));
            try writer.writeAll(&entry);
        }
    }

    pub fn addRela(plt: PltSection, elf_file: *Elf) !void {
        try elf_file.rela_plt.ensureUnusedCapacity(elf_file.base.allocator, plt.numRela());
        for (plt.symbols.items, 0..) |sym_index, i| {
            const sym = elf_file.getSymbol(sym_index);
            assert(sym.flags.import);
            const extra = sym.getExtra(elf_file).?;
            const r_offset = elf_file.getGotPltEntryAddress(@as(u32, @intCast(i)));
            const r_sym: u64 = extra.dynamic;
            const r_type: u32 = elf.R_X86_64_JUMP_SLOT;
            elf_file.rela_plt.appendAssumeCapacity(.{
                .r_offset = r_offset,
                .r_info = (r_sym << 32) | r_type,
                .r_addend = 0,
            });
        }
    }

    pub fn numRela(plt: PltSection) usize {
        return plt.symbols.items.len;
    }

    pub fn calcSymtabSize(plt: *PltSection, elf_file: *Elf) !void {
        if (elf_file.options.strip_all) return;

        plt.output_symtab_size.nlocals = @as(u32, @intCast(plt.symbols.items.len));
        for (plt.symbols.items) |sym_index| {
            const sym = elf_file.getSymbol(sym_index);
            plt.output_symtab_size.strsize += @as(u32, @intCast(sym.getName(elf_file).len + "$plt".len + 1));
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
                .st_value = elf_file.getPltEntryAddress(@as(u32, @intCast(i))),
                .st_size = 16,
            };
            ilocal += 1;
        }
    }
};

pub const GotPltSection = struct {
    pub const preamble_size = 24;

    pub fn size(got_plt: GotPltSection, elf_file: *Elf) usize {
        _ = got_plt;
        return preamble_size + elf_file.plt.symbols.items.len * 8;
    }

    pub fn write(got_plt: GotPltSection, elf_file: *Elf, writer: anytype) !void {
        _ = got_plt;
        {
            // [0]: _DYNAMIC
            const symbol = elf_file.getSymbol(elf_file.dynamic_index.?);
            try writer.writeIntLittle(u64, symbol.value);
        }
        // [1]: 0x0
        // [2]: 0x0
        try writer.writeIntLittle(u64, 0x0);
        try writer.writeIntLittle(u64, 0x0);
        if (elf_file.plt_sect_index) |shndx| {
            const plt_addr = elf_file.getSectionAddress(shndx);
            for (0..elf_file.plt.symbols.items.len) |_| {
                // [N]: .plt
                try writer.writeIntLittle(u64, plt_addr);
            }
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
        const index = @as(u32, @intCast(plt_got.symbols.items.len));
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
            const extra = sym.getExtra(elf_file).?;
            const target_addr = elf_file.getGotEntryAddress(extra.got);
            const source_addr = elf_file.getPltGotEntryAddress(@as(u32, @intCast(i)));
            const disp = @as(i64, @intCast(target_addr)) - @as(i64, @intCast(source_addr + 6)) - 4;
            var entry = [_]u8{
                0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp qword ptr [rip] -> .got[N]
                0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
            };
            mem.writeIntLittle(i32, entry[6..][0..4], @as(i32, @intCast(disp)));
            try writer.writeAll(&entry);
        }
    }

    pub fn calcSymtabSize(plt_got: *PltGotSection, elf_file: *Elf) !void {
        if (elf_file.options.strip_all) return;

        plt_got.output_symtab_size.nlocals = @as(u32, @intCast(plt_got.symbols.items.len));
        for (plt_got.symbols.items) |sym_index| {
            const sym = elf_file.getSymbol(sym_index);
            plt_got.output_symtab_size.strsize += @as(u32, @intCast(sym.getName(elf_file).len + "$pltgot".len + 1));
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
                .st_value = elf_file.getPltGotEntryAddress(@as(u32, @intCast(i))),
                .st_size = 16,
            };
            ilocal += 1;
        }
    }
};

pub const CopyRelSection = struct {
    symbols: std.ArrayListUnmanaged(u32) = .{},

    pub fn deinit(copy_rel: *CopyRelSection, allocator: Allocator) void {
        copy_rel.symbols.deinit(allocator);
    }

    pub fn addSymbol(copy_rel: *CopyRelSection, sym_index: u32, elf_file: *Elf) !void {
        const index = @as(u32, @intCast(copy_rel.symbols.items.len));
        const symbol = elf_file.getSymbol(sym_index);
        symbol.flags.import = true;
        symbol.flags.@"export" = true;
        symbol.flags.has_copy_rel = true;
        symbol.flags.weak = false;

        if (symbol.getExtra(elf_file)) |extra| {
            var new_extra = extra;
            new_extra.copy_rel = index;
            symbol.setExtra(new_extra, elf_file);
        } else try symbol.addExtra(.{ .copy_rel = index }, elf_file);
        try copy_rel.symbols.append(elf_file.base.allocator, sym_index);

        const shared = symbol.getFile(elf_file).?.shared;
        if (shared.aliases == null) {
            try shared.initSymbolAliases(elf_file);
        }

        const aliases = shared.getSymbolAliases(sym_index, elf_file);
        for (aliases) |alias| {
            if (alias == sym_index) continue;
            const alias_sym = elf_file.getSymbol(alias);
            alias_sym.flags.import = true;
            alias_sym.flags.@"export" = true;
            alias_sym.flags.has_copy_rel = true;
            alias_sym.flags.copy_rel = true;
            alias_sym.flags.weak = false;
            try elf_file.dynsym.addSymbol(alias, elf_file);
        }
    }

    pub fn calcSectionSize(copy_rel: CopyRelSection, shndx: u16, elf_file: *Elf) !void {
        const shdr = &elf_file.sections.items(.shdr)[shndx];
        for (copy_rel.symbols.items) |sym_index| {
            const symbol = elf_file.getSymbol(sym_index);
            const shared = symbol.getFile(elf_file).?.shared;
            const alignment = try symbol.getAlignment(elf_file);
            symbol.value = mem.alignForward(u64, shdr.sh_size, alignment);
            shdr.sh_addralign = @max(shdr.sh_addralign, alignment);
            shdr.sh_size = symbol.value + symbol.getSourceSymbol(elf_file).st_size;

            const aliases = shared.getSymbolAliases(sym_index, elf_file);
            for (aliases) |alias| {
                if (alias == sym_index) continue;
                const alias_sym = elf_file.getSymbol(alias);
                alias_sym.value = symbol.value;
            }
        }
    }

    pub fn addRela(copy_rel: CopyRelSection, elf_file: *Elf) !void {
        try elf_file.rela_dyn.ensureUnusedCapacity(elf_file.base.allocator, copy_rel.numRela());
        for (copy_rel.symbols.items) |sym_index| {
            const sym = elf_file.getSymbol(sym_index);
            assert(sym.flags.import and sym.flags.copy_rel);
            const extra = sym.getExtra(elf_file).?;
            elf_file.addRelaDynAssumeCapacity(.{
                .offset = sym.getAddress(.{}, elf_file),
                .sym = extra.dynamic,
                .type = elf.R_X86_64_COPY,
            });
        }
    }

    pub fn numRela(copy_rel: CopyRelSection) usize {
        return copy_rel.symbols.items.len;
    }
};

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const mem = std.mem;

const Allocator = mem.Allocator;
const Elf = @import("../Elf.zig");
const SharedObject = @import("SharedObject.zig");
