debug_info: []const u8,
debug_abbrev: []const u8,
debug_str: []const u8,

abbrev_tables: std.ArrayListUnmanaged(AbbrevTable) = .{},
compile_units: std.ArrayListUnmanaged(CompileUnit) = .{},

pub fn init(dw: *DwarfInfo, allocator: Allocator) !void {
    try dw.parseAbbrevTables(allocator);
    try dw.parseCompileUnits(allocator);
}

pub fn deinit(dw: *DwarfInfo, allocator: Allocator) void {
    dw.abbrev_tables.deinit(allocator);
    for (dw.compile_units.items) |*cu| {
        cu.deinit(allocator);
    }
    dw.compile_units.deinit(allocator);
}

fn getString(dw: DwarfInfo, off: u32) [:0]const u8 {
    assert(off < dw.debug_str.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(dw.debug_str.ptr + off)), 0);
}

fn getAbbrevTable(dw: DwarfInfo, off: u64) ?AbbrevTable {
    for (dw.abbrev_tables.items) |table| {
        if (table.loc.pos == off) return table;
    }
    return null;
}

fn parseAbbrevTables(dw: *DwarfInfo, allocator: Allocator) !void {
    const debug_abbrev = dw.debug_abbrev;
    var stream = std.io.fixedBufferStream(debug_abbrev);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    while (true) {
        if (creader.bytes_read >= debug_abbrev.len) break;

        const table = try dw.abbrev_tables.addOne(allocator);
        table.* = .{ .loc = .{ .pos = creader.bytes_read, .len = 0 } };

        while (true) {
            const code = try leb.readULEB128(u64, reader);
            if (code == 0) break;

            const decl = try table.decls.addOne(allocator);
            decl.* = .{
                .code = code,
                .tag = undefined,
                .children = false,
                .loc = .{ .pos = creader.bytes_read, .len = 1 },
            };
            decl.tag = try leb.readULEB128(u64, reader);
            decl.children = (try reader.readByte()) > 0;

            while (true) {
                const at = try leb.readULEB128(u64, reader);
                const form = try leb.readULEB128(u64, reader);
                if (at == 0 and form == 0) break;

                const attr = try decl.attrs.addOne(allocator);
                attr.* = .{
                    .at = at,
                    .form = form,
                    .loc = .{ .pos = creader.bytes_read, .len = 0 },
                };
                attr.loc.len = creader.bytes_read - attr.loc.pos;
            }

            decl.loc.len = creader.bytes_read - decl.loc.pos;
        }

        table.loc.len = creader.bytes_read - table.loc.pos;
    }
}

fn parseCompileUnits(dw: *DwarfInfo, allocator: Allocator) !void {
    const debug_info = dw.debug_info;
    var stream = std.io.fixedBufferStream(debug_info);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    while (true) {
        if (creader.bytes_read == debug_info.len) break;

        const cu = try dw.compile_units.addOne(allocator);
        cu.* = .{
            .header = undefined,
            .loc = .{ .pos = creader.bytes_read, .len = 0 },
        };

        var length: u64 = try reader.readInt(u32, .little);
        const is_64bit = length == 0xffffffff;
        if (is_64bit) {
            length = try reader.readInt(u64, .little);
        }
        cu.header.dw_format = if (is_64bit) .dwarf64 else .dwarf32;
        cu.header.length = length;
        cu.header.version = try reader.readInt(u16, .little);
        cu.header.debug_abbrev_offset = try readOffset(cu.header.dw_format, reader);
        cu.header.address_size = try reader.readInt(u8, .little);

        const table = dw.getAbbrevTable(cu.header.debug_abbrev_offset).?;
        try dw.parseDebugInfoEntry(allocator, cu, table, null, &creader);

        cu.loc.len = creader.bytes_read - cu.loc.pos;
    }
}

fn parseDebugInfoEntry(
    dw: *DwarfInfo,
    allocator: Allocator,
    cu: *CompileUnit,
    table: AbbrevTable,
    parent: ?usize,
    creader: anytype,
) anyerror!void {
    while (creader.bytes_read < cu.nextCompileUnitOffset()) {
        const die = try cu.addDie(allocator);
        cu.diePtr(die).* = .{
            .code = undefined,
            .loc = .{ .pos = creader.bytes_read, .len = 0 },
        };
        if (parent) |p| {
            try cu.diePtr(p).children.append(allocator, die);
        } else {
            try cu.children.append(allocator, die);
        }

        const code = try leb.readULEB128(u64, creader.reader());
        cu.diePtr(die).code = code;

        if (code == 0) {
            if (parent == null) continue;
            return; // Close scope
        }

        const decl = table.getDecl(code) orelse @panic("no suitable abbreviation decl found");
        const data = dw.debug_info;
        try cu.diePtr(die).values.ensureTotalCapacityPrecise(allocator, decl.attrs.items.len);

        for (decl.attrs.items) |attr| {
            const start = creader.bytes_read;
            try advanceByFormSize(cu, attr.form, creader);
            const end = creader.bytes_read;
            cu.diePtr(die).values.appendAssumeCapacity(data[start..end]);
        }

        if (decl.children) {
            // Open scope
            try dw.parseDebugInfoEntry(allocator, cu, table, die, creader);
        }

        cu.diePtr(die).loc.len = creader.bytes_read - cu.diePtr(die).loc.pos;
    }
}

fn advanceByFormSize(cu: *CompileUnit, form: u64, creader: anytype) !void {
    const reader = creader.reader();
    switch (form) {
        dwarf.FORM.strp,
        dwarf.FORM.sec_offset,
        dwarf.FORM.ref_addr,
        => {
            _ = try readOffset(cu.header.dw_format, reader);
        },

        dwarf.FORM.addr => try reader.skipBytes(cu.header.address_size, .{}),

        dwarf.FORM.block1,
        dwarf.FORM.block2,
        dwarf.FORM.block4,
        dwarf.FORM.block,
        => {
            const len: u64 = switch (form) {
                dwarf.FORM.block1 => try reader.readInt(u8, .little),
                dwarf.FORM.block2 => try reader.readInt(u16, .little),
                dwarf.FORM.block4 => try reader.readInt(u32, .little),
                dwarf.FORM.block => try leb.readULEB128(u64, reader),
                else => unreachable,
            };
            for (0..len) |_| {
                _ = try reader.readByte();
            }
        },

        dwarf.FORM.exprloc => {
            const len = try leb.readULEB128(u64, reader);
            for (0..len) |_| {
                _ = try reader.readByte();
            }
        },
        dwarf.FORM.flag_present => {},

        dwarf.FORM.data1,
        dwarf.FORM.ref1,
        dwarf.FORM.flag,
        => try reader.skipBytes(1, .{}),

        dwarf.FORM.data2,
        dwarf.FORM.ref2,
        => try reader.skipBytes(2, .{}),

        dwarf.FORM.data4,
        dwarf.FORM.ref4,
        => try reader.skipBytes(4, .{}),

        dwarf.FORM.data8,
        dwarf.FORM.ref8,
        dwarf.FORM.ref_sig8,
        => try reader.skipBytes(8, .{}),

        dwarf.FORM.udata,
        dwarf.FORM.ref_udata,
        => {
            _ = try leb.readULEB128(u64, reader);
        },

        dwarf.FORM.sdata => {
            _ = try leb.readILEB128(i64, reader);
        },

        dwarf.FORM.string => {
            while (true) {
                const byte = try reader.readByte();
                if (byte == 0x0) break;
            }
        },

        else => {
            log.err("unhandled DW_FORM_* value with identifier {x}", .{form});
            return error.UnhandledDwFormValue;
        },
    }
}

fn readOffset(format: Format, reader: anytype) !u64 {
    return switch (format) {
        .dwarf32 => try reader.readInt(u32, .little),
        .dwarf64 => try reader.readInt(u64, .little),
    };
}

pub const AbbrevTable = struct {
    decls: std.ArrayListUnmanaged(Decl) = .{},
    loc: Loc,

    pub fn deinit(table: *AbbrevTable, gpa: Allocator) void {
        for (table.decls.items) |*decl| {
            decl.deinit(gpa);
        }
        table.decls.deinit(gpa);
    }

    pub fn getDecl(table: AbbrevTable, code: u64) ?Decl {
        for (table.decls.items) |decl| {
            if (decl.code == code) return decl;
        }
        return null;
    }

    pub fn format(
        table: AbbrevTable,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        for (table.decls.items) |decl| {
            try writer.print("{}\n", .{decl});
        }
    }

    pub const Decl = struct {
        code: u64,
        tag: u64,
        children: bool,
        attrs: std.ArrayListUnmanaged(Attr) = .{},
        loc: Loc,

        pub fn deinit(decl: *Decl, gpa: Allocator) void {
            decl.attrs.deinit(gpa);
        }

        pub fn format(
            decl: Decl,
            comptime unused_fmt_string: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = unused_fmt_string;
            _ = options;

            try writer.print("[{d}]  ", .{decl.code});

            try writer.print("{}", .{fmtTag(decl.tag)});
            try writer.print("  DW_CHILDREN_{s}\n", .{if (decl.children) "yes" else "no"});

            const nattrs = decl.attrs.items.len;
            if (nattrs == 0) return;

            for (decl.attrs.items[0 .. nattrs - 1]) |attr| {
                try writer.print("{}\n", .{attr});
            }
            try writer.print("{}", .{decl.attrs.items[nattrs - 1]});
        }
    };

    pub fn fmtTag(tag: u64) std.fmt.Formatter(formatTag) {
        return .{ .data = tag };
    }

    fn formatTag(
        tag: u64,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        const is_tag_known = switch (tag) {
            dwarf.TAG.lo_user...dwarf.TAG.hi_user => switch (tag) {
                0x4109, 0x410a => true,
                else => false,
            },
            else => inline for (@typeInfo(dwarf.TAG).Struct.decls) |x| {
                if (@field(dwarf.TAG, x.name) == tag) break true;
            } else false,
        };
        if (is_tag_known) {
            const tag_s = switch (tag) {
                dwarf.TAG.lo_user...dwarf.TAG.hi_user => switch (tag) {
                    0x4109 => "DW_TAG_GNU_call_site",
                    0x410a => "DW_TAG_GNU_call_site_parameter",
                    else => unreachable, // sync'd with is_tag_known check above
                },
                else => inline for (@typeInfo(dwarf.TAG).Struct.decls) |x| {
                    if (@field(dwarf.TAG, x.name) == tag) {
                        break "DW_TAG_" ++ x.name;
                    }
                } else unreachable, // sync'd with is_tag_known check above
            };
            try writer.print("{s}", .{tag_s});
        } else {
            try writer.print("DW_TAG_unknown_{x}", .{tag});
        }
    }

    pub const Attr = struct {
        at: u64,
        form: u64,
        loc: Loc,

        pub fn getFlag(attr: Attr, value: []const u8) ?bool {
            return switch (attr.form) {
                dwarf.FORM.flag => value[0] == 1,
                dwarf.FORM.flag_present => true,
                else => null,
            };
        }

        pub fn getString(attr: Attr, value: []const u8, dwf: Format, ctx: *const DwarfInfo) ?[]const u8 {
            switch (attr.form) {
                dwarf.FORM.string => {
                    return mem.sliceTo(@as([*:0]const u8, @ptrCast(value.ptr)), 0);
                },
                dwarf.FORM.strp => {
                    const off = switch (dwf) {
                        .dwarf64 => mem.readInt(u64, value[0..8], .little),
                        .dwarf32 => mem.readInt(u32, value[0..4], .little),
                    };
                    return ctx.getString(off);
                },
                else => return null,
            }
        }

        pub fn getSecOffset(attr: Attr, value: []const u8, dwf: Format) ?u64 {
            return switch (attr.form) {
                dwarf.FORM.sec_offset => switch (dwf) {
                    .dwarf32 => mem.readInt(u32, value[0..4], .little),
                    .dwarf64 => mem.readInt(u64, value[0..8], .little),
                },
                else => null,
            };
        }

        pub fn getConstant(attr: Attr, value: []const u8) !?i128 {
            var stream = std.io.fixedBufferStream(value);
            const reader = stream.reader();
            return switch (attr.form) {
                dwarf.FORM.data1 => value[0],
                dwarf.FORM.data2 => mem.readInt(u16, value[0..2], .little),
                dwarf.FORM.data4 => mem.readInt(u32, value[0..4], .little),
                dwarf.FORM.data8 => mem.readInt(u64, value[0..8], .little),
                dwarf.FORM.udata => try leb.readULEB128(u64, reader),
                dwarf.FORM.sdata => try leb.readILEB128(i64, reader),
                else => null,
            };
        }

        pub fn getReference(attr: Attr, value: []const u8, dwf: Format) !?u64 {
            var stream = std.io.fixedBufferStream(value);
            const reader = stream.reader();
            return switch (attr.form) {
                dwarf.FORM.ref1 => value[0],
                dwarf.FORM.ref2 => mem.readInt(u16, value[0..2], .little),
                dwarf.FORM.ref4 => mem.readInt(u32, value[0..4], .little),
                dwarf.FORM.ref8 => mem.readInt(u64, value[0..8], .little),
                dwarf.FORM.ref_udata => try leb.readULEB128(u64, reader),
                dwarf.FORM.ref_addr => switch (dwf) {
                    .dwarf32 => mem.readInt(u32, value[0..4], .little),
                    .dwarf64 => mem.readInt(u64, value[0..8], .little),
                },
                else => null,
            };
        }

        pub fn getAddr(attr: Attr, value: []const u8, cuh: CompileUnit.Header) ?u64 {
            return switch (attr.form) {
                dwarf.FORM.addr => switch (cuh.address_size) {
                    1 => value[0],
                    2 => mem.readInt(u16, value[0..2], .little),
                    4 => mem.readInt(u32, value[0..4], .little),
                    8 => mem.readInt(u64, value[0..8], .little),
                    else => null,
                },
                else => null,
            };
        }

        pub fn getExprloc(attr: Attr, value: []const u8) !?[]const u8 {
            if (attr.form != dwarf.FORM.exprloc) return null;
            var stream = std.io.fixedBufferStream(value);
            var creader = std.io.countingReader(stream.reader());
            const reader = creader.reader();
            const expr_len = try leb.readULEB128(u64, reader);
            return value[creader.bytes_read..][0..expr_len];
        }

        pub fn format(
            attr: Attr,
            comptime unused_fmt_string: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = unused_fmt_string;
            _ = options;
            try writer.writeAll("        ");
            try writer.print("{}", .{fmtAt(attr.at)});
            try writer.writeAll("  ");
            inline for (@typeInfo(dwarf.FORM).Struct.decls) |x| {
                if (@field(dwarf.FORM, x.name) == attr.form) {
                    try writer.print("DW_FORM_{s}", .{x.name});
                    break;
                }
            } else try writer.print("DW_FORM_unknown_{x}", .{attr.form});
        }
    };

    pub fn fmtAt(at: u64) std.fmt.Formatter(formatAt) {
        return .{ .data = at };
    }

    fn formatAt(
        at: u64,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        const is_at_known = switch (at) {
            dwarf.AT.lo_user...dwarf.AT.hi_user => switch (at) {
                0x2111, 0x2113, 0x2115, 0x2117, 0x3e02, 0x3fef => true,
                else => false,
            },
            else => inline for (@typeInfo(dwarf.AT).Struct.decls) |x| {
                if (@field(dwarf.AT, x.name) == at) break true;
            } else false,
        };
        if (is_at_known) {
            const name = switch (at) {
                dwarf.AT.lo_user...dwarf.AT.hi_user => switch (at) {
                    0x2111 => "DW_AT_GNU_call_site_value",
                    0x2113 => "DW_AT_GNU_call_site_target",
                    0x2115 => "DW_AT_GNU_tail_cail",
                    0x2117 => "DW_AT_GNU_all_call_sites",
                    0x3e02 => "DW_AT_LLVM_sysroot",
                    0x3fef => "DW_AT_APPLE_sdk",
                    else => unreachable,
                },
                else => inline for (@typeInfo(dwarf.AT).Struct.decls) |x| {
                    if (@field(dwarf.AT, x.name) == at) {
                        break "DW_AT_" ++ x.name;
                    }
                } else unreachable,
            };
            try writer.print("{s}", .{name});
        } else {
            try writer.print("DW_AT_unknown_{x}", .{at});
        }
    }
};

pub const CompileUnit = struct {
    header: Header,
    loc: Loc,
    dies: std.ArrayListUnmanaged(DebugInfoEntry) = .{},
    children: std.ArrayListUnmanaged(usize) = .{},

    pub fn deinit(cu: *CompileUnit, gpa: Allocator) void {
        for (cu.dies.items) |*die| {
            die.deinit(gpa);
        }
        cu.dies.deinit(gpa);
        cu.children.deinit(gpa);
    }

    pub fn addDie(cu: *CompileUnit, gpa: Allocator) !usize {
        const index = cu.dies.items.len;
        _ = try cu.dies.addOne(gpa);
        return index;
    }

    pub fn diePtr(cu: *CompileUnit, index: usize) *DebugInfoEntry {
        return &cu.dies.items[index];
    }

    pub fn nextCompileUnitOffset(cu: CompileUnit) u64 {
        return cu.loc.pos + switch (cu.header.dw_format) {
            .dwarf32 => @as(u64, 4),
            .dwarf64 => 12,
        } + cu.header.length;
    }

    pub fn format(
        cu: CompileUnit,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = cu;
        _ = unused_fmt_string;
        _ = options;
        _ = writer;
        @compileError("do not format CompileUnit directly; use fmtCompileUnit");
    }

    pub fn fmtCompileUnit(
        cu: *CompileUnit,
        table: AbbrevTable,
        ctx: *const DwarfInfo,
    ) std.fmt.Formatter(formatCompileUnit) {
        return .{ .data = .{
            .cu = cu,
            .table = table,
            .ctx = ctx,
        } };
    }

    const FormatCompileUnitCtx = struct {
        cu: *CompileUnit,
        table: AbbrevTable,
        ctx: *const DwarfInfo,
    };

    pub fn formatCompileUnit(
        ctx: FormatCompileUnitCtx,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        const cu = ctx.cu;
        try writer.print("{}: Compile Unit: {} (next unit at {})\n\n", .{
            cu.header.dw_format.fmtOffset(cu.loc.pos),
            cu.header,
            cu.header.dw_format.fmtOffset(cu.nextCompileUnitOffset()),
        });
        for (cu.children.items) |die_index| {
            const die = cu.diePtr(die_index);
            try writer.print("{}\n", .{die.fmtDie(ctx.table, cu, ctx.ctx, null, 0)});
        }
    }

    pub const Header = struct {
        dw_format: Format,
        length: u64,
        version: u16,
        debug_abbrev_offset: u64,
        address_size: u8,

        pub fn format(
            header: Header,
            comptime unused_fmt_string: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = unused_fmt_string;
            _ = options;
            try writer.print(
                "length = {}, " ++
                    "format = {s}, " ++
                    "version = 0x{x:0>4}, " ++
                    "abbr_offset = {}, " ++
                    "address_size = 0x{x:0>2}",
                .{
                    header.dw_format.fmtOffset(header.length),
                    @tagName(header.dw_format),
                    header.version,
                    header.dw_format.fmtOffset(header.debug_abbrev_offset),
                    header.address_size,
                },
            );
        }
    };

    pub const DebugInfoEntry = struct {
        code: u64,
        loc: Loc,
        values: std.ArrayListUnmanaged([]const u8) = .{},
        children: std.ArrayListUnmanaged(usize) = .{},

        pub fn deinit(die: *DebugInfoEntry, gpa: Allocator) void {
            die.values.deinit(gpa);
            die.children.deinit(gpa);
        }

        pub fn format(
            die: DebugInfoEntry,
            comptime unused_fmt_string: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = die;
            _ = unused_fmt_string;
            _ = options;
            _ = writer;
            @compileError("do not format DebugInfoEntry directly; use fmtDie instead");
        }

        pub fn fmtDie(
            die: DebugInfoEntry,
            table: AbbrevTable,
            cu: *CompileUnit,
            ctx: *const DwarfInfo,
            low_pc: ?u64,
            indent: usize,
        ) std.fmt.Formatter(formatDie) {
            return .{ .data = .{
                .die = die,
                .table = table,
                .cu = cu,
                .ctx = ctx,
                .low_pc = low_pc,
                .indent = indent,
            } };
        }

        const FormatDieCtx = struct {
            die: DebugInfoEntry,
            table: AbbrevTable,
            cu: *CompileUnit,
            ctx: *const DwarfInfo,
            low_pc: ?u64 = null,
            indent: usize = 0,
        };

        fn formatDie(
            ctx: FormatDieCtx,
            comptime unused_fmt_string: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = unused_fmt_string;
            _ = options;

            try writer.print("{}: ", .{ctx.cu.header.dw_format.fmtOffset(ctx.die.loc.pos)});
            const align_base: usize = 4 + switch (ctx.cu.header.dw_format) {
                .dwarf32 => @as(usize, 8),
                .dwarf64 => 16,
            };
            try fmtIndent(ctx.indent, writer);

            if (ctx.die.code == 0) {
                try writer.writeAll("NULL\n\n");
                return;
            }

            const decl = ctx.table.getDecl(ctx.die.code).?;
            try writer.print("{}\n", .{AbbrevTable.fmtTag(decl.tag)});

            var low_pc: ?u64 = ctx.low_pc;
            for (decl.attrs.items, ctx.die.values.items) |attr, value| {
                try fmtIndent(ctx.indent + align_base + 2, writer);
                try writer.print("{} (", .{AbbrevTable.fmtAt(attr.at)});

                formatAtFormInner(attr, value, ctx.cu, &low_pc, ctx.ctx, writer) catch |err| switch (err) {
                    error.UnhandledForm => try writer.print("error: unhandled FORM {x} for attribute", .{attr.form}),
                    error.UnexpectedForm => try writer.print("error: unexpected FORM {x}", .{attr.form}),
                    error.MalformedDwarf => try writer.print("error: malformed DWARF while parsing FORM {x}", .{attr.form}),
                    error.Overflow, error.EndOfStream => unreachable,
                    else => |e| return e,
                };

                try writer.writeAll(")\n");
            }
            try writer.writeByte('\n');

            for (ctx.die.children.items) |child_index| {
                const child = ctx.cu.diePtr(child_index);
                try writer.print("{}", .{child.fmtDie(ctx.table, ctx.cu, ctx.ctx, low_pc, ctx.indent + 2)});
            }
        }

        fn formatAtFormInner(
            attr: AbbrevTable.Attr,
            value: []const u8,
            cu: *CompileUnit,
            low_pc: *?u64,
            ctx: *const DwarfInfo,
            writer: anytype,
        ) !void {
            switch (attr.at) {
                dwarf.AT.stmt_list,
                dwarf.AT.ranges,
                => {
                    const sec_offset = attr.getSecOffset(value, cu.header.dw_format) orelse
                        return error.MalformedDwarf;
                    try writer.print("{x:0>16}", .{sec_offset});
                },

                dwarf.AT.low_pc => {
                    const addr = attr.getAddr(value, cu.header) orelse
                        return error.MalformedDwarf;
                    low_pc.* = addr;
                    try writer.print("{x:0>16}", .{addr});
                },

                dwarf.AT.high_pc => {
                    if (try attr.getConstant(value)) |offset| {
                        try writer.print("{x:0>16}", .{offset + low_pc.*.?});
                    } else if (attr.getAddr(value, cu.header)) |addr| {
                        try writer.print("{x:0>16}", .{addr});
                    } else return error.MalformedDwarf;
                },

                dwarf.AT.type,
                dwarf.AT.abstract_origin,
                => {
                    const off = (try attr.getReference(value, cu.header.dw_format)) orelse
                        return error.MalformedDwarf;
                    try writer.print("{x}", .{off});
                },

                dwarf.AT.comp_dir,
                dwarf.AT.producer,
                dwarf.AT.name,
                dwarf.AT.linkage_name,
                => {
                    const str = attr.getString(value, cu.header.dw_format, ctx) orelse
                        return error.MalformedDwarf;
                    try writer.print("\"{s}\"", .{str});
                },

                dwarf.AT.language,
                dwarf.AT.calling_convention,
                dwarf.AT.encoding,
                dwarf.AT.decl_column,
                dwarf.AT.decl_file,
                dwarf.AT.decl_line,
                dwarf.AT.alignment,
                dwarf.AT.data_bit_offset,
                dwarf.AT.call_file,
                dwarf.AT.call_line,
                dwarf.AT.call_column,
                dwarf.AT.@"inline",
                => {
                    const x = (try attr.getConstant(value)) orelse return error.MalformedDwarf;
                    try writer.print("{x:0>16}", .{x});
                },

                dwarf.AT.location,
                dwarf.AT.frame_base,
                => {
                    if (try attr.getExprloc(value)) |list| {
                        try writer.print("<0x{x}> {x}", .{ list.len, std.fmt.fmtSliceHexLower(list) });
                    } else {
                        try writer.print("error: TODO check and parse loclist", .{});
                    }
                },

                dwarf.AT.data_member_location => {
                    if (try attr.getConstant(value)) |x| {
                        try writer.print("{x:0>16}", .{x});
                    } else if (try attr.getExprloc(value)) |list| {
                        try writer.print("<0x{x}> {x}", .{ list.len, std.fmt.fmtSliceHexLower(list) });
                    } else {
                        try writer.print("error: TODO check and parse loclist", .{});
                    }
                },

                dwarf.AT.const_value => {
                    if (try attr.getConstant(value)) |x| {
                        try writer.print("{x:0>16}", .{x});
                    } else if (attr.getString(value, cu.header.dw_format, ctx)) |str| {
                        try writer.print("\"{s}\"", .{str});
                    } else {
                        try writer.print("error: TODO check and parse block", .{});
                    }
                },

                dwarf.AT.count => {
                    if (try attr.getConstant(value)) |x| {
                        try writer.print("{x:0>16}", .{x});
                    } else if (try attr.getExprloc(value)) |list| {
                        try writer.print("<0x{x}> {x}", .{ list.len, std.fmt.fmtSliceHexLower(list) });
                    } else if (try attr.getReference(value, cu.header.dw_format)) |off| {
                        try writer.print("{x:0>16}", .{off});
                    } else return error.MalformedDwarf;
                },

                dwarf.AT.byte_size,
                dwarf.AT.bit_size,
                => {
                    if (try attr.getConstant(value)) |x| {
                        try writer.print("{x}", .{x});
                    } else if (try attr.getReference(value, cu.header.dw_format)) |off| {
                        try writer.print("{x}", .{off});
                    } else if (try attr.getExprloc(value)) |list| {
                        try writer.print("<0x{x}> {x}", .{ list.len, std.fmt.fmtSliceHexLower(list) });
                    } else return error.MalformedDwarf;
                },

                dwarf.AT.noreturn,
                dwarf.AT.external,
                dwarf.AT.variable_parameter,
                dwarf.AT.trampoline,
                => {
                    const flag = attr.getFlag(value) orelse return error.MalformedDwarf;
                    try writer.print("{}", .{flag});
                },

                else => {
                    if (dwarf.AT.lo_user <= attr.at and attr.at <= dwarf.AT.hi_user) {
                        if (try attr.getConstant(value)) |x| {
                            try writer.print("{x}", .{x});
                        } else if (attr.getString(value, cu.header.dw_format, ctx)) |string| {
                            try writer.print("\"{s}\"", .{string});
                        } else return error.UnhandledForm;
                    } else return error.UnexpectedForm;
                },
            }
        }
    };

    fn fmtIndent(indent: usize, writer: anytype) !void {
        for (0..indent) |_| try writer.writeByte(' ');
    }
};

pub const Loc = struct {
    pos: usize,
    len: usize,
};

pub const Format = enum {
    dwarf32,
    dwarf64,

    pub fn fmtOffset(format: Format, offset: u64) std.fmt.Formatter(formatOffset) {
        return .{ .data = .{
            .format = format,
            .offset = offset,
        } };
    }

    const FmtOffsetCtx = struct {
        format: Format,
        offset: u64,
    };

    fn formatOffset(
        ctx: FmtOffsetCtx,
        comptime unused_format_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_format_string;
        _ = options;
        switch (ctx.format) {
            .dwarf32 => try writer.print("0x{x:0>8}", .{ctx.offset}),
            .dwarf64 => try writer.print("0x{x:0>16}", .{ctx.offset}),
        }
    }
};

const assert = std.debug.assert;
const dwarf = std.dwarf;
const leb = std.leb;
const log = std.log.scoped(.link);
const mem = std.mem;
const std = @import("std");

const Allocator = mem.Allocator;
const DwarfInfo = @This();
const MachO = @import("../MachO.zig");
