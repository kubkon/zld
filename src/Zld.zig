const Zld = @This();

const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const meta = std.meta;
const fs = std.fs;
const macho = std.macho;
const math = std.math;
const log = std.log.scoped(.zld);

const Allocator = mem.Allocator;
const CodeSignature = @import("CodeSignature.zig");
const Object = @import("Object.zig");
const Trie = @import("Trie.zig");

usingnamespace @import("commands.zig");
usingnamespace @import("imports.zig");
usingnamespace @import("reloc.zig");

allocator: *Allocator,

arch: ?std.Target.Cpu.Arch = null,
page_size: ?u16 = null,
file: ?fs.File = null,
out_path: ?[]const u8 = null,

objects: std.ArrayListUnmanaged(Object) = .{},
load_commands: std.ArrayListUnmanaged(LoadCommand) = .{},
segments_dir: std.StringHashMapUnmanaged(u16) = .{},

pagezero_segment_cmd_index: ?u16 = null,
text_segment_cmd_index: ?u16 = null,
data_const_segment_cmd_index: ?u16 = null,
data_segment_cmd_index: ?u16 = null,
linkedit_segment_cmd_index: ?u16 = null,
dyld_info_cmd_index: ?u16 = null,
symtab_cmd_index: ?u16 = null,
dysymtab_cmd_index: ?u16 = null,
dylinker_cmd_index: ?u16 = null,
libsystem_cmd_index: ?u16 = null,
data_in_code_cmd_index: ?u16 = null,
function_starts_cmd_index: ?u16 = null,
main_cmd_index: ?u16 = null,
version_min_cmd_index: ?u16 = null,
source_version_cmd_index: ?u16 = null,
uuid_cmd_index: ?u16 = null,
code_signature_cmd_index: ?u16 = null,

text_section_index: ?u16 = null,
stubs_section_index: ?u16 = null,
stub_helper_section_index: ?u16 = null,
got_section_index: ?u16 = null,
la_symbol_ptr_section_index: ?u16 = null,
data_section_index: ?u16 = null,

locals: std.ArrayListUnmanaged(macho.nlist_64) = .{},
exports: std.StringArrayHashMapUnmanaged(macho.nlist_64) = .{},
extern_nonlazy_symbols: std.StringArrayHashMapUnmanaged(ExternSymbol) = .{},
extern_lazy_symbols: std.StringArrayHashMapUnmanaged(ExternSymbol) = .{},

string_table: std.ArrayListUnmanaged(u8) = .{},
string_table_directory: std.StringHashMapUnmanaged(u32) = .{},

/// Default path to dyld
/// TODO instead of hardcoding it, we should probably look through some env vars and search paths
/// instead but this will do for now.
const DEFAULT_DYLD_PATH: [*:0]const u8 = "/usr/lib/dyld";

/// Default lib search path
/// TODO instead of hardcoding it, we should probably look through some env vars and search paths
/// instead but this will do for now.
const DEFAULT_LIB_SEARCH_PATH: []const u8 = "/usr/lib";

const LIB_SYSTEM_NAME: [*:0]const u8 = "System";
/// TODO we should search for libSystem and fail if it doesn't exist, instead of hardcoding it
const LIB_SYSTEM_PATH: [*:0]const u8 = DEFAULT_LIB_SEARCH_PATH ++ "/libSystem.B.dylib";

pub fn init(allocator: *Allocator) Zld {
    return .{ .allocator = allocator };
}

pub fn deinit(self: *Zld) void {
    {
        var it = self.string_table_directory.iterator();
        while (it.next()) |nn| {
            self.allocator.free(nn.key);
        }
    }
    self.string_table_directory.deinit(self.allocator);
    self.string_table.deinit(self.allocator);
    for (self.extern_lazy_symbols.items()) |*entry| {
        self.allocator.free(entry.key);
    }
    self.extern_lazy_symbols.deinit(self.allocator);
    for (self.extern_nonlazy_symbols.items()) |*entry| {
        self.allocator.free(entry.key);
    }
    self.extern_nonlazy_symbols.deinit(self.allocator);
    for (self.exports.items()) |*entry| {
        self.allocator.free(entry.key);
    }
    self.exports.deinit(self.allocator);
    self.locals.deinit(self.allocator);
    for (self.objects.items) |*object| {
        object.deinit(self.allocator);
    }
    self.objects.deinit(self.allocator);
    for (self.load_commands.items) |*lc| {
        lc.deinit(self.allocator);
    }
    self.load_commands.deinit(self.allocator);
    {
        var it = self.segments_dir.iterator();
        while (it.next()) |nn| {
            self.allocator.free(nn.key);
        }
    }
    self.segments_dir.deinit(self.allocator);
    if (self.file) |*f| f.close();
}

pub fn link(self: *Zld, files: []const []const u8, out_path: []const u8) !void {
    if (files.len == 0) return error.NoInputFiles;
    if (files.len > 1) return error.TODOLinkMultipleObjectFiles;

    self.arch = blk: {
        const file = try fs.cwd().openFile(files[0], .{});
        defer file.close();
        var reader = file.reader();
        const header = try reader.readStruct(macho.mach_header_64);
        const arch: std.Target.Cpu.Arch = switch (header.cputype) {
            macho.CPU_TYPE_X86_64 => .x86_64,
            macho.CPU_TYPE_ARM64 => .aarch64,
            else => unreachable,
        };
        break :blk arch;
    };

    self.page_size = switch (self.arch.?) {
        .aarch64 => 0x4000,
        .x86_64 => 0x1000,
        else => unreachable,
    };

    self.out_path = out_path;
    self.file = try fs.cwd().createFile(out_path, .{
        .truncate = true,
        .read = true,
        .mode = if (std.Target.current.os.tag == .windows) 0 else 0o777,
    });

    try self.populateMetadata();

    try self.objects.ensureCapacity(self.allocator, files.len);
    for (files) |file_name| {
        var object: Object = .{ .base = self };
        const file = try fs.cwd().openFile(file_name, .{});
        try object.parse(file_name, file);
        self.objects.appendAssumeCapacity(object);

        const seg_cmd = object.load_commands.items[object.segment_cmd_index.?].Segment;
        for (seg_cmd.sections.items()) |entry| {
            const name = entry.key;
            const sect = entry.value;
            const segname = parseName(&sect.segname);

            if (mem.eql(u8, name, "__eh_frame")) {
                log.warn("TODO handle __eh_frame section", .{});
                continue;
            }
            const seg_id = self.segments_dir.get(segname) orelse {
                log.warn("segname {s} not found in the output artifact", .{segname});
                continue;
            };
            const seg = &self.load_commands.items[seg_id].Segment;
            const res = try seg.getOrPut(self.allocator, name);
            if (!res.found_existing) {
                res.entry.value = .{
                    .sectname = makeStaticString(name),
                    .segname = makeStaticString(segname),
                    .addr = 0,
                    .size = 0,
                    .offset = 0,
                    .@"align" = sect.@"align",
                    .reloff = 0,
                    .nreloc = 0,
                    .flags = sect.flags,
                    .reserved1 = 0,
                    .reserved2 = 0,
                    .reserved3 = 0,
                };
            }
            res.entry.value.size += sect.size;
            seg.inner.filesize += sect.size;
        }
    }

    for (self.objects.items) |object| {
        for (object.symtab.items) |sym| {
            if (sym.n_type != (macho.N_UNDF | macho.N_EXT)) continue;

            const sym_name = object.getString(sym.n_strx);
            const n_strx = try self.makeString(sym_name);
            if (mem.eql(u8, sym_name, "___stderrp") or mem.eql(u8, sym_name, "___stdoutp")) {
                log.debug("writing nonlazy symbol '{s}'", .{sym_name});
                var key = try self.allocator.dupe(u8, sym_name);
                const offset = @intCast(u32, self.extern_nonlazy_symbols.items().len * @sizeOf(u64));
                try self.extern_nonlazy_symbols.putNoClobber(self.allocator, key, .{
                    .inner = .{
                        .n_strx = n_strx,
                        .n_type = sym.n_type,
                        .n_value = 0,
                        .n_desc = macho.REFERENCE_FLAG_UNDEFINED_NON_LAZY | macho.N_SYMBOL_RESOLVER,
                        .n_sect = 0,
                    },
                    .dylib_ordinal = 1,
                    .segment = self.data_const_segment_cmd_index.?,
                    .offset = offset,
                });
            } else {
                log.debug("writing lazy symbol '{s}'", .{sym_name});
                var key = try self.allocator.dupe(u8, sym_name);
                try self.extern_lazy_symbols.putNoClobber(self.allocator, key, .{
                    .inner = .{
                        .n_strx = n_strx,
                        .n_type = sym.n_type,
                        .n_value = 0,
                        .n_desc = macho.REFERENCE_FLAG_UNDEFINED_NON_LAZY | macho.N_SYMBOL_RESOLVER,
                        .n_sect = 0,
                    },
                    .dylib_ordinal = 1,
                    .segment = self.data_segment_cmd_index.?,
                });
            }
        }
    }

    {
        const index = @intCast(u32, self.extern_nonlazy_symbols.items().len);
        const name = try self.allocator.dupe(u8, "dyld_stub_binder");
        const offset = try self.makeString("dyld_stub_binder");
        try self.extern_nonlazy_symbols.putNoClobber(self.allocator, name, .{
            .inner = .{
                .n_strx = offset,
                .n_type = std.macho.N_UNDF | std.macho.N_EXT,
                .n_sect = 0,
                .n_desc = std.macho.REFERENCE_FLAG_UNDEFINED_NON_LAZY | std.macho.N_SYMBOL_RESOLVER,
                .n_value = 0,
            },
            .dylib_ordinal = 1, // TODO this is currently hardcoded.
            .segment = self.data_const_segment_cmd_index.?,
            .offset = index * @sizeOf(u64),
        });
    }

    self.allocateTextSegment();
    self.allocateDataConstSegment();
    self.allocateDataSegment();
    self.allocateLinkeditSegment();

    for (self.objects.items) |*object| {
        for (object.symtab.items) |sym, i| {
            if (sym.n_type & macho.N_SECT == 0) continue;

            const seg = object.load_commands.items[object.segment_cmd_index.?].Segment;
            const sectname = seg.sections.items()[sym.n_sect - 1].key;
            const txt = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
            if (!txt.sections.contains(sectname)) continue;

            const n_sect = @intCast(u8, txt.sections.getIndex(sectname).? + 1);
            const sym_name = object.getString(sym.n_strx);
            const n_strx = try self.makeString(sym_name);
            var new_sym: macho.nlist_64 = .{
                .n_strx = n_strx,
                .n_type = sym.n_type,
                .n_value = 0,
                .n_desc = sym.n_desc,
                .n_sect = n_sect,
            };
            if (sym.n_type == (macho.N_SECT | macho.N_EXT)) {
                log.debug("writing export '{s}'", .{sym_name});
                const name = try self.allocator.dupe(u8, sym_name);
                try self.exports.putNoClobber(self.allocator, name, new_sym);
            } else {
                new_sym.n_value = txt.sections.get(sectname).?.addr;
                log.debug("writing local symbol '{s}'", .{sym_name});
                const index = self.locals.items.len;
                try self.locals.append(self.allocator, new_sym);
                try object.symbol_dir.putNoClobber(self.allocator, i, index);
            }
        }
    }

    try self.writeStubHelperCommon();
    try self.doRelocs();
    try self.flush();
}

fn allocateTextSegment(self: *Zld) void {
    const seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const sections = seg.sections.items();
    const nexterns = @intCast(u32, self.extern_lazy_symbols.items().len);

    // Set stubs and stub_helper sizes
    const stubs = &sections[self.stubs_section_index.?].value;
    const stub_helper = &sections[self.stub_helper_section_index.?].value;
    stubs.size += nexterns * stubs.reserved2;

    const stub_size: u4 = switch (self.arch.?) {
        .x86_64 => 10,
        .aarch64 => 3 * @sizeOf(u32),
        else => unreachable,
    };
    stub_helper.size += nexterns * stub_size;

    var sizeofcmds: u64 = 0;
    for (self.load_commands.items) |lc| {
        sizeofcmds += lc.cmdsize();
    }

    self.allocateSegment(self.text_segment_cmd_index.?, 0, sizeofcmds, true);
}

fn allocateDataConstSegment(self: *Zld) void {
    const seg = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const sections = seg.sections.items();
    const nexterns = @intCast(u32, self.extern_nonlazy_symbols.items().len);

    // Set got size
    const got = &sections[self.got_section_index.?].value;
    got.size += nexterns * @sizeOf(u64);

    const text_seg = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const offset = text_seg.inner.fileoff + text_seg.inner.filesize;
    self.allocateSegment(self.data_const_segment_cmd_index.?, offset, 0, false);
}

fn allocateDataSegment(self: *Zld) void {
    const seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const sections = seg.sections.items();
    const nexterns = @intCast(u32, self.extern_lazy_symbols.items().len);

    // Set la_symbol_ptr and data size
    const la_symbol_ptr = &sections[self.la_symbol_ptr_section_index.?].value;
    const data = &sections[self.data_section_index.?].value;
    la_symbol_ptr.size += nexterns * @sizeOf(u64);
    data.size += @sizeOf(u64); // TODO when do we need more?

    const dc_seg = self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const offset = dc_seg.inner.fileoff + dc_seg.inner.filesize;
    self.allocateSegment(self.data_segment_cmd_index.?, offset, 0, false);
}

fn allocateLinkeditSegment(self: *Zld) void {
    const data_seg = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const offset = data_seg.inner.fileoff + data_seg.inner.filesize;
    self.allocateSegment(self.linkedit_segment_cmd_index.?, offset, 0, false);
}

fn allocateSegment(self: *Zld, index: u16, offset: u64, start: u64, reverse: bool) void {
    const base_vmaddr = self.load_commands.items[self.pagezero_segment_cmd_index.?].Segment.inner.vmsize;
    const seg = &self.load_commands.items[index].Segment;
    const sections = seg.sections.items();

    // Calculate segment size
    var total_size = start;
    for (sections) |entry| {
        total_size += entry.value.size;
    }
    const aligned_size = mem.alignForwardGeneric(u64, total_size, self.page_size.?);
    seg.inner.vmaddr = base_vmaddr + offset;
    seg.inner.vmsize = aligned_size;
    seg.inner.fileoff = offset;
    seg.inner.filesize = aligned_size;

    // Allocate section offsets
    if (reverse) {
        var end_off: u64 = seg.inner.fileoff + seg.inner.filesize;
        var count: usize = sections.len;
        while (count > 0) : (count -= 1) {
            const sec = &sections[count - 1].value;
            end_off -= mem.alignForwardGeneric(u64, sec.size, @sizeOf(u32)); // TODO Should we always align to 4?
            sec.offset = @intCast(u32, end_off);
            sec.addr = base_vmaddr + end_off;
        }
    } else {
        var next_off: u64 = seg.inner.fileoff;
        for (sections) |*entry| {
            entry.value.offset = @intCast(u32, next_off);
            entry.value.addr = base_vmaddr + next_off;
            next_off += mem.alignForwardGeneric(u64, entry.value.size, @sizeOf(u32)); // TODO Should we always align to 4?
        }
    }
}

fn writeStubHelperCommon(self: *Zld) !void {
    const text_segment = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stub_helper = &text_segment.sections.items()[self.stub_helper_section_index.?].value;
    const data_segment = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const data = &data_segment.sections.items()[self.data_section_index.?].value;
    const la_symbol_ptr = data_segment.sections.items()[self.la_symbol_ptr_section_index.?].value;
    const data_const_segment = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const got = &data_const_segment.sections.items()[self.got_section_index.?].value;

    const stub_helper_stubs_start_off: u32 = blk: {
        switch (self.arch.?) {
            .x86_64 => {
                const code_size = 15;
                var code: [code_size]u8 = undefined;
                // lea %r11, [rip + disp]
                code[0] = 0x4c;
                code[1] = 0x8d;
                code[2] = 0x1d;
                {
                    const displacement = try math.cast(u32, data.addr - stub_helper.addr - 7);
                    mem.writeIntLittle(u32, code[3..7], displacement);
                }
                // push %r11
                code[7] = 0x41;
                code[8] = 0x53;
                // jmp [rip + disp]
                code[9] = 0xff;
                code[10] = 0x25;
                {
                    const dyld_stub_binder = self.extern_nonlazy_symbols.get("dyld_stub_binder").?;
                    const addr = (got.addr + dyld_stub_binder.offset);
                    const displacement = try math.cast(u32, addr - stub_helper.addr - code_size);
                    mem.writeIntLittle(u32, code[11..], displacement);
                }
                try self.file.?.pwriteAll(&code, stub_helper.offset);
                break :blk stub_helper.offset + code_size;
            },
            .aarch64 => {
                var code: [4 * @sizeOf(u32)]u8 = undefined;
                {
                    const displacement = @bitCast(u21, try math.cast(i21, data.addr - stub_helper.addr));
                    // adr x17, disp
                    mem.writeIntLittle(u32, code[0..4], Arm64.adr(17, displacement).toU32());
                }
                // stp x16, x17, [sp, #-16]!
                code[4] = 0xf0;
                code[5] = 0x47;
                code[6] = 0xbf;
                code[7] = 0xa9;
                {
                    const dyld_stub_binder = self.extern_nonlazy_symbols.get("dyld_stub_binder").?;
                    const addr = (got.addr + dyld_stub_binder.offset);
                    const displacement = try math.divExact(u64, addr - stub_helper.addr - 2 * @sizeOf(u32), 4);
                    const literal = try math.cast(u19, displacement);
                    // ldr x16, label
                    mem.writeIntLittle(u32, code[8..12], Arm64.ldr(16, literal, true).toU32());
                }
                // br x16
                code[12] = 0x00;
                code[13] = 0x02;
                code[14] = 0x1f;
                code[15] = 0xd6;
                try self.file.?.pwriteAll(&code, stub_helper.offset);
                break :blk stub_helper.offset + 4 * @sizeOf(u32);
            },
            else => unreachable,
        }
    };

    for (self.extern_lazy_symbols.items()) |_, i| {
        const index = @intCast(u32, i);
        try self.writeLazySymbolPointer(index, stub_helper_stubs_start_off);
        try self.writeStub(index);
        try self.writeStubInStubHelper(index, stub_helper_stubs_start_off);
    }
}

fn writeLazySymbolPointer(self: *Zld, index: u32, offset: u64) !void {
    const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stub_helper = text_segment.sections.items()[self.stub_helper_section_index.?].value;
    const data_segment = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const la_symbol_ptr = data_segment.sections.items()[self.la_symbol_ptr_section_index.?].value;

    const stub_size: u4 = switch (self.arch.?) {
        .x86_64 => 10,
        .aarch64 => 3 * @sizeOf(u32),
        else => unreachable,
    };
    const stub_off = offset + index * stub_size;
    const end = stub_helper.addr + stub_off - stub_helper.offset;
    var buf: [@sizeOf(u64)]u8 = undefined;
    mem.writeIntLittle(u64, &buf, end);
    const off = la_symbol_ptr.offset + index * @sizeOf(u64);
    log.debug("writing lazy symbol pointer entry 0x{x} at 0x{x}", .{ end, off });
    try self.file.?.pwriteAll(&buf, off);
}

fn writeStub(self: *Zld, index: u32) !void {
    const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stubs = text_segment.sections.items()[self.stubs_section_index.?].value;
    const data_segment = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const la_symbol_ptr = data_segment.sections.items()[self.la_symbol_ptr_section_index.?].value;

    const stub_off = stubs.offset + index * stubs.reserved2;
    const stub_addr = stubs.addr + index * stubs.reserved2;
    const la_ptr_addr = la_symbol_ptr.addr + index * @sizeOf(u64);
    log.debug("writing stub at 0x{x}", .{stub_off});
    var code = try self.allocator.alloc(u8, stubs.reserved2);
    defer self.allocator.free(code);
    switch (self.arch.?) {
        .x86_64 => {
            assert(la_ptr_addr >= stub_addr + stubs.reserved2);
            const displacement = try math.cast(u32, la_ptr_addr - stub_addr - stubs.reserved2);
            // jmp
            code[0] = 0xff;
            code[1] = 0x25;
            mem.writeIntLittle(u32, code[2..][0..4], displacement);
        },
        .aarch64 => {
            assert(la_ptr_addr >= stub_addr);
            const displacement = try math.divExact(u64, la_ptr_addr - stub_addr, 4);
            const literal = try math.cast(u19, displacement);
            // ldr x16, literal
            mem.writeIntLittle(u32, code[0..4], Arm64.ldr(16, literal, true).toU32());
            // br x16
            mem.writeIntLittle(u32, code[4..8], Arm64.br(16).toU32());
        },
        else => unreachable,
    }
    try self.file.?.pwriteAll(code, stub_off);
}

fn writeStubInStubHelper(self: *Zld, index: u32, offset: u64) !void {
    const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stub_helper = text_segment.sections.items()[self.stub_helper_section_index.?].value;

    const stub_size: u4 = switch (self.arch.?) {
        .x86_64 => 10,
        .aarch64 => 3 * @sizeOf(u32),
        else => unreachable,
    };
    const stub_off = offset + index * stub_size;
    var code = try self.allocator.alloc(u8, stub_size);
    defer self.allocator.free(code);
    switch (self.arch.?) {
        .x86_64 => {
            const displacement = try math.cast(
                i32,
                @intCast(i64, stub_helper.offset) - @intCast(i64, stub_off) - stub_size,
            );
            // pushq
            code[0] = 0x68;
            mem.writeIntLittle(u32, code[1..][0..4], 0x0); // Just a placeholder populated in `populateLazyBindOffsetsInStubHelper`.
            // jmpq
            code[5] = 0xe9;
            mem.writeIntLittle(u32, code[6..][0..4], @bitCast(u32, displacement));
        },
        .aarch64 => {
            const displacement = try math.cast(i28, @intCast(i64, stub_helper.offset) - @intCast(i64, stub_off) - 4);
            const literal = @divExact(stub_size - @sizeOf(u32), 4);
            // ldr w16, literal
            mem.writeIntLittle(u32, code[0..4], Arm64.ldr(16, literal, false).toU32());
            // b disp
            mem.writeIntLittle(u32, code[4..8], Arm64.b(displacement).toU32());
            mem.writeIntLittle(u32, code[8..12], 0x0); // Just a placeholder populated in `populateLazyBindOffsetsInStubHelper`.
        },
        else => unreachable,
    }
    try self.file.?.pwriteAll(code, stub_off);
}

fn doRelocs(self: *Zld) !void {
    var offsets = std.StringArrayHashMap(usize).init(self.allocator);
    defer {
        var it = offsets.iterator();
        while (it.next()) |nn| {
            self.allocator.free(nn.key);
        }
        offsets.deinit();
    }

    for (self.objects.items) |object| {
        const seg = object.load_commands.items[object.segment_cmd_index.?].Segment;
        const sections = seg.sections.items();

        for (sections) |entry| {
            const sectname = entry.key;
            const sect = entry.value;

            const out_seg_id = self.segments_dir.get(parseName(&sect.segname)) orelse continue;
            const out_seg = self.load_commands.items[out_seg_id].Segment;
            const out_sect = out_seg.sections.get(sectname) orelse continue;

            var code = try self.allocator.alloc(u8, sect.size);
            defer self.allocator.free(code);
            _ = try object.file.?.preadAll(code, sect.offset);

            // Parse relocs (if any)
            var raw_relocs = try self.allocator.alloc(u8, @sizeOf(macho.relocation_info) * sect.nreloc);
            defer self.allocator.free(raw_relocs);
            _ = try object.file.?.preadAll(raw_relocs, sect.reloff);
            const relocs = mem.bytesAsSlice(macho.relocation_info, raw_relocs);

            for (relocs) |rel| {
                const offset = @intCast(u32, rel.r_address);
                const inst = code[offset..][0..4];
                const this_addr = out_sect.addr + offset;
                const target_addr = blk: {
                    if (rel.r_extern == 1) {
                        if (object.symbol_dir.get(rel.r_symbolnum)) |idx| {
                            const sym = self.locals.items[idx];
                            break :blk sym.n_value;
                        } else {
                            // extern
                            const sym = object.symtab.items[rel.r_symbolnum];
                            const symname = object.getString(sym.n_strx);
                            if (self.extern_lazy_symbols.getIndex(symname)) |i| {
                                const segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
                                const stubs = segment.sections.items()[self.stubs_section_index.?].value;
                                break :blk stubs.addr + i * stubs.reserved2;
                            } else if (self.extern_nonlazy_symbols.get(symname)) |ext| {
                                const segment = self.load_commands.items[ext.segment].Segment;
                                const got = segment.sections.items()[self.got_section_index.?].value;
                                break :blk got.addr + ext.offset;
                            } else unreachable;
                        }
                    } else {
                        // TODO need to store object section to final artifact section mapping
                        const sect_id = rel.r_symbolnum - 1;
                        const segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
                        const sec = segment.sections.items()[sect_id + 2].value;
                        break :blk sec.addr;
                    }
                };

                switch (self.arch.?) {
                    .x86_64 => {
                        switch (@intToEnum(macho.reloc_type_x86_64, rel.r_type)) {
                            macho.reloc_type_x86_64.X86_64_RELOC_BRANCH => {
                                // callq / jmpq
                                const displacement = @bitCast(u32, @intCast(i32, @intCast(i64, target_addr) - @intCast(i64, this_addr) - 4));
                                mem.writeIntLittle(u32, inst, displacement);
                            },
                            macho.reloc_type_x86_64.X86_64_RELOC_SIGNED => {
                                // leaq
                                const displacement = @bitCast(u32, @intCast(i32, @intCast(i64, target_addr) - @intCast(i64, this_addr) - 4));
                                mem.writeIntLittle(u32, inst, displacement);
                            },
                            macho.reloc_type_x86_64.X86_64_RELOC_GOT_LOAD => {
                                // movq
                                const displacement = @bitCast(u32, @intCast(i32, @intCast(i64, target_addr) - @intCast(i64, this_addr) - 4));
                                mem.writeIntLittle(u32, inst, displacement);
                            },
                            else => |tt| {
                                log.warn("unhandled relocation type '{}'", .{tt});
                            },
                        }
                    },
                    .aarch64 => {
                        switch (@intToEnum(macho.reloc_type_arm64, rel.r_type)) {
                            macho.reloc_type_arm64.ARM64_RELOC_BRANCH26 => {
                                const displacement = @intCast(i28, @intCast(i64, target_addr) - @intCast(i64, this_addr));
                                var parsed = mem.bytesAsValue(meta.TagPayloadType(Arm64, Arm64.Branch), inst);
                                parsed.disp = @truncate(u26, @bitCast(u28, displacement) >> 2);
                            },
                            macho.reloc_type_arm64.ARM64_RELOC_PAGE21, macho.reloc_type_arm64.ARM64_RELOC_GOT_LOAD_PAGE21, macho.reloc_type_arm64.ARM64_RELOC_TLVP_LOAD_PAGE21 => {
                                const this_page = this_addr >> 12;
                                const target_page = target_addr >> 12;
                                const pages = @bitCast(u21, @intCast(i21, target_page - this_page));
                                var parsed = mem.bytesAsValue(meta.TagPayloadType(Arm64, Arm64.Address), inst);
                                parsed.immhi = @truncate(u19, pages >> 2);
                                parsed.immlo = @truncate(u2, pages);
                            },
                            macho.reloc_type_arm64.ARM64_RELOC_PAGEOFF12, macho.reloc_type_arm64.ARM64_RELOC_GOT_LOAD_PAGEOFF12, macho.reloc_type_arm64.ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => {
                                const narrowed = @truncate(u12, target_addr);
                                var parsed = mem.bytesAsValue(meta.TagPayloadType(Arm64, Arm64.LoadRegister), inst);
                                parsed.offset = narrowed;
                            },
                            else => |tt| {
                                log.warn("unhandled relocation type '{}'", .{tt});
                            },
                        }
                    },
                    else => unreachable,
                }
            }

            var name = try self.allocator.dupe(u8, sectname);
            const res = try offsets.getOrPut(name);
            if (!res.found_existing) {
                res.entry.value = out_sect.offset;
            }
            const off = &res.entry.value;

            log.debug("writing contents of '{s}' section from '{s}' from 0x{x} to 0x{x}", .{
                sectname,
                object.name,
                off.*,
                off.* + code.len,
            });

            try self.file.?.pwriteAll(code, off.*);
            off.* += code.len;
        }
    }
}

fn populateMetadata(self: *Zld) !void {
    if (self.pagezero_segment_cmd_index == null) {
        self.pagezero_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .Segment = SegmentCommand.empty(.{
                .cmd = macho.LC_SEGMENT_64,
                .cmdsize = @sizeOf(macho.segment_command_64),
                .segname = makeStaticString("__PAGEZERO"),
                .vmaddr = 0,
                .vmsize = 0x100000000, // size always set to 4GB
                .fileoff = 0,
                .filesize = 0,
                .maxprot = 0,
                .initprot = 0,
                .nsects = 0,
                .flags = 0,
            }),
        });
        try self.addSegmentToDir(0);
    }

    if (self.text_segment_cmd_index == null) {
        self.text_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .Segment = SegmentCommand.empty(.{
                .cmd = macho.LC_SEGMENT_64,
                .cmdsize = @sizeOf(macho.segment_command_64),
                .segname = makeStaticString("__TEXT"),
                .vmaddr = 0x100000000, // always starts at 4GB
                .vmsize = 0,
                .fileoff = 0,
                .filesize = 0,
                .maxprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE | macho.VM_PROT_EXECUTE,
                .initprot = macho.VM_PROT_READ | macho.VM_PROT_EXECUTE,
                .nsects = 0,
                .flags = 0,
            }),
        });
        try self.addSegmentToDir(self.text_segment_cmd_index.?);
    }

    if (self.text_section_index == null) {
        const text_seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        self.text_section_index = @intCast(u16, text_seg.sections.items().len);
        const alignment: u2 = switch (self.arch.?) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        try text_seg.put(self.allocator, .{
            .sectname = makeStaticString("__text"),
            .segname = makeStaticString("__TEXT"),
            .addr = 0,
            .size = 0,
            .offset = 0,
            .@"align" = alignment,
            .reloff = 0,
            .nreloc = 0,
            .flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
            .reserved1 = 0,
            .reserved2 = 0,
            .reserved3 = 0,
        });
    }

    if (self.stubs_section_index == null) {
        const text_seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        self.stubs_section_index = @intCast(u16, text_seg.sections.items().len);
        const alignment: u2 = switch (self.arch.?) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        const stub_size: u4 = switch (self.arch.?) {
            .x86_64 => 6,
            .aarch64 => 2 * @sizeOf(u32),
            else => unreachable, // unhandled architecture type
        };
        try text_seg.put(self.allocator, .{
            .sectname = makeStaticString("__stubs"),
            .segname = makeStaticString("__TEXT"),
            .addr = 0,
            .size = 0,
            .offset = 0,
            .@"align" = alignment,
            .reloff = 0,
            .nreloc = 0,
            .flags = macho.S_SYMBOL_STUBS | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
            .reserved1 = 0,
            .reserved2 = stub_size,
            .reserved3 = 0,
        });
    }

    if (self.stub_helper_section_index == null) {
        const text_seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        self.stub_helper_section_index = @intCast(u16, text_seg.sections.items().len);
        const alignment: u2 = switch (self.arch.?) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        const stub_helper_size: u5 = switch (self.arch.?) {
            .x86_64 => 15,
            .aarch64 => 6 * @sizeOf(u32),
            else => unreachable,
        };
        try text_seg.put(self.allocator, .{
            .sectname = makeStaticString("__stub_helper"),
            .segname = makeStaticString("__TEXT"),
            .addr = 0,
            .size = stub_helper_size,
            .offset = 0,
            .@"align" = alignment,
            .reloff = 0,
            .nreloc = 0,
            .flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
            .reserved1 = 0,
            .reserved2 = 0,
            .reserved3 = 0,
        });
    }

    if (self.data_const_segment_cmd_index == null) {
        self.data_const_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .Segment = SegmentCommand.empty(.{
                .cmd = macho.LC_SEGMENT_64,
                .cmdsize = @sizeOf(macho.segment_command_64),
                .segname = makeStaticString("__DATA_CONST"),
                .vmaddr = 0,
                .vmsize = 0,
                .fileoff = 0,
                .filesize = 0,
                .maxprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE | macho.VM_PROT_EXECUTE,
                .initprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE,
                .nsects = 0,
                .flags = 0,
            }),
        });
        try self.addSegmentToDir(self.data_const_segment_cmd_index.?);
    }

    if (self.got_section_index == null) {
        const data_const_seg = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
        self.got_section_index = @intCast(u16, data_const_seg.sections.items().len);
        try data_const_seg.put(self.allocator, .{
            .sectname = makeStaticString("__got"),
            .segname = makeStaticString("__DATA_CONST"),
            .addr = 0,
            .size = 0,
            .offset = 0,
            .@"align" = 3, // 2^3 = @sizeOf(u64)
            .reloff = 0,
            .nreloc = 0,
            .flags = macho.S_NON_LAZY_SYMBOL_POINTERS,
            .reserved1 = 0,
            .reserved2 = 0,
            .reserved3 = 0,
        });
    }

    if (self.data_segment_cmd_index == null) {
        self.data_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .Segment = SegmentCommand.empty(.{
                .cmd = macho.LC_SEGMENT_64,
                .cmdsize = @sizeOf(macho.segment_command_64),
                .segname = makeStaticString("__DATA"),
                .vmaddr = 0,
                .vmsize = 0,
                .fileoff = 0,
                .filesize = 0,
                .maxprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE | macho.VM_PROT_EXECUTE,
                .initprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE,
                .nsects = 0,
                .flags = 0,
            }),
        });
        try self.addSegmentToDir(self.data_segment_cmd_index.?);
    }

    if (self.la_symbol_ptr_section_index == null) {
        const data_seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        self.la_symbol_ptr_section_index = @intCast(u16, data_seg.sections.items().len);
        try data_seg.put(self.allocator, .{
            .sectname = makeStaticString("__la_symbol_ptr"),
            .segname = makeStaticString("__DATA"),
            .addr = 0,
            .size = 0,
            .offset = 0,
            .@"align" = 3, // 2^3 = @sizeOf(u64)
            .reloff = 0,
            .nreloc = 0,
            .flags = macho.S_LAZY_SYMBOL_POINTERS,
            .reserved1 = 0,
            .reserved2 = 0,
            .reserved3 = 0,
        });
    }

    if (self.data_section_index == null) {
        const data_seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        self.data_section_index = @intCast(u16, data_seg.sections.items().len);
        try data_seg.put(self.allocator, .{
            .sectname = makeStaticString("__data"),
            .segname = makeStaticString("__DATA"),
            .addr = 0,
            .size = 0,
            .offset = 0,
            .@"align" = 3, // 2^3 = @sizeOf(u64)
            .reloff = 0,
            .nreloc = 0,
            .flags = macho.S_REGULAR,
            .reserved1 = 0,
            .reserved2 = 0,
            .reserved3 = 0,
        });
    }

    if (self.linkedit_segment_cmd_index == null) {
        self.linkedit_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .Segment = SegmentCommand.empty(.{
                .cmd = macho.LC_SEGMENT_64,
                .cmdsize = @sizeOf(macho.segment_command_64),
                .segname = makeStaticString("__LINKEDIT"),
                .vmaddr = 0,
                .vmsize = 0,
                .fileoff = 0,
                .filesize = 0,
                .maxprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE | macho.VM_PROT_EXECUTE,
                .initprot = macho.VM_PROT_READ,
                .nsects = 0,
                .flags = 0,
            }),
        });
        try self.addSegmentToDir(self.linkedit_segment_cmd_index.?);
    }

    if (self.dyld_info_cmd_index == null) {
        self.dyld_info_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .DyldInfoOnly = .{
                .cmd = macho.LC_DYLD_INFO_ONLY,
                .cmdsize = @sizeOf(macho.dyld_info_command),
                .rebase_off = 0,
                .rebase_size = 0,
                .bind_off = 0,
                .bind_size = 0,
                .weak_bind_off = 0,
                .weak_bind_size = 0,
                .lazy_bind_off = 0,
                .lazy_bind_size = 0,
                .export_off = 0,
                .export_size = 0,
            },
        });
    }

    if (self.symtab_cmd_index == null) {
        self.symtab_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .Symtab = .{
                .cmd = macho.LC_SYMTAB,
                .cmdsize = @sizeOf(macho.symtab_command),
                .symoff = 0,
                .nsyms = 0,
                .stroff = 0,
                .strsize = 0,
            },
        });
    }

    if (self.dysymtab_cmd_index == null) {
        self.dysymtab_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .Dysymtab = .{
                .cmd = macho.LC_DYSYMTAB,
                .cmdsize = @sizeOf(macho.dysymtab_command),
                .ilocalsym = 0,
                .nlocalsym = 0,
                .iextdefsym = 0,
                .nextdefsym = 0,
                .iundefsym = 0,
                .nundefsym = 0,
                .tocoff = 0,
                .ntoc = 0,
                .modtaboff = 0,
                .nmodtab = 0,
                .extrefsymoff = 0,
                .nextrefsyms = 0,
                .indirectsymoff = 0,
                .nindirectsyms = 0,
                .extreloff = 0,
                .nextrel = 0,
                .locreloff = 0,
                .nlocrel = 0,
            },
        });
    }

    if (self.dylinker_cmd_index == null) {
        self.dylinker_cmd_index = @intCast(u16, self.load_commands.items.len);
        const cmdsize = @intCast(u32, mem.alignForwardGeneric(
            u64,
            @sizeOf(macho.dylinker_command) + mem.lenZ(DEFAULT_DYLD_PATH),
            @sizeOf(u64),
        ));
        var dylinker_cmd = emptyGenericCommandWithData(macho.dylinker_command{
            .cmd = macho.LC_LOAD_DYLINKER,
            .cmdsize = cmdsize,
            .name = @sizeOf(macho.dylinker_command),
        });
        dylinker_cmd.data = try self.allocator.alloc(u8, cmdsize - dylinker_cmd.inner.name);
        mem.set(u8, dylinker_cmd.data, 0);
        mem.copy(u8, dylinker_cmd.data, mem.spanZ(DEFAULT_DYLD_PATH));
        try self.load_commands.append(self.allocator, .{ .Dylinker = dylinker_cmd });
    }

    if (self.libsystem_cmd_index == null) {
        self.libsystem_cmd_index = @intCast(u16, self.load_commands.items.len);
        const cmdsize = @intCast(u32, mem.alignForwardGeneric(
            u64,
            @sizeOf(macho.dylib_command) + mem.lenZ(LIB_SYSTEM_PATH),
            @sizeOf(u64),
        ));
        // TODO Find a way to work out runtime version from the OS version triple stored in std.Target.
        // In the meantime, we're gonna hardcode to the minimum compatibility version of 0.0.0.
        const min_version = 0x0;
        var dylib_cmd = emptyGenericCommandWithData(macho.dylib_command{
            .cmd = macho.LC_LOAD_DYLIB,
            .cmdsize = cmdsize,
            .dylib = .{
                .name = @sizeOf(macho.dylib_command),
                .timestamp = 2, // not sure why not simply 0; this is reverse engineered from Mach-O files
                .current_version = min_version,
                .compatibility_version = min_version,
            },
        });
        dylib_cmd.data = try self.allocator.alloc(u8, cmdsize - dylib_cmd.inner.dylib.name);
        mem.set(u8, dylib_cmd.data, 0);
        mem.copy(u8, dylib_cmd.data, mem.spanZ(LIB_SYSTEM_PATH));
        try self.load_commands.append(self.allocator, .{ .Dylib = dylib_cmd });
    }

    if (self.main_cmd_index == null) {
        self.main_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .Main = .{
                .cmd = macho.LC_MAIN,
                .cmdsize = @sizeOf(macho.entry_point_command),
                .entryoff = 0x0,
                .stacksize = 0,
            },
        });
    }

    if (self.source_version_cmd_index == null) {
        self.source_version_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .SourceVersion = .{
                .cmd = macho.LC_SOURCE_VERSION,
                .cmdsize = @sizeOf(macho.source_version_command),
                .version = 0x0,
            },
        });
    }

    if (self.uuid_cmd_index == null) {
        self.uuid_cmd_index = @intCast(u16, self.load_commands.items.len);
        var uuid_cmd: macho.uuid_command = .{
            .cmd = macho.LC_UUID,
            .cmdsize = @sizeOf(macho.uuid_command),
            .uuid = undefined,
        };
        std.crypto.random.bytes(&uuid_cmd.uuid);
        try self.load_commands.append(self.allocator, .{ .Uuid = uuid_cmd });
    }

    if (self.code_signature_cmd_index == null and self.arch.? == .aarch64) {
        self.code_signature_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.allocator, .{
            .LinkeditData = .{
                .cmd = macho.LC_CODE_SIGNATURE,
                .cmdsize = @sizeOf(macho.linkedit_data_command),
                .dataoff = 0,
                .datasize = 0,
            },
        });
    }
}

fn flush(self: *Zld) !void {
    try self.setEntryPoint();
    try self.writeRebaseInfoTable();
    try self.writeBindInfoTable();
    try self.writeLazyBindInfoTable();
    try self.writeExportInfo();
    try self.writeSymbolTable();
    try self.writeDynamicSymbolTable();
    try self.writeStringTable();

    {
        // Seal __LINKEDIT size
        const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
        seg.inner.vmsize = mem.alignForwardGeneric(u64, seg.inner.filesize, self.page_size.?);
    }

    if (self.arch.? == .aarch64) {
        try self.writeCodeSignaturePadding();
    }

    try self.writeLoadCommands();
    try self.writeHeader();

    if (self.arch.? == .aarch64) {
        try self.writeCodeSignature();
    }

    if (comptime std.Target.current.isDarwin() and std.Target.current.cpu.arch == .aarch64) {
        try fs.cwd().copyFile(self.out_path.?, fs.cwd(), self.out_path.?, .{});
    }
}

fn setEntryPoint(self: *Zld) !void {
    const seg = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const text = seg.sections.items()[self.text_section_index.?].value;
    const entrypoint = self.exports.getEntry("_main") orelse return error.MissingMainEntrypoint;
    entrypoint.value.n_value = text.addr;

    const ec = &self.load_commands.items[self.main_cmd_index.?].Main;
    ec.entryoff = @intCast(u32, text.addr - seg.inner.vmaddr);
}

fn writeRebaseInfoTable(self: *Zld) !void {
    const size = try rebaseInfoSize(self.extern_lazy_symbols.items());
    var buffer = try self.allocator.alloc(u8, @intCast(usize, size));
    defer self.allocator.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    try writeRebaseInfo(self.extern_lazy_symbols.items(), stream.writer());

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    dyld_info.rebase_off = @intCast(u32, seg.inner.fileoff);
    dyld_info.rebase_size = @intCast(u32, mem.alignForwardGeneric(u64, buffer.len, @sizeOf(u64)));
    seg.inner.filesize += dyld_info.rebase_size;

    log.debug("writing rebase info from 0x{x} to 0x{x}", .{ dyld_info.rebase_off, dyld_info.rebase_off + dyld_info.rebase_size });

    try self.file.?.pwriteAll(buffer, dyld_info.rebase_off);
}

fn writeBindInfoTable(self: *Zld) !void {
    const size = try bindInfoSize(self.extern_nonlazy_symbols.items());
    var buffer = try self.allocator.alloc(u8, @intCast(usize, size));
    defer self.allocator.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    try writeBindInfo(self.extern_nonlazy_symbols.items(), stream.writer());

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    dyld_info.bind_off = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    dyld_info.bind_size = @intCast(u32, mem.alignForwardGeneric(u64, buffer.len, @alignOf(u64)));
    seg.inner.filesize += dyld_info.bind_size;

    log.debug("writing binding info from 0x{x} to 0x{x}", .{ dyld_info.bind_off, dyld_info.bind_off + dyld_info.bind_size });

    try self.file.?.pwriteAll(buffer, dyld_info.bind_off);
}

fn writeLazyBindInfoTable(self: *Zld) !void {
    const size = try lazyBindInfoSize(self.extern_lazy_symbols.items());
    var buffer = try self.allocator.alloc(u8, @intCast(usize, size));
    defer self.allocator.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    try writeLazyBindInfo(self.extern_lazy_symbols.items(), stream.writer());

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    dyld_info.lazy_bind_off = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    dyld_info.lazy_bind_size = @intCast(u32, mem.alignForwardGeneric(u64, buffer.len, @alignOf(u64)));
    seg.inner.filesize += dyld_info.lazy_bind_size;

    log.debug("writing lazy binding info from 0x{x} to 0x{x}", .{ dyld_info.lazy_bind_off, dyld_info.lazy_bind_off + dyld_info.lazy_bind_size });

    try self.file.?.pwriteAll(buffer, dyld_info.lazy_bind_off);
}

fn writeExportInfo(self: *Zld) !void {
    var trie = Trie.init(self.allocator);
    defer trie.deinit();

    const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    for (self.exports.items()) |entry| {
        const name = entry.key;
        const symbol = entry.value;
        // TODO figure out if we should put all exports into the export trie
        assert(symbol.n_value >= text_segment.inner.vmaddr);
        try trie.put(.{
            .name = name,
            .vmaddr_offset = symbol.n_value - text_segment.inner.vmaddr,
            .export_flags = macho.EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
        });
    }

    try trie.finalize();
    var buffer = try self.allocator.alloc(u8, @intCast(usize, trie.size));
    defer self.allocator.free(buffer);
    var stream = std.io.fixedBufferStream(buffer);
    const nwritten = try trie.write(stream.writer());
    assert(nwritten == trie.size);

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    dyld_info.export_off = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    dyld_info.export_size = @intCast(u32, mem.alignForwardGeneric(u64, buffer.len, @alignOf(u64)));
    seg.inner.filesize += dyld_info.export_size;

    log.debug("writing export info from 0x{x} to 0x{x}", .{ dyld_info.export_off, dyld_info.export_off + dyld_info.export_size });

    try self.file.?.pwriteAll(buffer, dyld_info.export_off);
}

fn writeSymbolTable(self: *Zld) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;

    const nlocals = self.locals.items.len;
    const nexports = self.exports.items().len;

    const nundefs = self.extern_lazy_symbols.items().len + self.extern_nonlazy_symbols.items().len;
    var undefs = std.ArrayList(macho.nlist_64).init(self.allocator);
    defer undefs.deinit();

    try undefs.ensureCapacity(nundefs);
    for (self.extern_lazy_symbols.items()) |entry| {
        undefs.appendAssumeCapacity(entry.value.inner);
    }
    for (self.extern_nonlazy_symbols.items()) |entry| {
        undefs.appendAssumeCapacity(entry.value.inner);
    }

    symtab.symoff = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    symtab.nsyms = @intCast(u32, nlocals + nexports + nundefs);

    const locals_off = symtab.symoff;
    const locals_size = nlocals * @sizeOf(macho.nlist_64);
    log.debug("writing local symbols from 0x{x} to 0x{x}", .{ locals_off, locals_size + locals_off });
    try self.file.?.pwriteAll(mem.sliceAsBytes(self.locals.items), locals_off);

    const exports_off = locals_off + locals_size;
    const exports_size = nexports * @sizeOf(macho.nlist_64);
    log.debug("writing export symbols from 0x{x} to 0x{x}", .{ exports_off, exports_size + exports_off });
    try self.file.?.pwriteAll(mem.sliceAsBytes(self.exports.items()), exports_off);

    const undefs_off = exports_off + exports_size;
    const undefs_size = nundefs * @sizeOf(macho.nlist_64);
    log.debug("writing extern symbols from 0x{x} to 0x{x}", .{ undefs_off, undefs_size + undefs_off });
    try self.file.?.pwriteAll(mem.sliceAsBytes(undefs.items), undefs_off);

    seg.inner.filesize += locals_size + exports_size + undefs_size;

    // Update dynamic symbol table.
    const dysymtab = &self.load_commands.items[self.dysymtab_cmd_index.?].Dysymtab;
    dysymtab.nlocalsym = @intCast(u32, nlocals);
    dysymtab.iextdefsym = @intCast(u32, nlocals);
    dysymtab.nextdefsym = @intCast(u32, nexports);
    dysymtab.iundefsym = @intCast(u32, nlocals + nexports);
    dysymtab.nundefsym = @intCast(u32, nundefs);
}

fn writeDynamicSymbolTable(self: *Zld) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const text_segment = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stubs = &text_segment.sections.items()[self.stubs_section_index.?].value;
    const data_const_seg = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const got = &data_const_seg.sections.items()[self.got_section_index.?].value;
    const data_segment = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const la_symbol_ptr = &data_segment.sections.items()[self.la_symbol_ptr_section_index.?].value;
    const dysymtab = &self.load_commands.items[self.dysymtab_cmd_index.?].Dysymtab;

    const lazy = self.extern_lazy_symbols.items();
    const nonlazy = self.extern_nonlazy_symbols.items();
    dysymtab.indirectsymoff = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    dysymtab.nindirectsyms = @intCast(u32, lazy.len * 2 + nonlazy.len);
    const needed_size = dysymtab.nindirectsyms * @sizeOf(u32);
    seg.inner.filesize += needed_size;

    log.debug("writing indirect symbol table from 0x{x} to 0x{x}", .{
        dysymtab.indirectsymoff,
        dysymtab.indirectsymoff + needed_size,
    });

    var buf = try self.allocator.alloc(u8, needed_size);
    defer self.allocator.free(buf);
    var stream = std.io.fixedBufferStream(buf);
    var writer = stream.writer();

    stubs.reserved1 = 0;
    for (self.extern_lazy_symbols.items()) |_, i| {
        const symtab_idx = @intCast(u32, dysymtab.iundefsym + i);
        try writer.writeIntLittle(u32, symtab_idx);
    }

    const base_id = @intCast(u32, lazy.len);
    got.reserved1 = base_id;
    for (self.extern_nonlazy_symbols.items()) |_, i| {
        const symtab_idx = @intCast(u32, dysymtab.iundefsym + i + base_id);
        try writer.writeIntLittle(u32, symtab_idx);
    }

    la_symbol_ptr.reserved1 = got.reserved1 + @intCast(u32, nonlazy.len);
    for (self.extern_lazy_symbols.items()) |_, i| {
        const symtab_idx = @intCast(u32, dysymtab.iundefsym + i);
        try writer.writeIntLittle(u32, symtab_idx);
    }

    try self.file.?.pwriteAll(buf, dysymtab.indirectsymoff);
}

fn writeStringTable(self: *Zld) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;
    symtab.stroff = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    symtab.strsize = @intCast(u32, mem.alignForwardGeneric(u64, self.string_table.items.len, @alignOf(u64)));
    seg.inner.filesize += symtab.strsize;

    log.debug("writing string table from 0x{x} to 0x{x}", .{ symtab.stroff, symtab.stroff + symtab.strsize });

    try self.file.?.pwriteAll(self.string_table.items, symtab.stroff);

    if (symtab.strsize > self.string_table.items.len and self.arch.? == .x86_64) {
        // This is the last section, so we need to pad it out.
        try self.file.?.pwriteAll(&[_]u8{0}, seg.inner.fileoff + seg.inner.filesize - 1);
    }
}

fn writeCodeSignaturePadding(self: *Zld) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const code_sig_cmd = &self.load_commands.items[self.code_signature_cmd_index.?].LinkeditData;
    const fileoff = seg.inner.fileoff + seg.inner.filesize;
    const needed_size = CodeSignature.calcCodeSignaturePaddingSize(
        self.out_path.?,
        fileoff,
        self.page_size.?,
    );
    code_sig_cmd.dataoff = @intCast(u32, fileoff);
    code_sig_cmd.datasize = needed_size;

    // Advance size of __LINKEDIT segment
    seg.inner.filesize += needed_size;
    seg.inner.vmsize = mem.alignForwardGeneric(u64, seg.inner.filesize, self.page_size.?);

    log.debug("writing code signature padding from 0x{x} to 0x{x}", .{ fileoff, fileoff + needed_size });

    // Pad out the space. We need to do this to calculate valid hashes for everything in the file
    // except for code signature data.
    try self.file.?.pwriteAll(&[_]u8{0}, fileoff + needed_size - 1);
}

fn writeCodeSignature(self: *Zld) !void {
    const text_seg = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const code_sig_cmd = self.load_commands.items[self.code_signature_cmd_index.?].LinkeditData;

    var code_sig = CodeSignature.init(self.allocator, self.page_size.?);
    defer code_sig.deinit();
    try code_sig.calcAdhocSignature(
        self.file.?,
        self.out_path.?,
        text_seg.inner,
        code_sig_cmd,
        .Exe,
    );

    var buffer = try self.allocator.alloc(u8, code_sig.size());
    defer self.allocator.free(buffer);
    var stream = std.io.fixedBufferStream(buffer);
    try code_sig.write(stream.writer());

    log.debug("writing code signature from 0x{x} to 0x{x}", .{ code_sig_cmd.dataoff, code_sig_cmd.dataoff + buffer.len });

    try self.file.?.pwriteAll(buffer, code_sig_cmd.dataoff);
}

fn writeLoadCommands(self: *Zld) !void {
    var sizeofcmds: u32 = 0;
    for (self.load_commands.items) |lc| {
        sizeofcmds += lc.cmdsize();
    }

    var buffer = try self.allocator.alloc(u8, sizeofcmds);
    defer self.allocator.free(buffer);
    var writer = std.io.fixedBufferStream(buffer).writer();
    for (self.load_commands.items) |lc| {
        try lc.write(writer);
    }

    const off = @sizeOf(macho.mach_header_64);
    log.debug("writing {} load commands from 0x{x} to 0x{x}", .{ self.load_commands.items.len, off, off + sizeofcmds });
    try self.file.?.pwriteAll(buffer, off);
}

fn writeHeader(self: *Zld) !void {
    var header: macho.mach_header_64 = undefined;
    header.magic = macho.MH_MAGIC_64;

    const CpuInfo = struct {
        cpu_type: macho.cpu_type_t,
        cpu_subtype: macho.cpu_subtype_t,
    };

    const cpu_info: CpuInfo = switch (self.arch.?) {
        .aarch64 => .{
            .cpu_type = macho.CPU_TYPE_ARM64,
            .cpu_subtype = macho.CPU_SUBTYPE_ARM_ALL,
        },
        .x86_64 => .{
            .cpu_type = macho.CPU_TYPE_X86_64,
            .cpu_subtype = macho.CPU_SUBTYPE_X86_64_ALL,
        },
        else => return error.UnsupportedMachOArchitecture,
    };
    header.cputype = cpu_info.cpu_type;
    header.cpusubtype = cpu_info.cpu_subtype;
    header.filetype = macho.MH_EXECUTE;
    header.flags = macho.MH_NOUNDEFS | macho.MH_DYLDLINK | macho.MH_PIE;
    header.reserved = 0;

    header.ncmds = @intCast(u32, self.load_commands.items.len);
    header.sizeofcmds = 0;
    for (self.load_commands.items) |cmd| {
        header.sizeofcmds += cmd.cmdsize();
    }
    log.debug("writing Mach-O header {}", .{header});
    try self.file.?.pwriteAll(mem.asBytes(&header), 0);
}

pub fn makeStaticString(bytes: []const u8) [16]u8 {
    var buf = [_]u8{0} ** 16;
    assert(bytes.len <= buf.len);
    mem.copy(u8, &buf, bytes);
    return buf;
}

fn makeString(self: *Zld, bytes: []const u8) !u32 {
    if (self.string_table_directory.get(bytes)) |offset| {
        log.debug("reusing '{s}' from string table at offset 0x{x}", .{ bytes, offset });
        return offset;
    }

    try self.string_table.ensureCapacity(self.allocator, self.string_table.items.len + bytes.len + 1);
    const offset = @intCast(u32, self.string_table.items.len);
    log.debug("writing new string '{s}' into string table at offset 0x{x}", .{ bytes, offset });
    self.string_table.appendSliceAssumeCapacity(bytes);
    self.string_table.appendAssumeCapacity(0);
    try self.string_table_directory.putNoClobber(
        self.allocator,
        try self.allocator.dupe(u8, bytes),
        offset,
    );

    return offset;
}

fn getString(self: *const Zld, str_off: u32) []const u8 {
    assert(str_off < self.string_table.items.len);
    return mem.spanZ(@ptrCast([*:0]const u8, self.string_table.items.ptr + str_off));
}

fn addSegmentToDir(self: *Zld, idx: u16) !void {
    const segment_cmd = self.load_commands.items[idx].Segment;
    const name = parseName(&segment_cmd.inner.segname);
    var key = try self.allocator.dupe(u8, name);
    try self.segments_dir.putNoClobber(self.allocator, key, idx);
}

inline fn isLocal(sym: *const macho.nlist_64) bool {
    return sym.n_type == macho.N_SECT;
}

inline fn isExport(sym: *const macho.nlist_64) bool {
    return sym.n_type == macho.N_SECT | macho.N_EXT;
}

inline fn isImport(sym: *const macho.nlist_64) bool {
    return sym.n_type == macho.N_UNDF | macho.N_EXT;
}
