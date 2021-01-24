const Zld = @This();

const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const fs = std.fs;
const macho = std.macho;
const log = std.log.scoped(.zld);
const reloc = @import("reloc.zig");

const Allocator = mem.Allocator;
const Target = std.Target;
const CodeSignature = @import("CodeSignature.zig");
const Object = @import("Object.zig");
const Trie = @import("Trie.zig");

usingnamespace @import("commands.zig");
usingnamespace @import("imports.zig");

allocator: *Allocator,
target: Target,
page_size: u16,

file: ?fs.File = null,

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

local_symbols: std.ArrayListUnmanaged(macho.nlist_64) = .{},
global_symbols: std.ArrayListUnmanaged(macho.nlist_64) = .{},
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

pub fn init(allocator: *Allocator, target: Target) Zld {
    const page_size: u16 = switch (target.cpu.arch) {
        .aarch64 => 0x4000,
        .x86_64 => 0x1000,
        else => unreachable,
    };
    return .{
        .allocator = allocator,
        .target = target,
        .page_size = page_size,
    };
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
    self.extern_lazy_symbols.deinit(self.allocator);
    self.extern_nonlazy_symbols.deinit(self.allocator);
    self.global_symbols.deinit(self.allocator);
    self.local_symbols.deinit(self.allocator);
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
    self.file.?.close();
}

pub fn link(self: *Zld, files: []const []const u8) !void {
    try self.populateMetadata();

    try self.objects.ensureCapacity(self.allocator, files.len);
    for (files) |file_name| {
        var object: Object = .{ .base = self };
        object.file = try fs.cwd().openFile(file_name, .{});
        try object.parse();
        self.objects.appendAssumeCapacity(object);

        const seg_cmd = object.load_commands.items[object.segment_cmd_index.?].Segment;
        for (seg_cmd.sections.items()) |entry| {
            const name = entry.key;
            const sect = entry.value;
            const segname = parseName(&sect.segname);

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
            const sym_name = object.getString(sym.n_strx);
            const n_strx = try self.makeString(sym_name);
            const new_sym = .{
                .n_strx = n_strx,
                .n_type = sym.n_type,
                .n_value = sym.n_value,
                .n_desc = sym.n_desc,
                .n_sect = sym.n_sect,
            };
            if (sym.n_type == (macho.N_SECT | macho.N_EXT)) {
                log.debug("writing global symbol '{s}' {}", .{ sym_name, new_sym });
                try self.global_symbols.append(self.allocator, new_sym);
            } else if (sym.n_type == macho.N_SECT) {
                log.debug("writing local symbol '{s}' {}", .{ sym_name, new_sym });
                try self.local_symbols.append(self.allocator, new_sym);
            } else if (sym.n_type == (macho.N_UNDF | macho.N_EXT)) {
                if (mem.eql(u8, sym_name, "___stderrp")) {
                    log.debug("writing nonlazy symbol '{s}' {}", .{ sym_name, new_sym });
                    var key = try self.allocator.dupe(u8, sym_name);
                    try self.extern_nonlazy_symbols.putNoClobber(self.allocator, key, .{
                        .inner = new_sym,
                        .dylib_ordinal = 1,
                        .segment = 2,
                    });
                } else {
                    log.debug("writing lazy symbol '{s}' {}", .{ sym_name, new_sym });
                    var key = try self.allocator.dupe(u8, sym_name);
                    try self.extern_lazy_symbols.putNoClobber(self.allocator, key, .{
                        .inner = new_sym,
                        .dylib_ordinal = 1,
                        .segment = 3,
                    });
                }
            } else {
                log.warn("unhandled symbol '{s}' of type 0x{x}", .{ sym_name, sym.n_type });
            }
        }
    }

    try self.allocateSegments();
    try self.flush();
}

fn allocateSegments(self: *Zld) !void {}

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
        const alignment: u2 = switch (self.target.cpu.arch) {
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
        const alignment: u2 = switch (self.target.cpu.arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        const stub_size: u4 = switch (self.target.cpu.arch) {
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
        const alignment: u2 = switch (self.target.cpu.arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        try text_seg.put(self.allocator, .{
            .sectname = makeStaticString("__stub_helper"),
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
    if (self.code_signature_cmd_index == null) {
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
    self.file = try fs.cwd().createFile("a.out", .{ .truncate = true });

    try self.writeCodeSignaturePadding();
    try self.writeLoadCommands();
    try self.writeHeader();
    try self.writeCodeSignature();
}

fn writeCodeSignaturePadding(self: *Zld) !void {
    const linkedit_seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const code_sig_cmd = &self.load_commands.items[self.code_signature_cmd_index.?].LinkeditData;
    const fileoff = linkedit_seg.inner.fileoff + linkedit_seg.inner.filesize;
    const needed_size = CodeSignature.calcCodeSignaturePaddingSize(
        "a.out",
        fileoff,
        self.page_size,
    );
    code_sig_cmd.dataoff = @intCast(u32, fileoff);
    code_sig_cmd.datasize = needed_size;

    // Advance size of __LINKEDIT segment
    linkedit_seg.inner.filesize += needed_size;
    if (linkedit_seg.inner.vmsize < linkedit_seg.inner.filesize) {
        linkedit_seg.inner.vmsize = mem.alignForwardGeneric(u64, linkedit_seg.inner.filesize, self.page_size);
    }
    log.debug("writing code signature padding from 0x{x} to 0x{x}", .{ fileoff, fileoff + needed_size });
    // Pad out the space. We need to do this to calculate valid hashes for everything in the file
    // except for code signature data.
    try self.file.?.pwriteAll(&[_]u8{0}, fileoff + needed_size - 1);
}

fn writeCodeSignature(self: *Zld) !void {
    const text_seg = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const code_sig_cmd = self.load_commands.items[self.code_signature_cmd_index.?].LinkeditData;

    var code_sig = CodeSignature.init(self.allocator, self.page_size);
    defer code_sig.deinit();
    try code_sig.calcAdhocSignature(
        self.file.?,
        "a.out",
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

    const cpu_info: CpuInfo = switch (self.target.cpu.arch) {
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

fn makeStaticString(bytes: []const u8) [16]u8 {
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
