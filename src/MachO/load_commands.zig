const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.link);
const macho = std.macho;
const mem = std.mem;

const Allocator = mem.Allocator;
const Dylib = @import("Dylib.zig");
const MachO = @import("../MachO.zig");
const Options = @import("../MachO.zig").Options;

pub const default_dyld_path: [*:0]const u8 = "/usr/lib/dyld";

fn calcInstallNameLen(cmd_size: u64, name: []const u8, assume_max_path_len: bool) u64 {
    const darwin_path_max = 1024;
    const name_len = if (assume_max_path_len) darwin_path_max else name.len + 1;
    return mem.alignForward(u64, cmd_size + name_len, @alignOf(u64));
}

fn calcLCsSize(macho_file: *MachO, assume_max_path_len: bool) !u32 {
    const gpa = macho_file.base.allocator;
    const options = &macho_file.options;
    var has_text_segment: bool = false;
    var sizeofcmds: u64 = 0;
    for (macho_file.segments.items) |seg| {
        sizeofcmds += seg.nsects * @sizeOf(macho.section_64) + @sizeOf(macho.segment_command_64);
        if (mem.eql(u8, seg.segName(), "__TEXT")) {
            has_text_segment = true;
        }
    }

    // LC_DYLD_INFO_ONLY
    sizeofcmds += @sizeOf(macho.dyld_info_command);
    // LC_FUNCTION_STARTS
    if (has_text_segment) {
        sizeofcmds += @sizeOf(macho.linkedit_data_command);
    }
    // LC_DATA_IN_CODE
    sizeofcmds += @sizeOf(macho.linkedit_data_command);
    // LC_SYMTAB
    sizeofcmds += @sizeOf(macho.symtab_command);
    // LC_DYSYMTAB
    sizeofcmds += @sizeOf(macho.dysymtab_command);
    // LC_LOAD_DYLINKER
    sizeofcmds += calcInstallNameLen(
        @sizeOf(macho.dylinker_command),
        mem.sliceTo(default_dyld_path, 0),
        false,
    );
    // LC_MAIN
    if (macho_file.options.output_mode == .exe) {
        sizeofcmds += @sizeOf(macho.entry_point_command);
    }
    // LC_ID_DYLIB
    if (options.output_mode == .lib) {
        sizeofcmds += blk: {
            const emit = options.emit;
            const install_name = options.install_name orelse emit.sub_path;
            break :blk calcInstallNameLen(
                @sizeOf(macho.dylib_command),
                install_name,
                assume_max_path_len,
            );
        };
    }
    // LC_RPATH
    {
        var it = RpathIterator.init(gpa, options.rpath_list);
        defer it.deinit();
        while (try it.next()) |rpath| {
            sizeofcmds += calcInstallNameLen(
                @sizeOf(macho.rpath_command),
                rpath,
                assume_max_path_len,
            );
        }
    }
    // LC_SOURCE_VERSION
    sizeofcmds += @sizeOf(macho.source_version_command);
    // LC_BUILD_VERSION
    if (options.platform) |_| {
        sizeofcmds += @sizeOf(macho.build_version_command) + @sizeOf(macho.build_tool_version);
    }
    // LC_UUID
    sizeofcmds += @sizeOf(macho.uuid_command);
    // LC_LOAD_DYLIB
    for (macho_file.referenced_dylibs.keys()) |id| {
        const dylib = macho_file.dylibs.items[id];
        const dylib_id = dylib.id orelse unreachable;
        sizeofcmds += calcInstallNameLen(
            @sizeOf(macho.dylib_command),
            dylib_id.name,
            assume_max_path_len,
        );
    }
    // LC_CODE_SIGNATURE
    if (macho_file.requiresCodeSig()) {
        sizeofcmds += @sizeOf(macho.linkedit_data_command);
    }

    return @as(u32, @intCast(sizeofcmds));
}

pub fn calcMinHeaderPad(macho_file: *MachO) !u64 {
    const options = &macho_file.options;
    var padding: u32 = (try calcLCsSize(macho_file, false)) + (options.headerpad orelse 0);
    log.debug("minimum requested headerpad size 0x{x}", .{padding + @sizeOf(macho.mach_header_64)});

    if (options.headerpad_max_install_names) {
        var min_headerpad_size: u32 = try calcLCsSize(macho_file, true);
        log.debug("headerpad_max_install_names minimum headerpad size 0x{x}", .{
            min_headerpad_size + @sizeOf(macho.mach_header_64),
        });
        padding = @max(padding, min_headerpad_size);
    }

    const offset = @sizeOf(macho.mach_header_64) + padding;
    log.debug("actual headerpad size 0x{x}", .{offset});

    return offset;
}

pub fn calcNumOfLCs(lc_buffer: []const u8) u32 {
    var ncmds: u32 = 0;
    var pos: usize = 0;
    while (true) {
        if (pos >= lc_buffer.len) break;
        const cmd = @as(*align(1) const macho.load_command, @ptrCast(lc_buffer.ptr + pos)).*;
        ncmds += 1;
        pos += cmd.cmdsize;
    }
    return ncmds;
}

pub fn writeDylinkerLC(lc_writer: anytype) !void {
    const name_len = mem.sliceTo(default_dyld_path, 0).len;
    const cmdsize = @as(u32, @intCast(mem.alignForward(
        u64,
        @sizeOf(macho.dylinker_command) + name_len,
        @sizeOf(u64),
    )));
    try lc_writer.writeStruct(macho.dylinker_command{
        .cmd = .LOAD_DYLINKER,
        .cmdsize = cmdsize,
        .name = @sizeOf(macho.dylinker_command),
    });
    try lc_writer.writeAll(mem.sliceTo(default_dyld_path, 0));
    const padding = cmdsize - @sizeOf(macho.dylinker_command) - name_len;
    if (padding > 0) {
        try lc_writer.writeByteNTimes(0, padding);
    }
}

const WriteDylibLCCtx = struct {
    cmd: macho.LC,
    name: []const u8,
    timestamp: u32 = 2,
    current_version: u32 = 0x10000,
    compatibility_version: u32 = 0x10000,
};

fn writeDylibLC(ctx: WriteDylibLCCtx, lc_writer: anytype) !void {
    const name_len = ctx.name.len + 1;
    const cmdsize = @as(u32, @intCast(mem.alignForward(
        u64,
        @sizeOf(macho.dylib_command) + name_len,
        @sizeOf(u64),
    )));
    try lc_writer.writeStruct(macho.dylib_command{
        .cmd = ctx.cmd,
        .cmdsize = cmdsize,
        .dylib = .{
            .name = @sizeOf(macho.dylib_command),
            .timestamp = ctx.timestamp,
            .current_version = ctx.current_version,
            .compatibility_version = ctx.compatibility_version,
        },
    });
    try lc_writer.writeAll(ctx.name);
    try lc_writer.writeByte(0);
    const padding = cmdsize - @sizeOf(macho.dylib_command) - name_len;
    if (padding > 0) {
        try lc_writer.writeByteNTimes(0, padding);
    }
}

pub fn writeDylibIdLC(options: *const Options, lc_writer: anytype) !void {
    assert(options.output_mode == .lib);
    const emit = options.emit;
    const install_name = options.install_name orelse emit.sub_path;
    const curr = options.current_version orelse std.SemanticVersion{
        .major = 1,
        .minor = 0,
        .patch = 0,
    };
    const compat = options.compatibility_version orelse std.SemanticVersion{
        .major = 1,
        .minor = 0,
        .patch = 0,
    };
    try writeDylibLC(.{
        .cmd = .ID_DYLIB,
        .name = install_name,
        .current_version = @as(u32, @intCast(curr.major << 16 | curr.minor << 8 | curr.patch)),
        .compatibility_version = @as(u32, @intCast(compat.major << 16 | compat.minor << 8 | compat.patch)),
    }, lc_writer);
}

const RpathIterator = struct {
    buffer: []const []const u8,
    table: std.StringHashMap(void),
    count: usize = 0,

    fn init(gpa: Allocator, rpaths: []const []const u8) RpathIterator {
        return .{ .buffer = rpaths, .table = std.StringHashMap(void).init(gpa) };
    }

    fn deinit(it: *RpathIterator) void {
        it.table.deinit();
    }

    fn next(it: *RpathIterator) !?[]const u8 {
        while (true) {
            if (it.count >= it.buffer.len) return null;
            const rpath = it.buffer[it.count];
            it.count += 1;
            const gop = try it.table.getOrPut(rpath);
            if (gop.found_existing) continue;
            return rpath;
        }
    }
};

pub fn writeRpathLCs(gpa: Allocator, options: *const Options, lc_writer: anytype) !void {
    var it = RpathIterator.init(gpa, options.rpath_list);
    defer it.deinit();

    while (try it.next()) |rpath| {
        const rpath_len = rpath.len + 1;
        const cmdsize = @as(u32, @intCast(mem.alignForward(
            u64,
            @sizeOf(macho.rpath_command) + rpath_len,
            @sizeOf(u64),
        )));
        try lc_writer.writeStruct(macho.rpath_command{
            .cmdsize = cmdsize,
            .path = @sizeOf(macho.rpath_command),
        });
        try lc_writer.writeAll(rpath);
        try lc_writer.writeByte(0);
        const padding = cmdsize - @sizeOf(macho.rpath_command) - rpath_len;
        if (padding > 0) {
            try lc_writer.writeByteNTimes(0, padding);
        }
    }
}

pub fn writeBuildVersionLC(platform: Options.Platform, lc_writer: anytype) !void {
    const cmdsize = @sizeOf(macho.build_version_command) + @sizeOf(macho.build_tool_version);
    const platform_version = blk: {
        const ver = platform.min_version;
        const platform_version = @as(u32, @intCast(ver.major << 16 | ver.minor << 8));
        break :blk platform_version;
    };
    const sdk_version = blk: {
        const ver = platform.sdk_version;
        const sdk_version = @as(u32, @intCast(ver.major << 16 | ver.minor << 8));
        break :blk sdk_version;
    };
    try lc_writer.writeStruct(macho.build_version_command{
        .cmdsize = cmdsize,
        .platform = platform.platform,
        .minos = platform_version,
        .sdk = sdk_version,
        .ntools = 1,
    });
    try lc_writer.writeAll(mem.asBytes(&macho.build_tool_version{
        .tool = @as(macho.TOOL, @enumFromInt(0x6)),
        .version = 0x0,
    }));
}

pub fn writeLoadDylibLCs(dylibs: []const Dylib, referenced: []u16, lc_writer: anytype) !void {
    for (referenced) |index| {
        const dylib = dylibs[index];
        const dylib_id = dylib.id orelse unreachable;
        try writeDylibLC(.{
            .cmd = if (dylib.weak) .LOAD_WEAK_DYLIB else .LOAD_DYLIB,
            .name = dylib_id.name,
            .timestamp = dylib_id.timestamp,
            .current_version = dylib_id.current_version,
            .compatibility_version = dylib_id.compatibility_version,
        }, lc_writer);
    }
}
