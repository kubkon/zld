const std = @import("std");
const assert = std.debug.assert;
const macho = std.macho;
const mem = std.mem;

pub const LoadCommandIterator = struct {
    ncmds: usize,
    buffer: []align(@alignOf(u64)) const u8,
    index: usize = 0,

    pub const LoadCommand = struct {
        hdr: macho.load_command,
        data: []const u8,

        pub fn cmd(lc: LoadCommand) macho.LC {
            return lc.hdr.cmd;
        }

        pub fn cmdsize(lc: LoadCommand) u32 {
            return lc.hdr.cmdsize;
        }

        pub fn cast(lc: LoadCommand, comptime Cmd: type) ?Cmd {
            if (lc.data.len < @sizeOf(Cmd)) return null;
            return @ptrCast(*const Cmd, @alignCast(@alignOf(Cmd), &lc.data[0])).*;
        }

        /// Asserts LoadCommand is of type macho.segment_command_64.
        pub fn getSections(lc: LoadCommand) []const macho.section_64 {
            const segment = lc.cast(macho.segment_command_64).?;
            const data = lc.data[@sizeOf(macho.segment_command_64)..];
            const sections = @ptrCast(
                [*]const macho.section_64,
                @alignCast(@alignOf(macho.section_64), &data[0]),
            )[0..segment.nsects];
            return sections;
        }

        /// Asserts LoadCommand is of type macho.dylib_command.
        pub fn getDylibPathName(lc: LoadCommand) []const u8 {
            const dylib = lc.cast(macho.dylib_command).?;
            const data = lc.data[dylib.dylib.name..];
            return mem.sliceTo(data, 0);
        }
    };

    pub fn next(it: *LoadCommandIterator) ?LoadCommand {
        if (it.index >= it.ncmds) return null;

        const hdr = @ptrCast(
            *const macho.load_command,
            @alignCast(@alignOf(macho.load_command), &it.buffer[0]),
        ).*;
        const cmd = LoadCommand{
            .hdr = hdr,
            .data = it.buffer[0..hdr.cmdsize],
        };

        it.buffer = it.buffer[hdr.cmdsize..];
        it.index += 1;

        return cmd;
    }
};
