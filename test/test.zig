pub fn addTests(b: *Build, comp: *Compile) *Step {
    const test_step = b.step("test-system-tools", "Run all system tools tests");
    test_step.dependOn(&comp.step);

    const zld = FileSourceWithDir.fromFileSource(b, comp.getOutputSource(), "ld");
    const sdk_path = if (builtin.target.isDarwin())
        std.zig.system.darwin.getDarwinSDK(b.allocator, builtin.target)
    else
        null;
    const opts: Options = .{
        .zld = zld,
        .sdk_path = sdk_path,
    };

    test_step.dependOn(macho.addMachOTests(b, opts));

    return test_step;
}

pub const Options = struct {
    zld: FileSourceWithDir,
    sdk_path: ?std.zig.system.darwin.DarwinSDK = null,
};

/// A system command that tracks the command itself via `cmd` Step.Run and output file
/// via `out` FileSource.
pub const SysCmd = struct {
    cmd: *Run,
    out: FileSource,

    pub fn addArg(sys_cmd: SysCmd, arg: []const u8) void {
        sys_cmd.cmd.addArg(arg);
    }

    pub fn addArgs(sys_cmd: SysCmd, args: []const []const u8) void {
        sys_cmd.cmd.addArgs(args);
    }

    pub fn addFileSource(sys_cmd: SysCmd, file: FileSource) void {
        sys_cmd.cmd.addFileSourceArg(file);
    }

    pub fn addDirectorySource(sys_cmd: SysCmd, dir: FileSource) void {
        sys_cmd.cmd.addDirectorySourceArg(dir);
    }

    pub fn addSourcePath(sys_cmd: SysCmd, path: []const u8, basename: []const u8) void {
        const b = sys_cmd.cmd.step.owner;
        const wf = WriteFile.create(b);
        const file = wf.addCopyFile(.{ .path = path }, basename);
        sys_cmd.cmd.addFileSourceArg(file);
    }

    pub fn addSourceBytes(sys_cmd: SysCmd, bytes: []const u8, basename: []const u8) void {
        const b = sys_cmd.cmd.step.owner;
        const wf = WriteFile.create(b);
        const file = wf.add(basename, bytes);
        sys_cmd.cmd.addFileSourceArg(file);
    }

    pub fn addSimpleCMain(sys_cmd: SysCmd) void {
        const main =
            \\int main(int argc, char* argv[]) {
            \\  return 0;
            \\}
        ;
        sys_cmd.addSourceBytes(main, "main.c");
    }

    pub fn saveOutputAs(sys_cmd: SysCmd, basename: []const u8) FileSourceWithDir {
        return FileSourceWithDir.fromFileSource(sys_cmd.cmd.step.owner, sys_cmd.out, basename);
    }

    pub fn check(sys_cmd: SysCmd) *CheckObject {
        const b = sys_cmd.cmd.step.owner;
        const ch = CheckObject.create(b, sys_cmd.out, .macho);
        ch.step.dependOn(&sys_cmd.cmd.step);
        return ch;
    }

    pub fn run(sys_cmd: SysCmd) *Run {
        const b = sys_cmd.cmd.step.owner;
        const r = Run.create(b, "exec");
        r.addFileSourceArg(sys_cmd.out);
        r.step.dependOn(&sys_cmd.cmd.step);
        return r;
    }
};

/// When going over different linking scenarios, we usually want to save a file
/// at a particular location however we do not specify the path to file explicitly
/// on the linker line. Instead, we specify its basename like `-la` and provide
/// the search directory with a matching companion flag `-L.`.
/// This abstraction tie the full path of a file with its immediate directory to make
/// the above scenario possible.
pub const FileSourceWithDir = struct {
    dir: FileSource,
    file: FileSource,

    pub fn fromFileSource(b: *Build, in_file: FileSource, basename: []const u8) FileSourceWithDir {
        const wf = WriteFile.create(b);
        const dir = wf.getDirectorySource();
        const file = wf.addCopyFile(in_file, basename);
        return .{ .dir = dir, .file = file };
    }

    pub fn fromBytes(b: *Build, bytes: []const u8, basename: []const u8) FileSourceWithDir {
        const wf = WriteFile.create(b);
        const dir = wf.getDirectorySource();
        const file = wf.add(basename, bytes);
        return .{ .dir = dir, .file = file };
    }
};

pub fn cc(b: *Build, name: ?[]const u8, opts: Options) SysCmd {
    const cmd = Run.create(b, "cc");
    cmd.addArgs(&.{ "cc", "-fno-lto" });
    cmd.addArg("-o");
    const out = cmd.addOutputFileArg(name orelse "a.out");
    cmd.addArg("-B");
    cmd.addDirectorySourceArg(opts.zld.dir);
    return .{ .cmd = cmd, .out = out };
}

pub fn ar(b: *Build, name: []const u8) SysCmd {
    const cmd = Run.create(b, "ar");
    cmd.addArgs(&.{ "ar", "rcs" });
    const out = cmd.addOutputFileArg(name);
    return .{ .cmd = cmd, .out = out };
}

pub fn ld(b: *Build, name: ?[]const u8, opts: Options) SysCmd {
    const cmd = Run.create(b, "ld");
    cmd.addFileSourceArg(opts.zld.file);
    cmd.addArg("-dynamic");
    cmd.addArg("-o");
    const out = cmd.addOutputFileArg(name orelse "a.out");
    cmd.addArgs(&.{ "-lSystem", "-lc" });
    if (opts.sdk_path) |sdk| {
        cmd.addArgs(&.{ "-syslibroot", sdk.path });
    }
    return .{ .cmd = cmd, .out = out };
}

const std = @import("std");
const builtin = @import("builtin");
const elf = @import("elf.zig");
const macho = @import("macho.zig");

const Build = std.Build;
const CheckObject = Step.CheckObject;
const Compile = Step.Compile;
const FileSource = Build.FileSource;
const Run = Step.Run;
const Step = Build.Step;
const WriteFile = Step.WriteFile;
