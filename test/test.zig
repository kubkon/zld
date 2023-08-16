pub fn addTests(b: *Build, comp: *Compile, build_opts: struct {
    system_compiler: ?SystemCompiler,
    has_static: bool,
    has_zig: bool,
    is_musl: bool,
}) *Step {
    const test_step = b.step("test-system-tools", "Run all system tools tests");
    test_step.dependOn(&comp.step);

    const system_compiler: SystemCompiler = build_opts.system_compiler orelse blk: {
        if (builtin.target.isDarwin()) break :blk .clang;
        break :blk switch (builtin.target.os.tag) {
            .linux => .gcc,
            else => .gcc,
        };
    };
    const cc_override: ?[]const u8 = std.process.getEnvVarOwned(b.allocator, "CC") catch |e| switch (e) {
        error.EnvironmentVariableNotFound => null,
        error.InvalidUtf8 => @panic("InvalidUtf8"),
        error.OutOfMemory => @panic("OOM"),
    };

    const zld = FileSourceWithDir.fromFileSource(b, comp.getOutputSource(), "ld");
    const sdk_path = if (builtin.target.isDarwin())
        std.zig.system.darwin.getSdk(b.allocator, builtin.target)
    else
        null;

    const opts: Options = .{
        .zld = zld,
        .sdk_path = sdk_path,
        .system_compiler = system_compiler,
        .has_static = build_opts.has_static,
        .has_zig = build_opts.has_zig,
        .is_musl = build_opts.is_musl,
        .cc_override = cc_override,
    };

    test_step.dependOn(macho.addMachOTests(b, opts));
    test_step.dependOn(elf.addElfTests(b, opts));

    return test_step;
}

pub const SystemCompiler = enum {
    gcc,
    clang,
};

pub const Options = struct {
    zld: FileSourceWithDir,
    system_compiler: SystemCompiler,
    sdk_path: ?std.zig.system.darwin.Sdk = null,
    has_static: bool = false,
    has_zig: bool = false,
    is_musl: bool = false,
    cc_override: ?[]const u8 = null,
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

    pub fn addPrefixedFileSource(sys_cmd: SysCmd, prefix: []const u8, file: FileSource) void {
        sys_cmd.cmd.addPrefixedFileSourceArg(prefix, file);
    }

    pub fn addDirectorySource(sys_cmd: SysCmd, dir: FileSource) void {
        sys_cmd.cmd.addDirectorySourceArg(dir);
    }

    pub fn addPrefixedDirectorySource(sys_cmd: SysCmd, prefix: []const u8, dir: FileSource) void {
        sys_cmd.cmd.addPrefixedDirectorySourceArg(prefix, dir);
    }

    pub inline fn addCSource(sys_cmd: SysCmd, bytes: []const u8) void {
        return sys_cmd.addSourceBytes(bytes, .c);
    }

    pub inline fn addCppSource(sys_cmd: SysCmd, bytes: []const u8) void {
        return sys_cmd.addSourceBytes(bytes, .cpp);
    }

    pub inline fn addAsmSource(sys_cmd: SysCmd, bytes: []const u8) void {
        return sys_cmd.addSourceBytes(bytes ++ "\n", .@"asm");
    }

    pub inline fn addZigSource(sys_cmd: SysCmd, bytes: []const u8) void {
        return sys_cmd.addSourceBytes(bytes, .zig);
    }

    pub const FileType = enum {
        c,
        cpp,
        @"asm",
        zig,
    };

    pub fn addSourceBytes(sys_cmd: SysCmd, bytes: []const u8, @"type": FileType) void {
        const b = sys_cmd.cmd.step.owner;
        const wf = WriteFile.create(b);
        const file = wf.add(switch (@"type") {
            .c => "a.c",
            .cpp => "a.cpp",
            .@"asm" => "a.s",
            .zig => "a.zig",
        }, bytes);
        sys_cmd.cmd.addFileSourceArg(file);
    }

    pub inline fn addEmptyMain(sys_cmd: SysCmd) void {
        sys_cmd.addCSource(
            \\int main(int argc, char* argv[]) {
            \\  return 0;
            \\}
        );
    }

    pub inline fn addHelloWorldMain(sys_cmd: SysCmd) void {
        sys_cmd.addCSource(
            \\#include <stdio.h>
            \\int main(int argc, char* argv[]) {
            \\  printf("Hello world!\n");
            \\  return 0;
            \\}
        );
    }

    pub fn saveOutputAs(sys_cmd: SysCmd, basename: []const u8) FileSourceWithDir {
        return FileSourceWithDir.fromFileSource(sys_cmd.cmd.step.owner, sys_cmd.out, basename);
    }

    pub fn check(sys_cmd: SysCmd) *CheckObject {
        const b = sys_cmd.cmd.step.owner;
        const ch = CheckObject.create(b, sys_cmd.out, builtin.target.ofmt);
        ch.step.dependOn(&sys_cmd.cmd.step);
        return ch;
    }

    pub fn run(sys_cmd: SysCmd) RunSysCmd {
        const b = sys_cmd.cmd.step.owner;
        const r = Run.create(b, "exec");
        r.addFileSourceArg(sys_cmd.out);
        r.step.dependOn(&sys_cmd.cmd.step);
        return .{ .run = r };
    }
};

pub const RunSysCmd = struct {
    run: *Run,

    pub inline fn expectHelloWorld(rsc: RunSysCmd) void {
        rsc.run.expectStdOutEqual("Hello world!\n");
    }

    pub inline fn expectStdOutEqual(rsc: RunSysCmd, exp: []const u8) void {
        rsc.run.expectStdOutEqual(exp);
    }

    pub inline fn expectExitCode(rsc: RunSysCmd, code: u8) void {
        rsc.run.expectExitCode(code);
    }

    pub inline fn step(rsc: RunSysCmd) *Step {
        return &rsc.run.step;
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

pub const SkipTestStep = struct {
    pub const base_id = .custom;

    step: Step,
    builder: *Build,

    pub fn create(builder: *Build) *SkipTestStep {
        const self = builder.allocator.create(SkipTestStep) catch unreachable;
        self.* = SkipTestStep{
            .builder = builder,
            .step = Step.init(.{
                .id = .custom,
                .name = "test skipped",
                .owner = builder,
                .makeFn = make,
            }),
        };
        return self;
    }

    fn make(step: *Step, prog_node: *std.Progress.Node) anyerror!void {
        _ = step;
        _ = prog_node;
        return error.MakeSkipped;
    }
};

pub fn skipTestStep(test_step: *Step) void {
    const skip = SkipTestStep.create(test_step.owner);
    test_step.dependOn(&skip.step);
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
