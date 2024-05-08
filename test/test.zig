pub fn addTests(b: *Build, comp: *Compile, build_opts: struct {
    system_compiler: ?SystemCompiler,
    has_static: bool,
    has_zig: bool,
    is_musl: bool,
    has_objc_msgsend_stubs: bool,
}) *Step {
    const test_step = b.step("test-system-tools", "Run all system tools tests");
    test_step.dependOn(&comp.step);

    const system_compiler: SystemCompiler = build_opts.system_compiler orelse
        switch (builtin.target.os.tag) {
        .macos => .clang,
        .linux => .gcc,
        else => .gcc,
    };
    const cc_override: ?[]const u8 = std.process.getEnvVarOwned(b.allocator, "CC") catch |e| switch (e) {
        error.EnvironmentVariableNotFound => null,
        error.InvalidWtf8 => @panic("InvalidWtf8"),
        error.OutOfMemory => @panic("OOM"),
    };
    const zld = WriteFile.create(b).addCopyFile(comp.getEmittedBin(), "ld");
    const opts: Options = .{
        .zld = zld,
        .system_compiler = system_compiler,
        .has_static = build_opts.has_static,
        .has_zig = build_opts.has_zig,
        .has_objc_msgsend_stubs = build_opts.has_objc_msgsend_stubs,
        .is_musl = build_opts.is_musl,
        .cc_override = cc_override,
    };

    test_step.dependOn(macho.addMachOTests(b, opts));
    test_step.dependOn(elf.addElfTests(b, opts));
    test_step.dependOn(coff.addCoffTests(b, opts));

    return test_step;
}

pub const SystemCompiler = enum {
    gcc,
    clang,
};

pub const Options = struct {
    zld: LazyPath,
    system_compiler: SystemCompiler,
    has_static: bool = false,
    has_zig: bool = false,
    has_objc_msgsend_stubs: bool = false,
    is_musl: bool = false,
    cc_override: ?[]const u8 = null,
};

/// A system command that tracks the command itself via `cmd` Step.Run and output file
/// via `out` LazyPath.
pub const SysCmd = struct {
    cmd: *Run,
    out: LazyPath,

    pub fn addArg(sys_cmd: SysCmd, arg: []const u8) void {
        sys_cmd.cmd.addArg(arg);
    }

    pub fn addArgs(sys_cmd: SysCmd, args: []const []const u8) void {
        sys_cmd.cmd.addArgs(args);
    }

    pub fn addFileSource(sys_cmd: SysCmd, file: LazyPath) void {
        sys_cmd.cmd.addFileArg(file);
    }

    pub fn addPrefixedFileSource(sys_cmd: SysCmd, prefix: []const u8, file: LazyPath) void {
        sys_cmd.cmd.addPrefixedFileArg(prefix, file);
    }

    pub fn addDirectorySource(sys_cmd: SysCmd, dir: LazyPath) void {
        sys_cmd.cmd.addDirectorySourceArg(dir);
    }

    pub fn addPrefixedDirectorySource(sys_cmd: SysCmd, prefix: []const u8, dir: LazyPath) void {
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

    pub inline fn addObjCSource(sys_cmd: SysCmd, bytes: []const u8) void {
        return sys_cmd.addSourceBytes(bytes, .objc);
    }

    pub inline fn addObjCppSource(sys_cmd: SysCmd, bytes: []const u8) void {
        return sys_cmd.addSourceBytes(bytes, .objcpp);
    }

    pub const FileType = enum {
        c,
        cpp,
        @"asm",
        zig,
        objc,
        objcpp,
    };

    pub fn addSourceBytes(sys_cmd: SysCmd, bytes: []const u8, @"type": FileType) void {
        const b = sys_cmd.cmd.step.owner;
        const wf = WriteFile.create(b);
        const file = wf.add(switch (@"type") {
            .c => "a.c",
            .cpp => "a.cpp",
            .@"asm" => "a.s",
            .zig => "a.zig",
            .objc => "a.m",
            .objcpp => "a.mm",
        }, bytes);
        sys_cmd.cmd.addFileArg(file);
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

    pub inline fn getFile(sys_cmd: SysCmd) LazyPath {
        return sys_cmd.out;
    }

    pub inline fn getDir(sys_cmd: SysCmd) LazyPath {
        return sys_cmd.out.dirname();
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
        r.addFileArg(sys_cmd.out);
        r.step.dependOn(&sys_cmd.cmd.step);
        return .{ .run = r };
    }
};

pub const RunSysCmd = struct {
    run: *Run,

    pub inline fn expectHelloWorld(rsc: RunSysCmd) void {
        switch (builtin.target.os.tag) {
            .windows => rsc.run.expectStdOutEqual("Hello world!\r\n"),
            else => rsc.run.expectStdOutEqual("Hello world!\n"),
        }
    }

    pub inline fn expectStdOutEqual(rsc: RunSysCmd, exp: []const u8) void {
        rsc.run.expectStdOutEqual(exp);
    }

    pub fn expectStdOutFuzzy(rsc: RunSysCmd, exp: []const u8) void {
        rsc.run.addCheck(.{
            .expect_stdout_match = rsc.run.step.owner.dupe(exp),
        });
    }

    pub inline fn expectStdErrEqual(rsc: RunSysCmd, exp: []const u8) void {
        rsc.run.expectStdErrEqual(exp);
    }

    pub fn expectStdErrFuzzy(rsc: RunSysCmd, exp: []const u8) void {
        rsc.run.addCheck(.{
            .expect_stderr_match = rsc.run.step.owner.dupe(exp),
        });
    }

    pub fn expectExitCode(rsc: RunSysCmd, code: u8) void {
        rsc.run.expectExitCode(code);
    }

    pub inline fn step(rsc: RunSysCmd) *Step {
        return &rsc.run.step;
    }
};

pub fn saveBytesToFile(b: *Build, name: []const u8, bytes: []const u8) LazyPath {
    const wf = WriteFile.create(b);
    return wf.add(name, bytes);
}

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

pub fn skipTestStep(test_step: *Step) *Step {
    const skip = SkipTestStep.create(test_step.owner);
    test_step.dependOn(&skip.step);
    return test_step;
}

const std = @import("std");
const builtin = @import("builtin");
const coff = @import("coff.zig");
const elf = @import("elf.zig");
const macho = @import("macho.zig");

const Build = std.Build;
const CheckObject = Step.CheckObject;
const Compile = Step.Compile;
const LazyPath = Build.LazyPath;
const Run = Step.Run;
const Step = Build.Step;
const WriteFile = Step.WriteFile;
