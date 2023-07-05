pub fn addMachOTests(b: *Build, comp: *Compile) *Step {
    const macho_step = b.step("test-macho", "Run MachO tests");
    macho_step.dependOn(&comp.step);

    const zld_path = WriteFile.create(b);
    _ = zld_path.addCopyFile(comp.getOutputSource(), "ld");

    const opts: Options = .{
        .comp = comp,
        .zld_path = zld_path.getDirectorySource(),
    };

    if (builtin.target.ofmt == .macho) {
        macho_step.dependOn(testDeadStrip(b, opts));
        macho_step.dependOn(testDeadStripDylibs(b, opts));
        macho_step.dependOn(testDylib(b, opts));
        macho_step.dependOn(testEmptyObject(b, opts));
        macho_step.dependOn(testEntryPoint(b, opts));
        macho_step.dependOn(testEntryPointArchive(b, opts));
        macho_step.dependOn(testEntryPointDylib(b, opts));
        macho_step.dependOn(testHeaderpad(b, opts));
        macho_step.dependOn(testHello(b, opts));
    }

    return macho_step;
}

const Options = struct {
    comp: *Compile,
    zld_path: FileSource,
};

fn testDeadStrip(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-dead-strip", "");

    const exe = cc(b, opts.zld_path);
    exe.addSourcePath("test/macho/dead-strip/main.c", "main.c");
    exe.addArg("-dead_strip");

    const run = exe.run();
    run.expectStdOutEqual("Hello!\n");
    test_step.dependOn(&run.step);

    const check = exe.check();
    check.checkInSymtab();
    check.checkNotPresent("{*} (__TEXT,__text) external _iAmUnused");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testDeadStripDylibs(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-dead-strip-dylibs", "");

    {
        const exe = cc(b, opts.zld_path);
        exe.addSourcePath("test/macho/dead-strip-dylibs/main.c", "main.c");
        exe.addArgs(&.{ "-framework", "Cocoa" });

        const check = exe.check();
        check.checkStart("cmd LOAD_DYLIB");
        check.checkNext("name {*}Cocoa");
        check.checkStart("cmd LOAD_DYLIB");
        check.checkNext("name {*}libobjc{*}.dylib");
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(&run.step);
    }

    {
        const exe = cc(b, opts.zld_path);
        exe.addSourcePath("test/macho/dead-strip-dylibs/main.c", "main.c");
        exe.addArgs(&.{ "-framework", "Cocoa", "-Wl,-dead_strip_dylibs" });

        const run = exe.run();
        run.expectExitCode(@as(u8, @bitCast(@as(i8, -2))));
        test_step.dependOn(&run.step);
    }

    return test_step;
}

fn testDylib(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-dylib", "");

    const dylib = cc(b, opts.zld_path);
    dylib.addArg("-shared");
    dylib.addSourcePath("test/macho/dylib/a.c", "a.c");

    const dylib_fs = WriteFile.create(b);
    _ = dylib_fs.addCopyFile(dylib.out, "liba.dylib");

    const exe = cc(b, opts.zld_path);
    exe.addSourcePath("test/macho/dylib/main.c", "main.c");
    exe.addArg("-la");
    exe.addArg("-L");
    exe.addDirectorySource(dylib_fs.getDirectorySource());

    const run = exe.run();
    run.expectStdOutEqual("Hello world");
    test_step.dependOn(&run.step);

    return test_step;
}

fn testEmptyObject(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-empty-object", "");

    const exe = cc(b, opts.zld_path);
    exe.addSourcePath("test/macho/empty-object/main.c", "main.c");
    exe.addSourceBytes("", "empty.c");

    const run = exe.run();
    run.expectStdOutEqual("Hello!\n");
    test_step.dependOn(&run.step);

    return test_step;
}

fn testEntryPoint(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-entry-point", "");

    const exe = cc(b, opts.zld_path);
    exe.addSourcePath("test/macho/entry-point/main.c", "main.c");
    exe.addArg("-Wl,-e,_non_main");

    const run = exe.run();
    run.expectStdOutEqual("42");
    test_step.dependOn(&run.step);

    const check = exe.check();
    check.checkStart("segname __TEXT");
    check.checkNext("vmaddr {vmaddr}");
    check.checkStart("cmd MAIN");
    check.checkNext("entryoff {entryoff}");
    check.checkInSymtab();
    check.checkNext("{n_value} (__TEXT,__text) external _non_main");
    check.checkComputeCompare("vmaddr entryoff +", .{ .op = .eq, .value = .{ .variable = "n_value" } });
    test_step.dependOn(&check.step);

    return test_step;
}

fn testEntryPointArchive(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-entry-point-archive", "");

    const obj = cc(b, opts.zld_path);
    obj.addArg("-c");
    obj.addSourcePath("test/macho/entry-point-archive/main.c", "main.c");

    const lib = ar(b, "libmain.a");
    lib.addFileSource(obj.out);

    const lib_fs = WriteFile.create(b);
    _ = lib_fs.addCopyFile(lib.out, "libmain.a");

    const exe = cc(b, opts.zld_path);
    exe.addArg("-lmain");
    exe.addArg("-L");
    exe.addDirectorySource(lib_fs.getDirectorySource());

    const run = exe.run();
    test_step.dependOn(&run.step);

    return test_step;
}

fn testEntryPointDylib(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-entry-point-dylib", "");

    const dylib = cc(b, opts.zld_path);
    dylib.addArgs(&.{ "-shared", "-Wl,-undefined,dynamic_lookup" });
    dylib.addSourcePath("test/macho/entry-point-dylib/bootstrap.c", "bootstrap.c");

    const dylib_fs = WriteFile.create(b);
    _ = dylib_fs.addCopyFile(dylib.out, "libbootstrap.dylib");

    const exe = cc(b, opts.zld_path);
    exe.addSourcePath("test/macho/entry-point-dylib/main.c", "main.c");
    exe.addArgs(&.{ "-Wl,-e,_bootstrap", "-Wl,-u,_my_main", "-lbootstrap", "-L" });
    exe.addDirectorySource(dylib_fs.getDirectorySource());

    const check = exe.check();
    check.checkStart("segname __TEXT");
    check.checkNext("vmaddr {text_vmaddr}");
    check.checkStart("sectname __stubs");
    check.checkNext("addr {stubs_vmaddr}");
    check.checkStart("cmd MAIN");
    check.checkNext("entryoff {entryoff}");
    check.checkComputeCompare("text_vmaddr entryoff +", .{
        .op = .eq,
        .value = .{ .variable = "stubs_vmaddr" }, // The entrypoint should be a synthetic stub
    });
    test_step.dependOn(&check.step);

    const run = exe.run();
    run.expectStdOutEqual("Hello!\n");
    test_step.dependOn(&run.step);

    return test_step;
}

fn testHeaderpad(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-headerpad", "");

    const flags: []const []const u8 = &.{
        "-framework", "CoreFoundation",
        "-framework", "Foundation",
        "-framework", "Cocoa",
        "-framework", "CoreGraphics",
        "-framework", "CoreHaptics",
        "-framework", "CoreAudio",
        "-framework", "AVFoundation",
        "-framework", "CoreImage",
        "-framework", "CoreLocation",
        "-framework", "CoreML",
        "-framework", "CoreVideo",
        "-framework", "CoreText",
        "-framework", "CryptoKit",
        "-framework", "GameKit",
        "-framework", "SwiftUI",
        "-framework", "StoreKit",
        "-framework", "SpriteKit",
    };

    {
        const exe = cc(b, opts.zld_path);
        exe.addArgs(flags);
        exe.addArg("-Wl,-headerpad_max_install_names");
        exe.addSimpleCMain();

        const check = exe.check();
        check.checkStart("sectname __text");
        check.checkNext("offset {offset}");
        switch (builtin.cpu.arch) {
            .aarch64 => check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x4000 } }),
            .x86_64 => check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x1000 } }),
            else => unreachable,
        }
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(&run.step);
    }

    {
        const exe = cc(b, opts.zld_path);
        exe.addArgs(flags);
        exe.addArg("-Wl,-headerpad,0x10000");
        exe.addSimpleCMain();

        const check = exe.check();
        check.checkStart("sectname __text");
        check.checkNext("offset {offset}");
        check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x10000 } });
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(&run.step);
    }

    {
        const exe = cc(b, opts.zld_path);
        exe.addArgs(flags);
        exe.addArg("-Wl,-headerpad,0x10000");
        exe.addArg("-Wl,-headerpad_max_install_names");
        exe.addSimpleCMain();

        const check = exe.check();
        check.checkStart("sectname __text");
        check.checkNext("offset {offset}");
        check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x10000 } });
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(&run.step);
    }

    {
        const exe = cc(b, opts.zld_path);
        exe.addArgs(flags);
        exe.addArg("-Wl,-headerpad,0x1000");
        exe.addArg("-Wl,-headerpad_max_install_names");
        exe.addSimpleCMain();

        const check = exe.check();
        check.checkStart("sectname __text");
        check.checkNext("offset {offset}");
        switch (builtin.cpu.arch) {
            .aarch64 => check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x4000 } }),
            .x86_64 => check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x1000 } }),
            else => unreachable,
        }
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(&run.step);
    }

    return test_step;
}

fn testHello(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-hello", "");

    const exe = cc(b, opts.zld_path);
    exe.addSourceBytes(
        \\#include <stdio.h>
        \\int main() {
        \\  printf("Hello, World!\n");
        \\  return 0;
        \\}
    , "main.c");

    const run = exe.run();
    test_step.dependOn(&run.step);

    return test_step;
}

const SysCmd = struct {
    cmd: *Run,
    out: FileSource,

    fn addArg(sys_cmd: SysCmd, arg: []const u8) void {
        sys_cmd.cmd.addArg(arg);
    }

    fn addArgs(sys_cmd: SysCmd, args: []const []const u8) void {
        sys_cmd.cmd.addArgs(args);
    }

    fn addFileSource(sys_cmd: SysCmd, file: FileSource) void {
        sys_cmd.cmd.addFileSourceArg(file);
    }

    fn addDirectorySource(sys_cmd: SysCmd, dir: FileSource) void {
        sys_cmd.cmd.addDirectorySourceArg(dir);
    }

    fn addSourcePath(sys_cmd: SysCmd, path: []const u8, basename: []const u8) void {
        const b = sys_cmd.cmd.step.owner;
        const wf = WriteFile.create(b);
        const file = wf.addCopyFile(.{ .path = path }, basename);
        sys_cmd.cmd.addFileSourceArg(file);
    }

    fn addSourceBytes(sys_cmd: SysCmd, bytes: []const u8, basename: []const u8) void {
        const b = sys_cmd.cmd.step.owner;
        const wf = WriteFile.create(b);
        const file = wf.add(basename, bytes);
        sys_cmd.cmd.addFileSourceArg(file);
    }

    fn addSimpleCMain(sys_cmd: SysCmd) void {
        const main =
            \\int main(int argc, char* argv[]) {
            \\  return 0;
            \\}
        ;
        sys_cmd.addSourceBytes(main, "main.c");
    }

    fn check(sys_cmd: SysCmd) *CheckObject {
        const b = sys_cmd.cmd.step.owner;
        const ch = CheckObject.create(b, sys_cmd.out, .macho);
        ch.step.dependOn(&sys_cmd.cmd.step);
        return ch;
    }

    fn run(sys_cmd: SysCmd) *Run {
        const b = sys_cmd.cmd.step.owner;
        const r = Run.create(b, "exec");
        r.addFileSourceArg(sys_cmd.out);
        r.step.dependOn(&sys_cmd.cmd.step);
        return r;
    }
};

fn cc(b: *Build, zld_path: FileSource) SysCmd {
    const cmd = Run.create(b, "cc");
    cmd.addArgs(&.{ "cc", "-fno-lto" });
    cmd.addArg("-o");
    const out = cmd.addOutputFileArg("a.out");
    cmd.addArg("-B");
    cmd.addDirectorySourceArg(zld_path);
    return .{ .cmd = cmd, .out = out };
}

fn ar(b: *Build, name: []const u8) SysCmd {
    const cmd = Run.create(b, "ar");
    cmd.addArgs(&.{ "ar", "rcs" });
    const out = cmd.addOutputFileArg(name);
    return .{ .cmd = cmd, .out = out };
}

const std = @import("std");
const builtin = @import("builtin");

const Build = std.Build;
const CheckObject = Step.CheckObject;
const Compile = Step.Compile;
const FileSource = Build.FileSource;
const Run = Step.Run;
const Step = Build.Step;
const WriteFile = Step.WriteFile;
