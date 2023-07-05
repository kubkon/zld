pub fn addMachOTests(b: *Build, comp: *Compile) *Step {
    const macho_step = b.step("test-macho", "Run MachO tests");
    macho_step.dependOn(&comp.step);

    if (builtin.target.ofmt != .macho) return macho_step;

    const sdk_path = if (builtin.target.isDarwin())
        std.zig.system.darwin.getDarwinSDK(b.allocator, builtin.target)
    else
        null;

    const zld = FileSourceWithDir.fromFileSource(b, comp.getOutputSource(), "ld");

    const opts: Options = .{
        .comp = comp,
        .zld = zld,
        .sdk_path = sdk_path,
    };

    macho_step.dependOn(testDeadStrip(b, opts));
    macho_step.dependOn(testDeadStripDylibs(b, opts));
    macho_step.dependOn(testDylib(b, opts));
    macho_step.dependOn(testEmptyObject(b, opts));
    macho_step.dependOn(testEntryPoint(b, opts));
    macho_step.dependOn(testEntryPointArchive(b, opts));
    macho_step.dependOn(testEntryPointDylib(b, opts));
    macho_step.dependOn(testHeaderpad(b, opts));
    macho_step.dependOn(testHello(b, opts));
    macho_step.dependOn(testNeededFramework(b, opts));
    macho_step.dependOn(testNeededLibrary(b, opts));
    macho_step.dependOn(testPagezeroSize(b, opts));
    macho_step.dependOn(testSearchDylibsFirst(b, opts));
    macho_step.dependOn(testSearchPathsFirst(b, opts));
    macho_step.dependOn(testStackSize(b, opts));
    macho_step.dependOn(testUnwindInfo(b, opts));

    return macho_step;
}

const Options = struct {
    comp: *Compile,
    zld: FileSourceWithDir,
    sdk_path: ?std.zig.system.darwin.DarwinSDK,
};

fn testDeadStrip(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-dead-strip", "");

    const exe = cc(b, opts.zld, null);
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
        const exe = cc(b, opts.zld, null);
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
        const exe = cc(b, opts.zld, null);
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

    const dylib = cc(b, opts.zld, "liba.dylib");
    dylib.addArg("-shared");
    dylib.addSourcePath("test/macho/dylib/a.c", "a.c");

    const exe = cc(b, opts.zld, null);
    exe.addSourcePath("test/macho/dylib/main.c", "main.c");
    exe.addArg("-la");
    exe.addArg("-L");
    exe.addDirectorySource(dylib.saveOutput("liba.dylib").dir);

    const run = exe.run();
    run.expectStdOutEqual("Hello world");
    test_step.dependOn(&run.step);

    return test_step;
}

fn testEmptyObject(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-empty-object", "");

    const exe = cc(b, opts.zld, null);
    exe.addSourceBytes(
        \\#include <stdio.h>
        \\int main() {
        \\  printf("Hello!\n");
        \\  return 0;
        \\}
    , "main.c");
    exe.addSourceBytes("", "empty.c");

    const run = exe.run();
    run.expectStdOutEqual("Hello!\n");
    test_step.dependOn(&run.step);

    return test_step;
}

fn testEntryPoint(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-entry-point", "");

    const exe = cc(b, opts.zld, null);
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

    const obj = cc(b, opts.zld, "main.o");
    obj.addArg("-c");
    obj.addSimpleCMain();

    const lib = ar(b, "libmain.a");
    lib.addFileSource(obj.out);

    const exe = cc(b, opts.zld, null);
    exe.addArg("-lmain");
    exe.addArg("-L");
    exe.addDirectorySource(lib.saveOutput("libmain.a").dir);

    const run = exe.run();
    test_step.dependOn(&run.step);

    return test_step;
}

fn testEntryPointDylib(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-entry-point-dylib", "");

    const dylib = cc(b, opts.zld, "libbootstrap.dylib");
    dylib.addArgs(&.{ "-shared", "-Wl,-undefined,dynamic_lookup" });
    dylib.addSourcePath("test/macho/entry-point-dylib/bootstrap.c", "bootstrap.c");

    const exe = cc(b, opts.zld, null);
    exe.addSourcePath("test/macho/entry-point-dylib/main.c", "main.c");
    exe.addArgs(&.{ "-Wl,-e,_bootstrap", "-Wl,-u,_my_main", "-lbootstrap", "-L" });
    exe.addDirectorySource(dylib.saveOutput("libbootstrap.dylib").dir);

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
        const exe = cc(b, opts.zld, null);
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
        const exe = cc(b, opts.zld, null);
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
        const exe = cc(b, opts.zld, null);
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
        const exe = cc(b, opts.zld, null);
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

    const exe = cc(b, opts.zld, null);
    exe.addSourceBytes(
        \\#include <stdio.h>
        \\int main() {
        \\  printf("Hello, World!\n");
        \\  return 0;
        \\}
    , "main.c");

    const run = exe.run();
    run.expectStdOutEqual("Hello, World!\n");
    test_step.dependOn(&run.step);

    return test_step;
}

fn testNeededFramework(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-needed-framework", "");

    const exe = cc(b, opts.zld, null);
    exe.addArgs(&.{ "-Wl,-needed_framework,Cocoa", "-Wl,-dead_strip_dylibs" });
    exe.addSimpleCMain();

    const check = exe.check();
    check.checkStart("cmd LOAD_DYLIB");
    check.checkNext("name {*}Cocoa");
    test_step.dependOn(&check.step);

    const run = exe.run();
    test_step.dependOn(&run.step);

    return test_step;
}

fn testNeededLibrary(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-needed-library", "");

    const dylib = cc(b, opts.zld, "liba.dylib");
    dylib.addArg("-shared");
    dylib.addSourceBytes("int a = 42;", "a.c");

    const exe = cc(b, opts.zld, null);
    exe.addSimpleCMain();
    exe.addArgs(&.{ "-Wl,-needed-la", "-Wl,-dead_strip_dylibs", "-L" });
    exe.addDirectorySource(dylib.saveOutput("liba.dylib").dir);

    const check = exe.check();
    check.checkStart("cmd LOAD_DYLIB");
    check.checkNext("name {*}liba.dylib");
    test_step.dependOn(&check.step);

    const run = exe.run();
    test_step.dependOn(&run.step);

    return test_step;
}

fn testPagezeroSize(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-pagezero-size", "");

    {
        const exe = cc(b, opts.zld, null);
        exe.addArg("-Wl,-pagezero_size,0x4000");
        exe.addSimpleCMain();

        const check = exe.check();
        check.checkStart("LC 0");
        check.checkNext("segname __PAGEZERO");
        check.checkNext("vmaddr 0");
        check.checkNext("vmsize 4000");
        check.checkStart("segname __TEXT");
        check.checkNext("vmaddr 4000");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, opts.zld, null);
        exe.addArg("-Wl,-pagezero_size,0");
        exe.addSimpleCMain();

        const check = exe.check();
        check.checkStart("LC 0");
        check.checkNext("segname __TEXT");
        check.checkNext("vmaddr 0");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testSearchDylibsFirst(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-search-dylibs-first", "");

    const obj = cc(b, opts.zld, "a.o");
    obj.addArg("-c");
    obj.addSourcePath("test/macho/search-dylibs-first/a.c", "a.c");

    const lib = ar(b, "liba.a");
    lib.addFileSource(obj.out);

    const dylib = cc(b, opts.zld, "liba.dylib");
    dylib.addArg("-shared");
    dylib.addSourcePath("test/macho/search-dylibs-first/a.c", "a.c");

    const exe = cc(b, opts.zld, null);
    exe.addSourcePath("test/macho/search-dylibs-first/main.c", "main.c");
    exe.addArgs(&.{ "-Wl,-search_dylibs_first", "-la" });
    exe.addArg("-L");
    exe.addDirectorySource(lib.saveOutput("liba.a").dir);
    exe.addArg("-L");
    exe.addDirectorySource(dylib.saveOutput("liba.dylib").dir);

    const run = exe.run();
    run.expectStdOutEqual("Hello world");
    test_step.dependOn(&run.step);

    const check = exe.check();
    check.checkStart("cmd LOAD_DYLIB");
    check.checkNext("name {*}liba.dylib");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testSearchPathsFirst(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-search-paths-first", "");

    const obj = cc(b, opts.zld, "a.o");
    obj.addArg("-c");
    obj.addSourcePath("test/macho/search-paths-first/a.c", "a.c");

    const lib = ar(b, "liba.a");
    lib.addFileSource(obj.out);

    const dylib = cc(b, opts.zld, "liba.dylib");
    dylib.addArg("-shared");
    dylib.addSourcePath("test/macho/search-paths-first/a.c", "a.c");

    const exe = cc(b, opts.zld, null);
    exe.addSourcePath("test/macho/search-paths-first/main.c", "main.c");
    exe.addArgs(&.{ "-Wl,-search_paths_first", "-la" });
    exe.addArg("-L");
    exe.addDirectorySource(lib.saveOutput("liba.a").dir);
    exe.addArg("-L");
    exe.addDirectorySource(dylib.saveOutput("liba.dylib").dir);

    const run = exe.run();
    run.expectStdOutEqual("Hello world");
    test_step.dependOn(&run.step);

    const check = exe.check();
    check.checkStart("cmd LOAD_DYLIB");
    check.checkNotPresent("name {*}liba.dylib");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testStackSize(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-stack-size", "");

    const exe = cc(b, opts.zld, null);
    exe.addSimpleCMain();
    exe.addArg("-Wl,-stack_size,0x100000000");

    const run = exe.run();
    test_step.dependOn(&run.step);

    const check = exe.check();
    check.checkStart("cmd MAIN");
    check.checkNext("stacksize 100000000");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testUnwindInfo(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-unwind-info", "");

    const flags: []const []const u8 = &.{ "-std=c++17", "-Itest/macho/unwind-info", "-c" };

    const exe = ld(b, opts.zld, null, opts.sdk_path);
    exe.addArg("-lc++");

    {
        const obj = cc(b, opts.zld, "main.o");
        obj.addSourcePath("test/macho/unwind-info/main.cpp", "main.cpp");
        obj.addArgs(flags);
        exe.addFileSource(obj.saveOutput("main.o").file);
    }

    {
        const obj = cc(b, opts.zld, "simple_string.o");
        obj.addSourcePath("test/macho/unwind-info/simple_string.cpp", "simple_string.cpp");
        obj.addArgs(flags);
        exe.addFileSource(obj.saveOutput("simple_string.o").file);
    }

    {
        const obj = cc(b, opts.zld, "simple_string_owner.o");
        obj.addSourcePath("test/macho/unwind-info/simple_string_owner.cpp", "simple_string_owner.cpp");
        obj.addArgs(flags);
        exe.addFileSource(obj.saveOutput("simple_string_owner.o").file);
    }

    const run = exe.run();
    run.expectStdOutEqual(
        \\Constructed: a
        \\Constructed: b
        \\About to destroy: b
        \\About to destroy: a
        \\Error: Not enough memory!
        \\
    );
    test_step.dependOn(&run.step);

    const check = exe.check();
    check.checkInSymtab();
    check.checkNext("{*} external ___gxx_personality_v0");
    test_step.dependOn(&check.step);

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

    fn saveOutput(sys_cmd: SysCmd, basename: []const u8) FileSourceWithDir {
        return FileSourceWithDir.fromFileSource(sys_cmd.cmd.step.owner, sys_cmd.out, basename);
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

const FileSourceWithDir = struct {
    dir: FileSource,
    file: FileSource,

    fn fromFileSource(b: *Build, in_file: FileSource, basename: []const u8) FileSourceWithDir {
        const wf = WriteFile.create(b);
        const dir = wf.getDirectorySource();
        const file = wf.addCopyFile(in_file, basename);
        return .{ .dir = dir, .file = file };
    }
};

fn cc(b: *Build, zld: FileSourceWithDir, name: ?[]const u8) SysCmd {
    const cmd = Run.create(b, "cc");
    cmd.addArgs(&.{ "cc", "-fno-lto" });
    cmd.addArg("-o");
    const out = cmd.addOutputFileArg(name orelse "a.out");
    cmd.addArg("-B");
    cmd.addDirectorySourceArg(zld.dir);
    return .{ .cmd = cmd, .out = out };
}

fn ar(b: *Build, name: []const u8) SysCmd {
    const cmd = Run.create(b, "ar");
    cmd.addArgs(&.{ "ar", "rcs" });
    const out = cmd.addOutputFileArg(name);
    return .{ .cmd = cmd, .out = out };
}

fn ld(b: *Build, zld: FileSourceWithDir, name: ?[]const u8, sdk_path: ?std.zig.system.darwin.DarwinSDK) SysCmd {
    const cmd = Run.create(b, "ld");
    cmd.addFileSourceArg(zld.file);
    cmd.addArg("-dynamic");
    cmd.addArg("-o");
    const out = cmd.addOutputFileArg(name orelse "a.out");
    cmd.addArgs(&.{ "-lSystem", "-lc" });
    if (sdk_path) |sdk| {
        cmd.addArgs(&.{ "-syslibroot", sdk.path });
    }
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
