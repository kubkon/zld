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
    addSourcePath(exe.run, "test/macho/dead-strip/main.c", "main.c");
    exe.run.addArg("-dead_strip");

    const run = exec(b, exe.out);
    run.expectStdOutEqual("Hello!\n");
    run.step.dependOn(&exe.run.step);
    test_step.dependOn(&run.step);

    const ch = check(b, exe.out);
    ch.checkInSymtab();
    ch.checkNotPresent("{*} (__TEXT,__text) external _iAmUnused");
    ch.step.dependOn(&exe.run.step);
    test_step.dependOn(&ch.step);

    return test_step;
}

fn testDeadStripDylibs(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-dead-strip-dylibs", "");

    {
        const exe = cc(b, opts.zld_path);
        addSourcePath(exe.run, "test/macho/dead-strip-dylibs/main.c", "main.c");
        exe.run.addArgs(&.{ "-framework", "Cocoa" });

        const ch = check(b, exe.out);
        ch.checkStart("cmd LOAD_DYLIB");
        ch.checkNext("name {*}Cocoa");
        ch.checkStart("cmd LOAD_DYLIB");
        ch.checkNext("name {*}libobjc{*}.dylib");
        ch.step.dependOn(&exe.run.step);
        test_step.dependOn(&ch.step);

        const run = exec(b, exe.out);
        run.step.dependOn(&exe.run.step);
        test_step.dependOn(&run.step);
    }

    {
        const exe = cc(b, opts.zld_path);
        addSourcePath(exe.run, "test/macho/dead-strip-dylibs/main.c", "main.c");
        exe.run.addArgs(&.{ "-framework", "Cocoa", "-Wl,-dead_strip_dylibs" });

        const run = exec(b, exe.out);
        run.expectExitCode(@as(u8, @bitCast(@as(i8, -2))));
        run.step.dependOn(&exe.run.step);
        test_step.dependOn(&run.step);
    }

    return test_step;
}

fn testDylib(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-dylib", "");

    const dylib = cc(b, opts.zld_path);
    dylib.run.addArg("-shared");
    addSourcePath(dylib.run, "test/macho/dylib/a.c", "a.c");

    const dylib_fs = WriteFile.create(b);
    _ = dylib_fs.addCopyFile(dylib.out, "liba.dylib");

    const exe = cc(b, opts.zld_path);
    addSourcePath(exe.run, "test/macho/dylib/main.c", "main.c");
    exe.run.addArg("-la");
    exe.run.addArg("-L");
    exe.run.addDirectorySourceArg(dylib_fs.getDirectorySource());

    const run = exec(b, exe.out);
    run.expectStdOutEqual("Hello world");
    run.step.dependOn(&exe.run.step);
    test_step.dependOn(&run.step);

    return test_step;
}

fn testEmptyObject(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-empty-object", "");

    const exe = cc(b, opts.zld_path);
    addSourcePath(exe.run, "test/macho/empty-object/main.c", "main.c");
    addSourceBytes(exe.run, "", "empty.c");

    const run = exec(b, exe.out);
    run.expectStdOutEqual("Hello!\n");
    run.step.dependOn(&exe.run.step);
    test_step.dependOn(&run.step);

    return test_step;
}

fn testEntryPoint(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-entry-point", "");

    const exe = cc(b, opts.zld_path);
    addSourcePath(exe.run, "test/macho/entry-point/main.c", "main.c");
    exe.run.addArg("-Wl,-e,_non_main");

    const run = exec(b, exe.out);
    run.expectStdOutEqual("42");
    run.step.dependOn(&exe.run.step);
    test_step.dependOn(&run.step);

    const ch = check(b, exe.out);
    ch.checkStart("segname __TEXT");
    ch.checkNext("vmaddr {vmaddr}");
    ch.checkStart("cmd MAIN");
    ch.checkNext("entryoff {entryoff}");
    ch.checkInSymtab();
    ch.checkNext("{n_value} (__TEXT,__text) external _non_main");
    ch.checkComputeCompare("vmaddr entryoff +", .{ .op = .eq, .value = .{ .variable = "n_value" } });
    ch.step.dependOn(&exe.run.step);
    test_step.dependOn(&ch.step);

    return test_step;
}

fn testEntryPointArchive(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-entry-point-archive", "");

    const obj = cc(b, opts.zld_path);
    obj.run.addArg("-c");
    addSourcePath(obj.run, "test/macho/entry-point-archive/main.c", "main.c");

    const lib = ar(b, "libmain.a");
    lib.run.addFileSourceArg(obj.out);

    const lib_fs = WriteFile.create(b);
    _ = lib_fs.addCopyFile(lib.out, "libmain.a");

    const exe = cc(b, opts.zld_path);
    exe.run.addArg("-lmain");
    exe.run.addArg("-L");
    exe.run.addDirectorySourceArg(lib_fs.getDirectorySource());

    const run = exec(b, exe.out);
    // run.expectExitCode(1);
    run.step.dependOn(&exe.run.step);
    test_step.dependOn(&run.step);

    return test_step;
}

const SysCmd = struct {
    run: *Run,
    out: FileSource,
};

fn cc(b: *Build, zld_path: FileSource) SysCmd {
    const run = Run.create(b, "cc");
    run.addArgs(&.{ "cc", "-fno-lto" });
    run.addArg("-o");
    const out = run.addOutputFileArg("a.out");
    run.addArg("-B");
    run.addDirectorySourceArg(zld_path);
    return .{ .run = run, .out = out };
}

fn addSourcePath(run: *Run, path: []const u8, basename: []const u8) void {
    const b = run.step.owner;
    const wf = WriteFile.create(b);
    const file = wf.addCopyFile(.{ .path = path }, basename);
    run.addFileSourceArg(file);
}

fn addSourceBytes(run: *Run, bytes: []const u8, basename: []const u8) void {
    const b = run.step.owner;
    const wf = WriteFile.create(b);
    const file = wf.add(basename, bytes);
    run.addFileSourceArg(file);
}

fn ar(b: *Build, name: []const u8) SysCmd {
    const run = Run.create(b, "ar");
    run.addArgs(&.{ "ar", "rcs" });
    const out = run.addOutputFileArg(name);
    return .{ .run = run, .out = out };
}

fn exec(b: *Build, out: FileSource) *Run {
    const run = Run.create(b, "exec");
    run.addFileSourceArg(out);
    return run;
}

fn check(b: *Build, out: FileSource) *CheckObject {
    return CheckObject.create(b, out, .macho);
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
