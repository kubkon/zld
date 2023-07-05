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
    addSourceFile(exe.run, "test/macho/dead-strip", "main.c");
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
    const prefix = "test/macho/dead-strip-dylibs";

    {
        const exe = cc(b, opts.zld_path);
        addSourceFile(exe.run, prefix, "main.c");
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
        addSourceFile(exe.run, prefix, "main.c");
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
    const prefix = "test/macho/dylib";

    const dylib = cc(b, opts.zld_path);
    dylib.run.addArg("-shared");
    addSourceFile(dylib.run, prefix, "a.c");
    const dylib_fs = WriteFile.create(b);
    _ = dylib_fs.addCopyFile(dylib.out, "liba.dylib");

    const exe = cc(b, opts.zld_path);
    addSourceFile(exe.run, prefix, "main.c");
    exe.run.addArg("-la");
    exe.run.addArg("-L");
    exe.run.addDirectorySourceArg(dylib_fs.getDirectorySource());

    const run = exec(b, exe.out);
    run.expectStdOutEqual("Hello world");
    run.step.dependOn(&exe.run.step);
    test_step.dependOn(&run.step);

    return test_step;
}

fn cc(b: *Build, zld_path: FileSource) struct { run: *Run, out: FileSource } {
    const run = Run.create(b, "cc");
    run.addArgs(&.{ "cc", "-fno-lto" });
    run.addArg("-o");
    const out = run.addOutputFileArg("a.out");
    run.addArg("-B");
    run.addDirectorySourceArg(zld_path);
    return .{ .run = run, .out = out };
}

fn addSourceFile(run: *Run, prefix: []const u8, basename: []const u8) void {
    const b = run.step.owner;
    const wf = WriteFile.create(b);
    const file = wf.addCopyFile(.{ .path = b.pathJoin(&.{ prefix, basename }) }, basename);
    run.addFileSourceArg(file);
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
