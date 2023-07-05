pub fn addMachOTests(b: *Build, comp: *Compile) *Step {
    const macho_step = b.step("test-macho", "Run MachO tests");
    macho_step.dependOn(&comp.step);

    const zld_path = WriteFile.create(b);
    _ = zld_path.addCopyFile(comp.getOutputSource(), "ld");

    const opts: Options = .{
        .comp = comp,
        .test_step = macho_step,
        .zld_path = zld_path.getDirectorySource(),
    };

    if (builtin.target.ofmt == .macho) {
        testDeadStrip(b, opts);
    }

    return macho_step;
}

const Options = struct {
    comp: *Compile,
    test_step: *Step,
    zld_path: FileSource,
};

fn testDeadStrip(b: *Build, opts: Options) void {
    const prefix = "test/macho/dead-strip";
    const main_c = WriteFile.create(b).addCopyFile(.{ .path = b.pathJoin(&.{ prefix, "main.c" }) }, "main.c");

    const exe = Run.create(b, "cc");
    exe.addArgs(&.{
        "cc",
        "-fno-lto",
        "-dead_strip",
    });
    exe.addFileSourceArg(main_c);
    exe.addArg("-o");
    const a_out = exe.addOutputFileArg("a.out");
    exe.addArg("-B");
    exe.addDirectorySourceArg(opts.zld_path);

    const run = Run.create(b, "run");
    run.addFileSourceArg(a_out);
    run.expectStdOutEqual("Hello!\n");
    run.step.dependOn(&exe.step);
    opts.test_step.dependOn(&run.step);

    const check = CheckObject.create(b, a_out, .macho);
    check.checkInSymtab();
    check.checkNotPresent("{*} (__TEXT,__text) external _iAmUnused");
    check.step.dependOn(&exe.step);
    opts.test_step.dependOn(&check.step);
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
