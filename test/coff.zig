pub fn addCoffTests(b: *Build, options: common.Options) *Step {
    const coff_step = b.step("test-coff", "Run COFF tests");

    if (builtin.target.ofmt != .coff) return skipTestStep(coff_step);

    const opts = Options{
        .zld = options.zld,
    };

    coff_step.dependOn(testHelloDynamic(b, opts));

    return coff_step;
}

fn testHelloDynamic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-coff-hello-dynamic", "");

    const obj = cl(b, "main.obj", opts);
    obj.addHelloWorldMain();

    const exe = ld(b, "main.exe", opts);
    exe.addArg("/machine:x64"); // TODO
    exe.addFileSource(obj.getFile());

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    return test_step;
}

fn cl(b: *Build, name: []const u8, opts: Options) SysCmd {
    _ = opts;
    const cmd = Run.create(b, "cl");
    cmd.addArgs(&.{ "cl", "/nologo", "/c" });
    const out = cmd.addPrefixedOutputFileArg("/Fo:", name);
    return .{ .cmd = cmd, .out = out };
}

fn ld(b: *Build, name: []const u8, opts: Options) SysCmd {
    const cmd = Run.create(b, "ld");
    cmd.addFileArg(opts.zld);
    const out = cmd.addPrefixedOutputFileArg("/out:", name);
    return .{ .cmd = cmd, .out = out };
}

const Options = struct {
    zld: LazyPath,
};

const std = @import("std");
const builtin = @import("builtin");
const common = @import("test.zig");
const skipTestStep = common.skipTestStep;

const Build = std.Build;
const Compile = Step.Compile;
const LazyPath = Build.LazyPath;
const Run = Step.Run;
const Step = Build.Step;
const SysCmd = common.SysCmd;
const WriteFile = Step.WriteFile;
