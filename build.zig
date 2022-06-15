const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const enable_logging = b.option(bool, "log", "Whether to enable logging") orelse false;
    const is_qemu_enabled = b.option(bool, "enable-qemu", "Use QEMU to run cross compiled foreign architecture tests") orelse false;

    const lib = b.addStaticLibrary("zld", "src/Zld.zig");
    lib.setTarget(target);
    lib.setBuildMode(mode);
    lib.addPackagePath("dis_x86_64", "zig-dis-x86_64/src/dis_x86_64.zig");

    const exe = b.addExecutable("zld", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.addPackagePath("dis_x86_64", "zig-dis-x86_64/src/dis_x86_64.zig");

    const exe_opts = b.addOptions();
    exe.addOptions("build_options", exe_opts);
    exe_opts.addOption(bool, "enable_logging", enable_logging);

    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const tests = b.addTest("src/test.zig");
    tests.setBuildMode(mode);
    tests.addPackagePath("end_to_end_tests", "test/test.zig");
    tests.addPackagePath("dis_x86_64", "zig-dis-x86_64/src/dis_x86_64.zig");

    const test_opts = b.addOptions();
    tests.addOptions("build_options", test_opts);
    test_opts.addOption(bool, "enable_qemu", is_qemu_enabled);

    const test_step = b.step("test", "Run library and end-to-end tests");
    test_step.dependOn(&exe.step);
    test_step.dependOn(&tests.step);
}
