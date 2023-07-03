const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const exe_step = b.addSystemCommand(&.{
        "cc",
        "-fno-lto",
        "-dead_strip",
        "main.c",
        "-B../../../zig-out/bin/",
    });
    test_step.dependOn(&exe_step.step);

    const run_step = b.addSystemCommand(&.{"./a.out"});
    run_step.has_side_effects = true;
    run_step.expectStdOutEqual("Hello!\n");
    run_step.step.dependOn(&exe_step.step);
    test_step.dependOn(&run_step.step);

    const check_step = std.Build.Step.CheckObject.create(b, .{ .path = b.pathFromRoot("a.out") }, .macho);
    check_step.checkInSymtab();
    check_step.checkNotPresent("{*} (__TEXT,__text) external _iAmUnused");
    check_step.step.dependOn(&exe_step.step);
    test_step.dependOn(&check_step.step);
}
