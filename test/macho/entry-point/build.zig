const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const exe = b.addSystemCommand(&.{
        "cc",
        "-fno-lto",
        "main.c",
        "-B../../../zig-out/bin/",
        "-Wl,-e,_non_main",
    });
    test_step.dependOn(&exe.step);

    const run = b.addSystemCommand(&.{"./a.out"});
    run.has_side_effects = true;
    run.expectStdOutEqual("42");
    run.step.dependOn(&exe.step);
    test_step.dependOn(&run.step);

    const check = std.Build.Step.CheckObject.create(b, .{ .path = b.pathFromRoot("a.out") }, .macho);
    check.checkStart("segname __TEXT");
    check.checkNext("vmaddr {vmaddr}");
    check.checkStart("cmd MAIN");
    check.checkNext("entryoff {entryoff}");
    check.checkInSymtab();
    check.checkNext("{n_value} (__TEXT,__text) external _non_main");
    check.checkComputeCompare("vmaddr entryoff +", .{ .op = .eq, .value = .{ .variable = "n_value" } });
    check.step.dependOn(&exe.step);
    test_step.dependOn(&check.step);
}
