const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const exe = b.addSystemCommand(&.{
        "cc",
        "-fno-lto",
        "main.c",
        "-B../../../zig-out/bin/",
        "-Wl,-stack_size,0x100000000",
    });
    test_step.dependOn(&exe.step);

    const run = b.addSystemCommand(&.{"./a.out"});
    run.has_side_effects = true;
    run.step.dependOn(&exe.step);
    test_step.dependOn(&run.step);

    const check = std.Build.Step.CheckObject.create(b, .{ .path = b.pathFromRoot("a.out") }, .macho);
    check.checkStart("cmd MAIN");
    check.checkNext("stacksize 100000000");
    check.step.dependOn(&exe.step);
    test_step.dependOn(&check.step);
}
