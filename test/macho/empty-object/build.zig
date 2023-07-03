const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const exe = b.addSystemCommand(&.{
        "cc",
        "-fno-lto",
        "main.c",
        "empty.c",
        "-B../../../zig-out/bin/",
    });
    test_step.dependOn(&exe.step);

    const run = b.addSystemCommand(&.{"./a.out"});
    run.has_side_effects = true;
    run.expectStdOutEqual("Hello!\n");
    run.step.dependOn(&exe.step);
    test_step.dependOn(&run.step);
}
