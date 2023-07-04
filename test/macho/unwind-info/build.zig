const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const exe = b.addSystemCommand(&.{
        "cc",
        "-fno-lto",
        "main.cpp",
        "simple_string.cpp",
        "simple_string_owner.cpp",
        "-I.",
        "-lc++",
        "-std=c++17",
        "-B../../../zig-out/bin/",
    });
    test_step.dependOn(&exe.step);

    const run = b.addSystemCommand(&.{"./a.out"});
    run.has_side_effects = true;
    run.expectStdOutEqual(
        \\Constructed: a
        \\Constructed: b
        \\About to destroy: b
        \\About to destroy: a
        \\Error: Not enough memory!
        \\
    );
    run.step.dependOn(&exe.step);
    test_step.dependOn(&run.step);

    const check = std.Build.Step.CheckObject.create(b, .{ .path = b.pathFromRoot("a.out") }, .macho);
    check.checkInSymtab();
    check.checkNext("{*} external ___gxx_personality_v0");
    check.step.dependOn(&exe.step);
    test_step.dependOn(&check.step);
}
