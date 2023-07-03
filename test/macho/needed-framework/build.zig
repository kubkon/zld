const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const exe = b.addSystemCommand(&.{
        "cc",                      "-fno-lto",
        "main.c",                  "-Wl,-needed_framework,Cocoa",
        "-B../../../zig-out/bin/", "-Wl,-dead_strip_dylibs",
    });
    test_step.dependOn(&exe.step);

    const check = std.Build.Step.CheckObject.create(b, .{ .path = b.pathFromRoot("a.out") }, .macho);
    check.checkStart("cmd LOAD_DYLIB");
    check.checkNext("name {*}Cocoa");
    check.step.dependOn(&exe.step);
    test_step.dependOn(&check.step);

    const run = b.addSystemCommand(&.{"./a.out"});
    run.has_side_effects = true;
    run.step.dependOn(&exe.step);
    test_step.dependOn(&run.step);
}
