const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const lib = b.addSystemCommand(&.{
        "cc",
        "-fno-lto",
        "-shared",
        "a.c",
        "-o",
        "liba.dylib",
        "-B../../../zig-out/bin/",
    });
    test_step.dependOn(&lib.step);

    const exe = b.addSystemCommand(&.{
        "cc",                     "-fno-lto",
        "main.c",                 "-L.",
        "-Wl,-needed-la",         "-B../../../zig-out/bin/",
        "-Wl,-dead_strip_dylibs",
    });
    exe.step.dependOn(&lib.step);
    test_step.dependOn(&exe.step);

    const check = std.Build.Step.CheckObject.create(b, .{ .path = b.pathFromRoot("a.out") }, .macho);
    check.checkStart("cmd LOAD_DYLIB");
    check.checkNext("name liba.dylib");
    check.step.dependOn(&exe.step);
    test_step.dependOn(&check.step);

    const run = b.addSystemCommand(&.{"./a.out"});
    run.has_side_effects = true;
    run.step.dependOn(&exe.step);
    test_step.dependOn(&run.step);
}
