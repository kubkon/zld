const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const obj = b.addSystemCommand(&.{
        "cc",
        "-c",
        "main.c",
    });
    test_step.dependOn(&obj.step);

    const lib = b.addSystemCommand(&.{
        "ar",
        "rcs",
        "libmain.a",
        "main.o",
    });
    lib.step.dependOn(&obj.step);
    test_step.dependOn(&lib.step);

    const exe = b.addSystemCommand(&.{
        "cc",
        "-fno-lto",
        "-lmain",
        "-L.",
        "-B../../../zig-out/bin/",
    });
    exe.step.dependOn(&lib.step);
    test_step.dependOn(&exe.step);

    const run = b.addSystemCommand(&.{"./a.out"});
    run.has_side_effects = true;
    run.expectExitCode(0);
    run.step.dependOn(&exe.step);
    test_step.dependOn(&run.step);
}
