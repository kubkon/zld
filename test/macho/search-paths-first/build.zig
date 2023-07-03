const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const obj = b.addSystemCommand(&.{ "cc", "-c", "a.c" });
    test_step.dependOn(&obj.step);

    const static_lib = b.addSystemCommand(&.{ "ar", "rcs", "liba.a", "a.o" });
    static_lib.step.dependOn(&obj.step);
    test_step.dependOn(&static_lib.step);

    const dyn_lib = b.addSystemCommand(&.{
        "../../../zig-out/bin/ld",
        "-dylib",
        "-dynamic",
        "a.o",
        "-o",
        "liba.dylib",
    });
    dyn_lib.step.dependOn(&obj.step);
    test_step.dependOn(&dyn_lib.step);

    const exe = b.addSystemCommand(&.{
        "cc",
        "-fno-lto",
        "main.c",
        "-la",
        "-L.",
        "-B../../../zig-out/bin/",
        "-Wl,-search_paths_first",
    });
    exe.step.dependOn(&static_lib.step);
    exe.step.dependOn(&dyn_lib.step);
    test_step.dependOn(&exe.step);

    const run = b.addSystemCommand(&.{"./a.out"});
    run.has_side_effects = true;
    run.step.dependOn(&exe.step);
    test_step.dependOn(&run.step);
}
