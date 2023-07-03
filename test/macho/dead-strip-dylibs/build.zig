const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    {
        const exe = b.addSystemCommand(&.{
            "cc",
            "-fno-lto",
            "main.c",
            "-framework",
            "Cocoa",
            "-B../../../zig-out/bin/",
            "-o",
            "a1.out",
        });
        test_step.dependOn(&exe.step);

        const check = std.Build.Step.CheckObject.create(b, .{ .path = b.pathFromRoot("a1.out") }, .macho);
        check.checkStart("cmd LOAD_DYLIB");
        check.checkNext("name {*}Cocoa");
        check.checkStart("cmd LOAD_DYLIB");
        check.checkNext("name {*}libobjc{*}.dylib");
        check.step.dependOn(&exe.step);
        test_step.dependOn(&check.step);

        const run = b.addSystemCommand(&.{"./a1.out"});
        run.has_side_effects = true;
        run.step.dependOn(&exe.step);
        test_step.dependOn(&run.step);
    }

    {
        const exe = b.addSystemCommand(&.{
            "cc",
            "-fno-lto",
            "main.c",
            "-Wl,-dead_strip_dylibs",
            "-framework",
            "Cocoa",
            "-B../../../zig-out/bin/",
            "-o",
            "a2.out",
        });
        test_step.dependOn(&exe.step);

        const run = b.addSystemCommand(&.{"./a2.out"});
        run.has_side_effects = true;
        run.expectExitCode(@as(u8, @bitCast(@as(i8, -2))));
        run.step.dependOn(&exe.step);
        test_step.dependOn(&run.step);
    }
}
