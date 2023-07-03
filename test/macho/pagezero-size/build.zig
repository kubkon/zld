const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    {
        const exe = b.addSystemCommand(&.{
            "cc",                        "-fno-lto",
            "main.c",                    "-B../../../zig-out/bin/",
            "-Wl,-pagezero_size,0x4000", "-o",
            "a1.out",
        });
        test_step.dependOn(&exe.step);

        const check = std.Build.Step.CheckObject.create(b, .{ .path = b.pathFromRoot("a1.out") }, .macho);
        check.checkStart("LC 0");
        check.checkNext("segname __PAGEZERO");
        check.checkNext("vmaddr 0");
        check.checkNext("vmsize 4000");
        check.checkStart("segname __TEXT");
        check.checkNext("vmaddr 4000");
        check.step.dependOn(&exe.step);
        test_step.dependOn(&check.step);
    }

    {
        const exe = b.addSystemCommand(&.{
            "cc",                   "-fno-lto",
            "main.c",               "-B../../../zig-out/bin/",
            "-Wl,-pagezero_size,0", "-o",
            "a2.out",
        });
        test_step.dependOn(&exe.step);

        const check = std.Build.Step.CheckObject.create(b, .{ .path = b.pathFromRoot("a2.out") }, .macho);
        check.checkStart("LC 0");
        check.checkNext("segname __TEXT");
        check.checkNext("vmaddr 0");
        check.step.dependOn(&exe.step);
        test_step.dependOn(&check.step);
    }
}
