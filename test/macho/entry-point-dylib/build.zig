const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const lib = b.addSystemCommand(&.{
        "cc",
        "-fno-lto",
        "-shared",
        "bootstrap.c",
        "-o",
        "libbootstrap.dylib",
        "-B../../../zig-out/bin/",
        "-Wl,-undefined,dynamic_lookup",
    });
    test_step.dependOn(&lib.step);

    const exe = b.addSystemCommand(&.{
        "cc",
        "-fno-lto",
        "main.c",
        "-lbootstrap",
        "-L.",
        "-B../../../zig-out/bin/",
        "-Wl,-e,_bootstrap",
        "-Wl,-u,_my_main",
    });
    exe.step.dependOn(&lib.step);
    test_step.dependOn(&exe.step);

    const check = std.Build.Step.CheckObject.create(b, .{ .path = b.pathFromRoot("a.out") }, .macho);
    check.checkStart("segname __TEXT");
    check.checkNext("vmaddr {text_vmaddr}");
    check.checkStart("sectname __stubs");
    check.checkNext("addr {stubs_vmaddr}");
    check.checkStart("cmd MAIN");
    check.checkNext("entryoff {entryoff}");
    check.checkComputeCompare("text_vmaddr entryoff +", .{
        .op = .eq,
        .value = .{ .variable = "stubs_vmaddr" }, // The entrypoint should be a synthetic stub
    });

    const run = b.addSystemCommand(&.{"./a.out"});
    run.has_side_effects = true;
    run.expectStdOutEqual("Hello!\n");
    run.step.dependOn(&exe.step);
    test_step.dependOn(&run.step);
}
