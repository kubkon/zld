const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    {
        const exe = b.addSystemCommand(&.{
            "cc",                               "-fno-lto",
            "main.c",                           "-framework",
            "CoreFoundation",                   "-framework",
            "Foundation",                       "-framework",
            "Cocoa",                            "-framework",
            "CoreGraphics",                     "-framework",
            "CoreHaptics",                      "-framework",
            "CoreAudio",                        "-framework",
            "AVFoundation",                     "-framework",
            "CoreImage",                        "-framework",
            "CoreLocation",                     "-framework",
            "CoreML",                           "-framework",
            "CoreVideo",                        "-framework",
            "CoreText",                         "-framework",
            "CryptoKit",                        "-framework",
            "GameKit",                          "-framework",
            "SwiftUI",                          "-framework",
            "StoreKit",                         "-framework",
            "SpriteKit",                        "-B../../../zig-out/bin/",
            "-Wl,-headerpad_max_install_names", "-o",
            "a1.out",
        });
        test_step.dependOn(&exe.step);

        const check = std.Build.Step.CheckObject.create(b, .{ .path = b.pathFromRoot("a1.out") }, .macho);
        check.checkStart("sectname __text");
        check.checkNext("offset {offset}");
        switch (builtin.cpu.arch) {
            .aarch64 => check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x4000 } }),
            .x86_64 => check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x1000 } }),
            else => unreachable,
        }
        check.step.dependOn(&exe.step);
        test_step.dependOn(&check.step);

        const run = b.addSystemCommand(&.{"./a1.out"});
        run.has_side_effects = true;
        run.step.dependOn(&exe.step);
        test_step.dependOn(&run.step);
    }

    {
        const exe = b.addSystemCommand(&.{
            "cc",                     "-fno-lto",
            "main.c",                 "-framework",
            "CoreFoundation",         "-framework",
            "Foundation",             "-framework",
            "Cocoa",                  "-framework",
            "CoreGraphics",           "-framework",
            "CoreHaptics",            "-framework",
            "CoreAudio",              "-framework",
            "AVFoundation",           "-framework",
            "CoreImage",              "-framework",
            "CoreLocation",           "-framework",
            "CoreML",                 "-framework",
            "CoreVideo",              "-framework",
            "CoreText",               "-framework",
            "CryptoKit",              "-framework",
            "GameKit",                "-framework",
            "SwiftUI",                "-framework",
            "StoreKit",               "-framework",
            "SpriteKit",              "-B../../../zig-out/bin/",
            "-Wl,-headerpad,0x10000", "-o",
            "a2.out",
        });
        test_step.dependOn(&exe.step);

        const check = std.Build.Step.CheckObject.create(b, .{ .path = b.pathFromRoot("a2.out") }, .macho);
        check.checkStart("sectname __text");
        check.checkNext("offset {offset}");
        check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x10000 } });
        check.step.dependOn(&exe.step);
        test_step.dependOn(&check.step);

        const run = b.addSystemCommand(&.{"./a2.out"});
        run.has_side_effects = true;
        run.step.dependOn(&exe.step);
        test_step.dependOn(&run.step);
    }

    {
        const exe = b.addSystemCommand(&.{
            "cc",                               "-fno-lto",
            "main.c",                           "-framework",
            "CoreFoundation",                   "-framework",
            "Foundation",                       "-framework",
            "Cocoa",                            "-framework",
            "CoreGraphics",                     "-framework",
            "CoreHaptics",                      "-framework",
            "CoreAudio",                        "-framework",
            "AVFoundation",                     "-framework",
            "CoreImage",                        "-framework",
            "CoreLocation",                     "-framework",
            "CoreML",                           "-framework",
            "CoreVideo",                        "-framework",
            "CoreText",                         "-framework",
            "CryptoKit",                        "-framework",
            "GameKit",                          "-framework",
            "SwiftUI",                          "-framework",
            "StoreKit",                         "-framework",
            "SpriteKit",                        "-B../../../zig-out/bin/",
            "-Wl,-headerpad_max_install_names", "-Wl,-headerpad,0x10000",
            "-o",                               "a3.out",
        });
        test_step.dependOn(&exe.step);

        const check = std.Build.Step.CheckObject.create(b, .{ .path = b.pathFromRoot("a3.out") }, .macho);
        check.checkStart("sectname __text");
        check.checkNext("offset {offset}");
        check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x10000 } });
        check.step.dependOn(&exe.step);
        test_step.dependOn(&check.step);

        const run = b.addSystemCommand(&.{"./a3.out"});
        run.has_side_effects = true;
        run.step.dependOn(&exe.step);
        test_step.dependOn(&run.step);
    }

    {
        const exe = b.addSystemCommand(&.{
            "cc",                               "-fno-lto",
            "main.c",                           "-framework",
            "CoreFoundation",                   "-framework",
            "Foundation",                       "-framework",
            "Cocoa",                            "-framework",
            "CoreGraphics",                     "-framework",
            "CoreHaptics",                      "-framework",
            "CoreAudio",                        "-framework",
            "AVFoundation",                     "-framework",
            "CoreImage",                        "-framework",
            "CoreLocation",                     "-framework",
            "CoreML",                           "-framework",
            "CoreVideo",                        "-framework",
            "CoreText",                         "-framework",
            "CryptoKit",                        "-framework",
            "GameKit",                          "-framework",
            "SwiftUI",                          "-framework",
            "StoreKit",                         "-framework",
            "SpriteKit",                        "-B../../../zig-out/bin/",
            "-Wl,-headerpad_max_install_names", "-Wl,-headerpad,0x1000",
            "-o",                               "a4.out",
        });
        test_step.dependOn(&exe.step);

        const check = std.Build.Step.CheckObject.create(b, .{ .path = b.pathFromRoot("a4.out") }, .macho);
        check.checkStart("sectname __text");
        check.checkNext("offset {offset}");
        switch (builtin.cpu.arch) {
            .aarch64 => check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x4000 } }),
            .x86_64 => check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x1000 } }),
            else => unreachable,
        }
        check.step.dependOn(&exe.step);
        test_step.dependOn(&check.step);

        const run = b.addSystemCommand(&.{"./a4.out"});
        run.has_side_effects = true;
        run.step.dependOn(&exe.step);
        test_step.dependOn(&run.step);
    }
}
