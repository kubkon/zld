const std = @import("std");
const fs = std.fs;
const log = std.log;

const Allocator = std.mem.Allocator;

pub fn build(b: *std.Build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardOptimizeOption(.{});

    const enable_logging = b.option(bool, "log", "Whether to enable logging") orelse (mode == .Debug);
    const is_qemu_enabled = b.option(bool, "enable-qemu", "Use QEMU to run cross compiled foreign architecture tests") orelse false;
    const enable_tracy = b.option([]const u8, "tracy", "Enable Tracy integration. Supply path to Tracy source");

    const dis_x86_64 = b.addModule("dis_x86_64", .{
        .source_file = .{ .path = "zig-dis-x86_64/src/dis_x86_64.zig" },
    });

    const exe = b.addExecutable(.{
        .name = "zld",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = mode,
    });
    exe.addModule("dis_x86_64", dis_x86_64);
    exe.linkLibC();

    const exe_opts = b.addOptions();
    exe.addOptions("build_options", exe_opts);
    exe_opts.addOption(bool, "enable_logging", enable_logging);
    exe_opts.addOption(bool, "enable_tracy", enable_tracy != null);

    if (enable_tracy) |tracy_path| {
        const client_cpp = fs.path.join(
            b.allocator,
            &[_][]const u8{ tracy_path, "TracyClient.cpp" },
        ) catch unreachable;

        // On mingw, we need to opt into windows 7+ to get some features required by tracy.
        const tracy_c_flags: []const []const u8 = if (target.isWindows() and target.getAbi() == .gnu)
            &[_][]const u8{ "-DTRACY_ENABLE=1", "-fno-sanitize=undefined", "-D_WIN32_WINNT=0x601" }
        else
            &[_][]const u8{ "-DTRACY_ENABLE=1", "-fno-sanitize=undefined" };

        exe.addIncludePath(tracy_path);
        // TODO: upstream bug
        exe.addSystemIncludePath("/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include");
        exe.addCSourceFile(client_cpp, tracy_c_flags);
        exe.linkSystemLibraryName("c++");
        exe.strip = false;

        if (target.isWindows()) {
            exe.linkSystemLibrary("dbghelp");
            exe.linkSystemLibrary("ws2_32");
        }
    }
    const install = b.addInstallArtifact(exe);
    const symlinks = addSymlinks(b, install, &[_][]const u8{
        "ld.zld",
        "ld",
        "ld64.zld",
        "ld64",
        "wasm-zld",
    });
    symlinks.step.dependOn(&install.step);

    const tests = b.addTest(.{
        .root_source_file = .{ .path = "src/test.zig" },
        .optimize = mode,
    });
    tests.addModule("dis_x86_64", dis_x86_64);
    tests.main_pkg_path = "."; // set root directory as main package path for our tests

    const test_opts = b.addOptions();
    tests.addOptions("build_options", test_opts);
    test_opts.addOption(bool, "enable_qemu", is_qemu_enabled);
    test_opts.addOption(bool, "enable_logging", enable_logging);

    const test_step = b.step("test", "Run library and end-to-end tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
}

fn addSymlinks(
    builder: *std.Build.Builder,
    install: *std.Build.InstallArtifactStep,
    names: []const []const u8,
) *CreateSymlinksStep {
    const step = CreateSymlinksStep.create(builder, install, names);
    builder.getInstallStep().dependOn(&step.step);
    return step;
}

const CreateSymlinksStep = struct {
    pub const base_id = .custom;

    step: std.Build.Step,
    builder: *std.Build.Builder,
    install: *std.Build.InstallArtifactStep,
    targets: []const []const u8,

    pub fn create(
        builder: *std.Build.Builder,
        install: *std.Build.InstallArtifactStep,
        targets: []const []const u8,
    ) *CreateSymlinksStep {
        const self = builder.allocator.create(CreateSymlinksStep) catch unreachable;
        self.* = CreateSymlinksStep{
            .builder = builder,
            .step = std.Build.Step.init(.{
                .id = .custom,
                .name = builder.fmt("symlinks to {s}", .{install.artifact.name}),
                .owner = builder,
                .makeFn = make,
            }),
            .install = install,
            .targets = builder.dupeStrings(targets),
        };
        return self;
    }

    fn make(step: *std.Build.Step, prog_node: *std.Progress.Node) anyerror!void {
        const self = @fieldParentPtr(CreateSymlinksStep, "step", step);
        const install_path = self.install.artifact.getOutputSource().getPath(self.builder);
        const rel_source = fs.path.basename(install_path);

        var node = prog_node.start("creating symlinks", self.targets.len);
        node.activate();
        defer node.end();
        for (self.targets, 0..) |target, i| {
            const target_path = self.builder.getInstallPath(.bin, target);
            fs.atomicSymLink(self.builder.allocator, rel_source, target_path) catch |err| {
                log.err("Unable to symlink {s} -> {s}", .{ rel_source, target_path });
                return err;
            };
            node.setCompletedItems(i + 1);
        }
    }
};
