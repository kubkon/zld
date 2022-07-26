const std = @import("std");
const fs = std.fs;
const log = std.log;

const Allocator = std.mem.Allocator;
const Builder = std.build.Builder;
const FileSource = std.build.FileSource;
const LibExeObjStep = std.build.LibExeObjStep;
const InstallDir = std.build.InstallDir;
const Step = std.build.Step;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const enable_logging = b.option(bool, "log", "Whether to enable logging") orelse false;
    const is_qemu_enabled = b.option(bool, "enable-qemu", "Use QEMU to run cross compiled foreign architecture tests") orelse false;

    const lib = b.addStaticLibrary("zld", "src/Zld.zig");
    lib.setTarget(target);
    lib.setBuildMode(mode);
    lib.addPackagePath("dis_x86_64", "zig-dis-x86_64/src/dis_x86_64.zig");

    const exe = b.addExecutable("zld", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.addPackagePath("dis_x86_64", "zig-dis-x86_64/src/dis_x86_64.zig");

    const exe_opts = b.addOptions();
    exe.addOptions("build_options", exe_opts);
    exe_opts.addOption(bool, "enable_logging", enable_logging);
    exe.install();

    const elf_symlink = symlink(exe, "ld.zld");
    elf_symlink.step.dependOn(&exe.step);

    const macho_symlink = symlink(exe, "ld64.zld");
    macho_symlink.step.dependOn(&exe.step);

    const tests = b.addTest("src/test.zig");
    tests.setBuildMode(mode);
    tests.addPackagePath("end_to_end_tests", "test/test.zig");
    tests.addPackagePath("dis_x86_64", "zig-dis-x86_64/src/dis_x86_64.zig");

    const test_opts = b.addOptions();
    tests.addOptions("build_options", test_opts);
    test_opts.addOption(bool, "enable_qemu", is_qemu_enabled);
    test_opts.addOption(bool, "enable_logging", enable_logging);

    const test_step = b.step("test", "Run library and end-to-end tests");
    test_step.dependOn(&tests.step);
}

fn symlink(exe: *LibExeObjStep, name: []const u8) *CreateSymlinkStep {
    const step = CreateSymlinkStep.create(exe.builder, exe.getOutputSource(), name);
    exe.builder.getInstallStep().dependOn(&step.step);
    return step;
}

const CreateSymlinkStep = struct {
    pub const base_id = .custom;

    step: Step,
    builder: *Builder,
    source: FileSource,
    target: []const u8,

    pub fn create(
        builder: *Builder,
        source: FileSource,
        target: []const u8,
    ) *CreateSymlinkStep {
        const self = builder.allocator.create(CreateSymlinkStep) catch unreachable;
        self.* = CreateSymlinkStep{
            .builder = builder,
            .step = Step.init(.log, builder.fmt("symlink {s} -> {s}", .{
                source.getDisplayName(),
                target,
            }), builder.allocator, make),
            .source = source,
            .target = builder.dupe(target),
        };
        return self;
    }

    fn make(step: *Step) anyerror!void {
        const self = @fieldParentPtr(CreateSymlinkStep, "step", step);
        const rel_source = fs.path.basename(self.source.getPath(self.builder));
        const target_path = self.builder.getInstallPath(.bin, self.target);
        fs.atomicSymLink(self.builder.allocator, rel_source, target_path) catch |err| {
            log.err("Unable to symlink {s} -> {s}", .{ rel_source, target_path });
            return err;
        };
    }
};
