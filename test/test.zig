const std = @import("std");
const builtin = @import("builtin");
const elf = @import("elf.zig");
const macho = @import("macho.zig");

fn addStandaloneTestCase(step: *std.Build.Step, case: anytype) void {
    const b = step.owner;
    const dep = b.anonymousDependency(case.build_root, case.import, .{});
    const dep_step = dep.builder.default_step;
    const dep_prefix_adjusted = dep.builder.dep_prefix["test".len..];
    dep_step.name = b.fmt("{s}{s}", .{ dep_prefix_adjusted, dep_step.name });
    step.dependOn(dep_step);
}

pub fn addElfTests(b: *std.Build) *std.Build.Step {
    const step = b.step("test-elf", "Run ELF tests");

    if (builtin.target.ofmt == .elf)
        inline for (elf.cases) |case| addStandaloneTestCase(step, case);

    return step;
}

pub fn addMachOTests(b: *std.Build) *std.Build.Step {
    const step = b.step("test-macho", "Run MachO tests");

    if (builtin.target.ofmt == .macho)
        inline for (macho.cases) |case| addStandaloneTestCase(step, case);

    return step;
}
