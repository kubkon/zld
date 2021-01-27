const std = @import("std");
const TestContext = @import("../src/test.zig").TestContext;

const archs = [_]std.Target.Cpu.Arch{.aarch64}; //, .x86_64 };

pub fn addCases(ctx: *TestContext) !void {
    for (archs) |arch| {
        const target = std.zig.CrossTarget{
            .cpu_arch = arch,
            .os_tag = .macos,
        };
        var case = try ctx.addCase("hello world in C", target);
        try case.addSource(
            \\#include <stdio.h>
            \\
            \\int main() {
            \\    fprintf(stdout, "Hello, World!\n");
            \\    return 0;
            \\}
        , .C);
        case.expectedOutput("Hello, World!\n");
    }
}
