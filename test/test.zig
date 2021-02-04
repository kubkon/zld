const std = @import("std");
const TestContext = @import("../src/test.zig").TestContext;

const archs = [_]std.Target.Cpu.Arch{ .aarch64, .x86_64 };

pub fn addCases(ctx: *TestContext) !void {
    for (archs) |arch| {
        const target = std.zig.CrossTarget{
            .cpu_arch = arch,
            .os_tag = .macos,
            .abi = .gnu,
        };
        {
            var case = try ctx.addCase("hello world in C", target);
            try case.addInput("main.c",
                \\#include <stdio.h>
                \\
                \\int main() {
                \\    fprintf(stdout, "Hello, World!\n");
                \\    return 0;
                \\}
            );
            case.expectedOutput("Hello, World!\n");
        }

        {
            var case = try ctx.addCase("simple multi object in C", target);
            try case.addInput("add.h",
                \\#ifndef ADD_H
                \\#define ADD_H
                \\
                \\int add(int a, int b);
                \\
                \\#endif
            );
            try case.addInput("add.c",
                \\#include "add.h"
                \\
                \\int add(int a, int b) {
                \\    return a + b;
                \\}
            );
            try case.addInput("main.c",
                \\#include <stdio.h>
                \\#include "add.h"
                \\
                \\int main() {
                \\    int a = 1;
                \\    int b = 2;
                \\    int res = add(1, 2);
                \\    printf("%d + %d = %d\n", a, b, res);
                \\    return 0;
                \\}
            );
            case.expectedOutput("1 + 2 = 3\n");
        }

        {
            var case = try ctx.addCase("multiple imports in C", target);
            try case.addInput("main.c",
                \\#include <stdio.h>
                \\#include <stdlib.h>
                \\
                \\int main() {
                \\    fprintf(stdout, "Hello, World!\n");
                \\    exit(0);
                \\    return 0;
                \\}
            );
            case.expectedOutput("Hello, World!\n");
        }

        {
            var case = try ctx.addCase("zero-init statics in C", target);
            try case.addInput("main.c",
                \\#include <stdio.h>
                \\
                \\static int aGlobal = 1;
                \\
                \\int main() {
                \\    printf("aGlobal=%d\n", aGlobal);
                \\    aGlobal -= 1;
                \\    return aGlobal;
                \\}
            );
            case.expectedOutput("aGlobal=1\n");
        }
    }
}
