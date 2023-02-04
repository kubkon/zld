const std = @import("std");
const CrossTarget = std.zig.CrossTarget;
const TestContext = @import("test_base").TestContext;

const linux_x86_64 = CrossTarget{
    .cpu_arch = .x86_64,
    .os_tag = .linux,
    .abi = .musl,
};
const macos_x86_64 = CrossTarget{
    .cpu_arch = .x86_64,
    .os_tag = .macos,
    .abi = .none,
};
const macos_aarch64 = CrossTarget{
    .cpu_arch = .aarch64,
    .os_tag = .macos,
    .abi = .none,
};
const macos_targets: []const CrossTarget = &.{
    macos_x86_64,
    macos_aarch64,
};
const all_targets: []const CrossTarget = &.{
    linux_x86_64,
    macos_x86_64,
    macos_aarch64,
};

pub fn addCases(ctx: *TestContext) !void {
    // All targets
    for (all_targets) |target| {
        {
            var case = try ctx.addCase("hello world in Zig", target);
            try case.addInput("hello.zig",
                \\const std = @import("std");
                \\
                \\pub fn main() anyerror!void {
                \\    const stdout = std.io.getStdOut().writer();
                \\    try stdout.print("Hello, World!\n", .{});
                \\}
            );
            case.expectedStdout("Hello, World!\n");
        }
        {
            var case = try ctx.addCase("stack traces in Zig", target);
            try case.addInput("panic.zig",
                \\const std = @import("std");
                \\
                \\pub fn main() void {
                \\    unreachable;
                \\}
            );
            case.expectedStdout("");
            // TODO figure out if we can test the resultant stack trace info
            // case.expectedStderr(
            //     \\thread 5731434 panic: reached unreachable code
            //     \\/Users/kubkon/dev/zld/zig-cache/tmp/ObL4MD7CSJolhrZC/panic.zig:4:5: 0x104d4bef3 in main (panic)
            //     \\    unreachable;
            //     \\    ^
            //     \\/opt/zig/lib/zig/std/start.zig:335:22: 0x104d4c03f in std.start.main (panic)
            //     \\            root.main();
            //     \\                     ^
            //     \\???:?:?: 0x190c74f33 in ??? (???)
            //     \\Panicked during a panic. Aborting.
            // );
        }
        {
            var case = try ctx.addCase("tlv in Zig", target);
            try case.addInput("tlv.zig",
                \\const std = @import("std");
                \\
                \\threadlocal var globl: usize = 0;
                \\
                \\pub fn main() void {
                \\    std.log.info("Before: {}", .{globl});
                \\    globl += 1;
                \\    std.log.info("After: {}", .{globl});
                \\}
            );
            case.expectedStdout("");
            case.expectedStderr("info: Before: 0\ninfo: After: 1\n");
        }
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
            case.expectedStdout("Hello, World!\n");
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
            case.expectedStdout("1 + 2 = 3\n");
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
            case.expectedStdout("Hello, World!\n");
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
            case.expectedStdout("aGlobal=1\n");
        }
        {
            var case = try ctx.addCase("zerofill test in C", target);
            try case.addInput("bss.c",
                \\#include <stdio.h>
                \\
                \\static int buf[0x100000];
                \\
                \\int main(int argc, char* argv[]) {
                \\  buf[0] = 1;
                \\  buf[1] = 3;
                \\  printf("%d, %d, %d\n", buf[0], buf[1], buf[0x100000-1]);
                \\  return 0;
                \\}
            );
            case.expectedStdout("1, 3, 0\n");
        }
        {
            var case = try ctx.addCase("local tls in C", target);
            try case.addInput("a.c",
                \\#include <stdio.h>
                \\
                \\_Thread_local int x = 2;
                \\extern _Thread_local int y;
                \\extern _Thread_local int z;
                \\
                \\int main(int argc, char* argv[]) {
                \\  y = 3;
                \\  printf("%d, %d, %d\n", x, y, z);
                \\  x += 1;
                \\  y -= 1;
                \\  z *= 2;
                \\  printf("%d, %d, %d\n", x, y, z);
                \\  return 0;
                \\}
            );
            try case.addInput("b.c",
                \\_Thread_local int y;
                \\_Thread_local int z = 4;
            );
            case.expectedStdout(
                \\2, 3, 4
                \\3, 2, 8
                \\
            );
        }
    }
}
