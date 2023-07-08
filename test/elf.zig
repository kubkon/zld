pub fn addElfTests(b: *Build, opts: Options) *Step {
    const elf_step = b.step("test-elf", "Run ELF tests");

    if (builtin.target.ofmt == .elf) {
        elf_step.dependOn(testCommon(b, opts));
        elf_step.dependOn(testCopyrel(b, opts));
        elf_step.dependOn(testCopyrelAlias(b, opts));
        elf_step.dependOn(testDsoIfunc(b, opts));
        elf_step.dependOn(testDsoPlt(b, opts));
        elf_step.dependOn(testIfuncDynamic(b, opts));
        elf_step.dependOn(testHelloDynamic(b, opts));
    }

    return elf_step;
}

fn testCommon(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-common", "");

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\int foo;
        \\int bar;
        \\int baz = 42;
    , "a.c");
    exe.addSourceBytes(
        \\#include<stdio.h>
        \\int foo;
        \\int bar = 5;
        \\int baz;
        \\int main() {
        \\  printf("%d %d %d\n", foo, bar, baz);
        \\}
    , "main.c");
    exe.addArg("-fcommon");

    const run = exe.run();
    run.expectStdOutEqual("0 5 42\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testCopyrel(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-copyrel", "");

    const dso = cc(b, "liba.so", opts);
    dso.addArgs(&.{ "-fPIC", "-shared" });
    dso.addSourceBytes(
        \\int foo = 3;
        \\int bar = 5;
    , "a.c");
    const dso_out = dso.saveOutputAs("liba.so");

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\#include<stdio.h>
        \\extern int foo, bar;
        \\int main() {
        \\  printf("%d %d\n", foo, bar);
        \\  return 0;
        \\}
    , "main.c");
    exe.addArg("-la");
    exe.addPrefixedDirectorySource("-L", dso_out.dir);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

    const run = exe.run();
    run.expectStdOutEqual("3 5\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testCopyrelAlias(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-copyrel-alias", "");

    const dso = cc(b, "c.so", opts);
    dso.addArgs(&.{ "-fPIC", "-shared" });
    dso.addSourceBytes(
        \\int bruh = 31;
        \\int foo = 42;
        \\extern int bar __attribute__((alias("foo")));
        \\extern int baz __attribute__((alias("foo")));
    , "c.c");
    const dso_out = dso.saveOutputAs("c.so");

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\#include<stdio.h>
        \\extern int foo;
        \\extern int *get_bar();
        \\int main() {
        \\  printf("%d %d %d\n", foo, *get_bar(), &foo == get_bar());
        \\  return 0;
        \\}
    , "a.c");
    exe.addSourceBytes(
        \\extern int bar;
        \\int *get_bar() { return &bar; }
    , "b.c");
    exe.addArgs(&.{ "-fno-PIC", "-no-pie" });
    exe.addFileSource(dso_out.file);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

    const run = exe.run();
    run.expectStdOutEqual("42 42 1\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testDsoIfunc(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-dso-ifunc", "");

    const dso = cc(b, "liba.so", opts);
    dso.addArgs(&.{ "-fPIC", "-shared" });
    dso.addSourceBytes(
        \\#include<stdio.h>
        \\__attribute__((ifunc("resolve_foobar")))
        \\void foobar(void);
        \\static void real_foobar(void) {
        \\  printf("Hello world\n");
        \\}
        \\typedef void Func();
        \\static Func *resolve_foobar(void) {
        \\  return real_foobar;
        \\}
    , "a.c");
    const dso_out = dso.saveOutputAs("liba.so");

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\void foobar(void);
        \\int main() {
        \\  foobar();
        \\}
    , "main.c");
    exe.addArg("-la");
    exe.addPrefixedDirectorySource("-L", dso_out.dir);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

    const run = exe.run();
    run.expectStdOutEqual("Hello world\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testDsoPlt(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-dso-plt", "");

    const dso = cc(b, "liba.so", opts);
    dso.addArgs(&.{ "-fPIC", "-shared" });
    dso.addSourceBytes(
        \\#include<stdio.h>
        \\void world() {
        \\  printf("world\n");
        \\}
        \\void real_hello() {
        \\  printf("Hello ");
        \\  world();
        \\}
        \\void hello() {
        \\  real_hello();
        \\}
    , "a.c");
    const dso_out = dso.saveOutputAs("liba.so");

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\#include<stdio.h>
        \\void world() {
        \\  printf("WORLD\n");
        \\}
        \\void hello();
        \\int main() {
        \\  hello();
        \\}
    , "main.c");
    exe.addArg("-la");
    exe.addPrefixedDirectorySource("-L", dso_out.dir);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

    const run = exe.run();
    run.expectStdOutEqual("Hello WORLD\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testIfuncDynamic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-ifunc-dynamic", "");

    const main_c =
        \\#include <stdio.h>
        \\__attribute__((ifunc("resolve_foobar")))
        \\static void foobar(void);
        \\static void real_foobar(void) {
        \\  printf("Hello world\n");
        \\}
        \\typedef void Func();
        \\static Func *resolve_foobar(void) {
        \\  return real_foobar;
        \\}
        \\int main() {
        \\  foobar();
        \\}
    ;

    {
        const exe = cc(b, null, opts);
        exe.addSourceBytes(main_c, "main.c");
        exe.addArg("-Wl,-z,lazy");

        const run = exe.run();
        run.expectStdOutEqual("Hello world\n");
        test_step.dependOn(run.step());
    }
    {
        const exe = cc(b, null, opts);
        exe.addSourceBytes(main_c, "main.c");
        exe.addArg("-Wl,-z,now");

        const run = exe.run();
        run.expectStdOutEqual("Hello world\n");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testHelloDynamic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-hello-dynamic", "");

    const exe = cc(b, null, opts);
    exe.addHelloWorldMain();
    exe.addArg("-no-pie");

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    return test_step;
}

fn cc(b: *Build, name: ?[]const u8, opts: Options) SysCmd {
    const cmd = Run.create(b, "cc");
    cmd.addArgs(&.{ "cc", "-fno-lto" });
    cmd.addArg("-o");
    const out = cmd.addOutputFileArg(name orelse "a.out");
    cmd.addPrefixedDirectorySourceArg("-B", opts.zld.dir);
    return .{ .cmd = cmd, .out = out };
}

fn ar(b: *Build, name: []const u8) SysCmd {
    const cmd = Run.create(b, "ar");
    cmd.addArgs(&.{ "ar", "rcs" });
    const out = cmd.addOutputFileArg(name);
    return .{ .cmd = cmd, .out = out };
}

fn ld(b: *Build, name: ?[]const u8, opts: Options) SysCmd {
    const cmd = Run.create(b, "ld");
    cmd.addFileSourceArg(opts.zld.file);
    cmd.addArg("-o");
    const out = cmd.addOutputFileArg(name orelse "a.out");
    return .{ .cmd = cmd, .out = out };
}

const std = @import("std");
const builtin = @import("builtin");
const common = @import("test.zig");

const Build = std.Build;
const Compile = Step.Compile;
const FileSourceWithDir = common.FileSourceWithDir;
const Options = common.Options;
const Run = Step.Run;
const Step = Build.Step;
const SysCmd = common.SysCmd;
