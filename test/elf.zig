pub fn addElfTests(b: *Build, opts: Options) *Step {
    const elf_step = b.step("test-elf", "Run ELF tests");

    if (builtin.target.ofmt == .elf) {
        elf_step.dependOn(testCommon(b, opts));
        elf_step.dependOn(testCopyrel(b, opts));
        elf_step.dependOn(testCopyrelAlias(b, opts));
        elf_step.dependOn(testDsoIfunc(b, opts));
        elf_step.dependOn(testDsoPlt(b, opts));
        elf_step.dependOn(testIfuncAlias(b, opts));
        elf_step.dependOn(testIfuncDynamic(b, opts));
        elf_step.dependOn(testIfuncFuncPtr(b, opts));
        elf_step.dependOn(testIfuncNoPlt(b, opts));
        elf_step.dependOn(testIfuncStatic(b, opts));
        elf_step.dependOn(testIfuncStaticPie(b, opts));
        elf_step.dependOn(testHelloDynamic(b, opts));
        elf_step.dependOn(testHelloPie(b, opts));
        elf_step.dependOn(testHelloStatic(b, opts));
        elf_step.dependOn(testTlsDesc(b, opts));
        elf_step.dependOn(testTlsDescStatic(b, opts));
        elf_step.dependOn(testTlsDso(b, opts));
        elf_step.dependOn(testTlsGd(b, opts));
        elf_step.dependOn(testTlsStatic(b, opts));
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

fn testIfuncAlias(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-ifunc-alias", "");

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\#include <assert.h>
        \\void foo() {}
        \\int bar() __attribute__((ifunc("resolve_bar")));
        \\void *resolve_bar() { return foo; }
        \\void *bar2 = bar;
        \\int main() {
        \\  assert(bar == bar2);
        \\}
    , "main.c");
    exe.addArg("-fPIC");

    const run = exe.run();
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

fn testIfuncFuncPtr(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-ifunc-func-ptr", "");

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\typedef int Fn();
        \\int foo() __attribute__((ifunc("resolve_foo")));
        \\int real_foo() { return 3; }
        \\Fn *resolve_foo(void) {
        \\  return real_foo;
        \\}
    , "a.c");
    exe.addSourceBytes(
        \\typedef int Fn();
        \\int foo();
        \\Fn *get_foo() { return foo; }
    , "b.c");
    exe.addSourceBytes(
        \\#include <stdio.h>
        \\typedef int Fn();
        \\Fn *get_foo();
        \\int main() {
        \\  Fn *f = get_foo();
        \\  printf("%d\n", f());
        \\}
    , "c.c");
    exe.addArg("-fPIC");

    const run = exe.run();
    run.expectStdOutEqual("3\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testIfuncNoPlt(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-ifunc-noplt", "");

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\#include <stdio.h>
        \\__attribute__((ifunc("resolve_foo")))
        \\void foo(void);
        \\void hello(void) {
        \\  printf("Hello world\n");
        \\}
        \\typedef void Fn();
        \\Fn *resolve_foo(void) {
        \\  return hello;
        \\}
        \\int main() {
        \\  foo();
        \\}
    , "main.c");
    exe.addArgs(&.{ "-fPIC", "-fno-plt" });

    const run = exe.run();
    run.expectStdOutEqual("Hello world\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testIfuncStatic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-ifunc-static", "");

    if (!opts.has_static) {
        skipTestStep(test_step);
        return test_step;
    }

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\#include <stdio.h>
        \\void foo() __attribute__((ifunc("resolve_foo")));
        \\void hello() {
        \\  printf("Hello world\n");
        \\}
        \\void *resolve_foo() {
        \\  return hello;
        \\}
        \\int main() {
        \\  foo();
        \\  return 0;
        \\}
    , "main.c");
    exe.addArgs(&.{"-static"});

    const run = exe.run();
    run.expectStdOutEqual("Hello world\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testIfuncStaticPie(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-ifunc-static-pie", "");

    if (!opts.has_static_pie) {
        skipTestStep(test_step);
        return test_step;
    }

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\#include <stdio.h>
        \\void foo() __attribute__((ifunc("resolve_foo")));
        \\void hello() {
        \\  printf("Hello world\n");
        \\}
        \\void *resolve_foo() {
        \\  return hello;
        \\}
        \\int main() {
        \\  foo();
        \\  return 0;
        \\}
    , "main.c");
    exe.addArgs(&.{ "-fPIC", "-static-pie" });

    const run = exe.run();
    run.expectStdOutEqual("Hello world\n");
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkStart("header");
    check.checkNext("type DYN");
    check.checkStart("shdr {*}");
    check.checkNext("name .dynamic");
    check.checkStart("shdr {*}");
    check.checkNotPresent("name .interp");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testHelloStatic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-hello-static", "");

    if (!opts.has_static) {
        skipTestStep(test_step);
        return test_step;
    }

    const exe = cc(b, null, opts);
    exe.addHelloWorldMain();
    exe.addArg("-static");

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkStart("header");
    check.checkNext("type EXEC");
    check.checkStart("shdr {*}");
    check.checkNotPresent("name .dynamic");
    test_step.dependOn(&check.step);

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

    const check = exe.check();
    check.checkStart("header");
    check.checkNext("type EXEC");
    check.checkStart("shdr {*}");
    check.checkNext("name .dynamic");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testHelloPie(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-hello-pie", "");

    const exe = cc(b, null, opts);
    exe.addHelloWorldMain();
    exe.addArgs(&.{ "-fPIC", "-pie" });

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkStart("header");
    check.checkNext("type DYN");
    check.checkStart("shdr {*}");
    check.checkNext("name .dynamic");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testTlsDesc(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-desc", "");

    const main_o = cc(b, null, opts);
    main_o.addSourceBytes(
        \\#include <stdio.h>
        \\_Thread_local int foo;
        \\int get_foo();
        \\int get_bar();
        \\int main() {
        \\  foo = 42;
        \\  printf("%d %d\n", get_foo(), get_bar());
        \\  return 0;
        \\}
    , "main.c");
    main_o.addArgs(&.{ "-c", "-fPIC", "-mtls-dialect=gnu2" });
    const main_o_out = main_o.saveOutputAs("main.o");

    const a_o = cc(b, null, opts);
    a_o.addSourceBytes(
        \\extern _Thread_local int foo;
        \\int get_foo() {
        \\  return foo;
        \\}
        \\static _Thread_local int bar = 5;
        \\int get_bar() {
        \\  return bar;
        \\}
    , "a.c");
    a_o.addArgs(&.{ "-c", "-fPIC", "-mtls-dialect=gnu2" });
    const a_o_out = a_o.saveOutputAs("a.o");

    const exp_stdout = "42 5\n";

    {
        const exe = cc(b, null, opts);
        exe.addFileSource(main_o_out.file);
        exe.addFileSource(a_o_out.file);

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, null, opts);
        exe.addFileSource(main_o_out.file);
        exe.addFileSource(a_o_out.file);
        exe.addArg("-Wl,-no-relax");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsDescStatic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-desc-static", "");

    if (!opts.has_static) {
        skipTestStep(test_step);
        return test_step;
    }

    const main_o = cc(b, null, opts);
    main_o.addSourceBytes(
        \\#include <stdio.h>
        \\extern _Thread_local int foo;
        \\int main() {
        \\  foo = 42;
        \\  printf("%d\n", foo);
        \\}
    , "main.c");
    main_o.addArgs(&.{ "-c", "-fPIC", "-mtls-dialect=gnu2" });
    const main_o_out = main_o.saveOutputAs("main.o");

    const a_o = cc(b, null, opts);
    a_o.addSourceBytes(
        \\_Thread_local int foo;
    , "a.c");
    a_o.addArgs(&.{ "-c", "-fPIC", "-mtls-dialect=gnu2" });
    const a_o_out = a_o.saveOutputAs("a.o");

    const exp_stdout = "42\n";

    {
        const exe = cc(b, null, opts);
        exe.addFileSource(main_o_out.file);
        exe.addFileSource(a_o_out.file);
        exe.addArg("-static");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, null, opts);
        exe.addFileSource(main_o_out.file);
        exe.addFileSource(a_o_out.file);
        exe.addArgs(&.{ "-static", "-Wl,-no-relax" });

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsDso(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-dso", "");

    const dso = cc(b, "a.so", opts);
    dso.addSourceBytes(
        \\extern _Thread_local int foo;
        \\_Thread_local int bar;
        \\int get_foo1() { return foo; }
        \\int get_bar1() { return bar; }
    , "a.c");
    dso.addArgs(&.{ "-fPIC", "-shared" });
    const dso_out = dso.saveOutputAs("a.so");

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\#include <stdio.h>
        \\_Thread_local int foo;
        \\extern _Thread_local int bar;
        \\int get_foo1();
        \\int get_bar1();
        \\int get_foo2() { return foo; }
        \\int get_bar2() { return bar; }
        \\int main() {
        \\  foo = 5;
        \\  bar = 3;
        \\  printf("%d %d %d %d %d %d\n",
        \\         foo, bar,
        \\         get_foo1(), get_bar1(),
        \\         get_foo2(), get_bar2());
        \\  return 0;
        \\}
    , "main.c");
    exe.addFileSource(dso_out.file);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

    const run = exe.run();
    run.expectStdOutEqual("5 3 5 3 5 3\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testTlsGd(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-gd", "");

    const main_o = cc(b, "main.o", opts);
    main_o.addSourceBytes(
        \\#include <stdio.h>
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x1 = 1;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x2;
        \\__attribute__((tls_model("global-dynamic"))) extern _Thread_local int x3;
        \\__attribute__((tls_model("global-dynamic"))) extern _Thread_local int x4;
        \\int get_x5();
        \\int get_x6();
        \\int main() {
        \\  x2 = 2;
        \\  printf("%d %d %d %d %d %d\n", x1, x2, x3, x4, get_x5(), get_x6());
        \\  return 0;
        \\}
    , "main.c");
    main_o.addArgs(&.{ "-c", "-fPIC" });
    const main_o_out = main_o.saveOutputAs("main.o");

    const a_o = cc(b, "a.o", opts);
    a_o.addSourceBytes(
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x3 = 3;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x5 = 5;
        \\int get_x5() { return x5; }
    , "a.c");
    a_o.addArgs(&.{ "-c", "-fPIC" });
    const a_o_out = a_o.saveOutputAs("a.o");

    const b_o = cc(b, "b.o", opts);
    b_o.addSourceBytes(
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x4 = 4;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x6 = 6;
        \\int get_x6() { return x6; }
    , "b.c");
    b_o.addArgs(&.{ "-c", "-fPIC" });
    const b_o_out = b_o.saveOutputAs("b.o");

    const exp_stdout = "1 2 3 4 5 6\n";

    const dso1 = cc(b, "a.so", opts);
    dso1.addArg("-shared");
    dso1.addFileSource(a_o_out.file);
    const dso1_out = dso1.saveOutputAs("a.so");

    const dso2 = cc(b, "b.so", opts);
    dso2.addArgs(&.{ "-shared", "-Wl,-no-relax" });
    dso2.addFileSource(b_o_out.file);
    const dso2_out = dso2.saveOutputAs("b.so");

    {
        const exe = cc(b, null, opts);
        exe.addFileSource(main_o_out.file);
        exe.addFileSource(dso1_out.file);
        exe.addFileSource(dso2_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso1_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso2_out.dir);

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, null, opts);
        exe.addFileSource(main_o_out.file);
        exe.addArg("-Wl,-no-relax");
        exe.addFileSource(dso1_out.file);
        exe.addFileSource(dso2_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso1_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso2_out.dir);

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    if (opts.has_static) {
        {
            const exe = cc(b, null, opts);
            exe.addFileSource(main_o_out.file);
            exe.addFileSource(a_o_out.file);
            exe.addFileSource(b_o_out.file);
            exe.addArg("-static");

            const run = exe.run();
            run.expectStdOutEqual(exp_stdout);
            test_step.dependOn(run.step());
        }

        {
            const exe = cc(b, null, opts);
            exe.addFileSource(main_o_out.file);
            exe.addFileSource(a_o_out.file);
            exe.addFileSource(b_o_out.file);
            exe.addArgs(&.{ "-static", "-Wl,-no-relax" });

            const run = exe.run();
            run.expectStdOutEqual(exp_stdout);
            test_step.dependOn(run.step());
        }
    }

    return test_step;
}

fn testTlsStatic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-static", "");

    if (!opts.has_static) {
        skipTestStep(test_step);
        return test_step;
    }

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\#include <stdio.h>
        \\_Thread_local int a = 10;
        \\_Thread_local int b;
        \\_Thread_local char c = 'a';
        \\int main(int argc, char* argv[]) {
        \\  printf("%d %d %c\n", a, b, c);
        \\  a += 1;
        \\  b += 1;
        \\  c += 1;
        \\  printf("%d %d %c\n", a, b, c);
        \\  return 0;
        \\}
    , "main.c");
    exe.addArg("-static");

    const run = exe.run();
    run.expectStdOutEqual(
        \\10 0 a
        \\11 1 b
        \\
    );
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
const skipTestStep = common.skipTestStep;

const Build = std.Build;
const Compile = Step.Compile;
const FileSourceWithDir = common.FileSourceWithDir;
const Options = common.Options;
const Run = Step.Run;
const Step = Build.Step;
const SysCmd = common.SysCmd;
