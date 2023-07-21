pub fn addElfTests(b: *Build, opts: Options) *Step {
    const elf_step = b.step("test-elf", "Run ELF tests");

    if (builtin.target.ofmt == .elf) {
        elf_step.dependOn(testAbsSymbols(b, opts));
        elf_step.dependOn(testAllowMultipleDefinitions(b, opts));
        elf_step.dependOn(testAsNeeded(b, opts));
        elf_step.dependOn(testCanonicalPlt(b, opts));
        elf_step.dependOn(testCommon(b, opts));
        elf_step.dependOn(testCommonArchive(b, opts));
        elf_step.dependOn(testCopyrel(b, opts));
        elf_step.dependOn(testCopyrelAlias(b, opts));
        elf_step.dependOn(testCopyrelAlignment(b, opts));
        elf_step.dependOn(testDsoIfunc(b, opts));
        elf_step.dependOn(testDsoPlt(b, opts));
        elf_step.dependOn(testDsoUndef(b, opts));
        elf_step.dependOn(testEmptyObject(b, opts));
        elf_step.dependOn(testEntryPoint(b, opts));
        elf_step.dependOn(testExecStack(b, opts));
        elf_step.dependOn(testExportDynamic(b, opts));
        elf_step.dependOn(testExportSymbolsFromExe(b, opts));
        elf_step.dependOn(testFuncAddress(b, opts));
        elf_step.dependOn(testGcSections(b, opts));
        elf_step.dependOn(testHelloDynamic(b, opts));
        elf_step.dependOn(testHelloPie(b, opts));
        elf_step.dependOn(testHelloStatic(b, opts));
        elf_step.dependOn(testHiddenWeakUndef(b, opts));
        elf_step.dependOn(testIfuncAlias(b, opts));
        elf_step.dependOn(testIfuncDlopen(b, opts));
        elf_step.dependOn(testIfuncDynamic(b, opts));
        elf_step.dependOn(testIfuncExport(b, opts));
        elf_step.dependOn(testIfuncFuncPtr(b, opts));
        elf_step.dependOn(testIfuncNoPlt(b, opts));
        elf_step.dependOn(testIfuncStatic(b, opts));
        elf_step.dependOn(testIfuncStaticPie(b, opts));
        elf_step.dependOn(testImageBase(b, opts));
        elf_step.dependOn(testInitArrayOrder(b, opts));
        elf_step.dependOn(testLargeAlignmentDso(b, opts));
        elf_step.dependOn(testLargeAlignmentExe(b, opts));
        elf_step.dependOn(testLinkOrder(b, opts));
        elf_step.dependOn(testLinkerScript(b, opts));
        elf_step.dependOn(testNoEhFrameHdr(b, opts));
        elf_step.dependOn(testPltGot(b, opts));
        elf_step.dependOn(testPreinitArray(b, opts));
        elf_step.dependOn(testPushPopState(b, opts));
        elf_step.dependOn(testSharedAbsSymbol(b, opts));
        elf_step.dependOn(testStrip(b, opts));
        elf_step.dependOn(testTlsCommon(b, opts));
        elf_step.dependOn(testTlsDesc(b, opts));
        elf_step.dependOn(testTlsDescImport(b, opts));
        elf_step.dependOn(testTlsDescStatic(b, opts));
        elf_step.dependOn(testTlsDfStaticTls(b, opts));
        elf_step.dependOn(testTlsDso(b, opts));
        elf_step.dependOn(testTlsGd(b, opts));
        elf_step.dependOn(testTlsGdNoPlt(b, opts));
        elf_step.dependOn(testTlsGdToIe(b, opts));
        elf_step.dependOn(testTlsIe(b, opts));
        elf_step.dependOn(testTlsLargeAlignment(b, opts));
        elf_step.dependOn(testTlsLargeStaticImage(b, opts));
        elf_step.dependOn(testTlsLd(b, opts));
        elf_step.dependOn(testTlsLdDso(b, opts));
        elf_step.dependOn(testTlsLdNoPlt(b, opts));
        elf_step.dependOn(testTlsNoPic(b, opts));
        elf_step.dependOn(testTlsOffsetAlignment(b, opts));
        elf_step.dependOn(testTlsPic(b, opts));
        elf_step.dependOn(testTlsSmallAlignment(b, opts));
        elf_step.dependOn(testTlsStatic(b, opts));
        elf_step.dependOn(testZNow(b, opts));
    }

    return elf_step;
}

fn testAbsSymbols(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-abs-symbols", "");

    const obj = cc(b, opts);
    obj.addAsmSource(
        \\.globl foo
        \\foo = 0x800008
    );
    obj.addArg("-c");
    const obj_out = obj.saveOutputAs("a.o");

    const exe = cc(b, opts);
    exe.addCSource(
        \\#define _GNU_SOURCE 1
        \\#include <signal.h>
        \\#include <stdio.h>
        \\#include <stdlib.h>
        \\#include <ucontext.h>
        \\#include <assert.h>
        \\void handler(int signum, siginfo_t *info, void *ptr) {
        \\  assert((size_t)info->si_addr == 0x800008);
        \\  exit(0);
        \\}
        \\extern volatile int foo;
        \\int main() {
        \\  struct sigaction act;
        \\  act.sa_flags = SA_SIGINFO | SA_RESETHAND;
        \\  act.sa_sigaction = handler;
        \\  sigemptyset(&act.sa_mask);
        \\  sigaction(SIGSEGV, &act, 0);
        \\  foo = 5;
        \\}
    );
    exe.addArg("-fno-PIC");
    exe.addFileSource(obj_out.file);

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testAllowMultipleDefinitions(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-allow-multiple-definitions", "");

    const a_o = cc(b, opts);
    a_o.addCSource("int main() { return 0; }");
    a_o.addArg("-c");
    const a_o_out = a_o.saveOutputAs("a.o");

    const b_o = cc(b, opts);
    b_o.addCSource("int main() { return 1; }");
    b_o.addArg("-c");
    const b_o_out = b_o.saveOutputAs("b.o");

    {
        const exe = cc(b, opts);
        exe.addFileSource(a_o_out.file);
        exe.addFileSource(b_o_out.file);
        exe.addArg("-Wl,--allow-multiple-definition");

        const run = exe.run();
        test_step.dependOn(run.step());
    }
    {
        const exe = cc(b, opts);
        exe.addFileSource(a_o_out.file);
        exe.addFileSource(b_o_out.file);
        exe.addArg("-Wl,-z,muldefs");

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testAsNeeded(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-as-needed", "");

    const main_o = cc(b, opts);
    main_o.addCSource(
        \\#include <stdio.h>
        \\int baz();
        \\int main() {
        \\  printf("%d\n", baz());
        \\  return 0;
        \\}
    );
    main_o.addArg("-c");
    const main_o_out = main_o.saveOutputAs("main.o");

    const libfoo = cc(b, opts);
    libfoo.addCSource("int foo() { return 42; }");
    libfoo.addArgs(&.{ "-shared", "-fPIC", "-Wl,-soname,libfoo.so" });
    const libfoo_out = libfoo.saveOutputAs("libfoo.so");

    const libbar = cc(b, opts);
    libbar.addCSource("int bar() { return 42; }");
    libbar.addArgs(&.{ "-shared", "-fPIC", "-Wl,-soname,libbar.so" });
    const libbar_out = libbar.saveOutputAs("libbar.so");

    const libbaz = cc(b, opts);
    libbaz.addCSource(
        \\int foo();
        \\int baz() { return foo(); }
    );
    libbaz.addArgs(&.{ "-shared", "-fPIC", "-Wl,-soname,libbaz.so", "-lfoo" });
    libbaz.addPrefixedDirectorySource("-L", libfoo_out.dir);
    const libbaz_out = libbaz.saveOutputAs("libbaz.so");

    {
        const exe = cc(b, opts);
        exe.addFileSource(main_o_out.file);
        exe.addArg("-Wl,--no-as-needed");
        exe.addFileSource(libfoo_out.file);
        exe.addFileSource(libbar_out.file);
        exe.addFileSource(libbaz_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libfoo_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libbar_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libbaz_out.dir);

        const run = exe.run();
        run.expectStdOutEqual("42\n");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInDynamicSection();
        check.checkExact("NEEDED libfoo.so");
        check.checkExact("NEEDED libbar.so");
        check.checkExact("NEEDED libbaz.so");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(main_o_out.file);
        exe.addArg("-Wl,--as-needed");
        exe.addFileSource(libfoo_out.file);
        exe.addFileSource(libbar_out.file);
        exe.addFileSource(libbaz_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libfoo_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libbar_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libbaz_out.dir);

        const run = exe.run();
        run.expectStdOutEqual("42\n");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInDynamicSection();
        check.checkNotPresent("NEEDED libbar.so");
        check.checkInDynamicSection();
        check.checkExact("NEEDED libfoo.so");
        check.checkExact("NEEDED libbaz.so");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testCanonicalPlt(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-canonical-plt", "");

    const dso = cc(b, opts);
    dso.addCSource(
        \\void *foo() {
        \\  return foo;
        \\}
        \\void *bar() {
        \\  return bar;
        \\}
    );
    dso.addArgs(&.{ "-fPIC", "-shared" });
    const dso_out = dso.saveOutputAs("a.so");

    const b_o = cc(b, opts);
    b_o.addCSource(
        \\void *bar();
        \\void *baz() {
        \\  return bar;
        \\}
    );
    b_o.addArgs(&.{ "-fPIC", "-c" });
    const b_o_out = b_o.saveOutputAs("b.o");

    const main_o = cc(b, opts);
    main_o.addCSource(
        \\#include <assert.h>
        \\void *foo();
        \\void *bar();
        \\void *baz();
        \\int main() {
        \\  assert(foo == foo());
        \\  assert(bar == bar());
        \\  assert(bar == baz());
        \\}
    );
    main_o.addArgs(&.{ "-fno-PIC", "-c" });
    const main_o_out = main_o.saveOutputAs("main.o");

    const exe = cc(b, opts);
    exe.addFileSource(main_o_out.file);
    exe.addFileSource(b_o_out.file);
    exe.addFileSource(dso_out.file);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);
    exe.addArg("-no-pie");

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testCommon(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-common", "");

    const exe = cc(b, opts);
    exe.addCSource(
        \\int foo;
        \\int bar;
        \\int baz = 42;
    );
    exe.addCSource(
        \\#include<stdio.h>
        \\int foo;
        \\int bar = 5;
        \\int baz;
        \\int main() {
        \\  printf("%d %d %d\n", foo, bar, baz);
        \\}
    );
    exe.addArg("-fcommon");

    const run = exe.run();
    run.expectStdOutEqual("0 5 42\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testCommonArchive(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-common-archive", "");

    const a_o = cc(b, opts);
    a_o.addCSource(
        \\#include <stdio.h>
        \\int foo;
        \\int bar;
        \\extern int baz;
        \\__attribute__((weak)) int two();
        \\int main() {
        \\  printf("%d %d %d %d\n", foo, bar, baz, two ? two() : -1);
        \\}
    );
    a_o.addArgs(&.{ "-fcommon", "-c" });
    const a_o_out = a_o.saveOutputAs("a.o");

    const b_o = cc(b, opts);
    b_o.addCSource("int foo = 5;");
    b_o.addArgs(&.{ "-fcommon", "-c" });
    const b_o_out = b_o.saveOutputAs("b.o");

    {
        const c_o = cc(b, opts);
        c_o.addCSource(
            \\int bar;
            \\int two() { return 2; }
        );
        c_o.addArgs(&.{ "-fcommon", "-c" });
        const c_o_out = c_o.saveOutputAs("c.o");

        const d_o = cc(b, opts);
        d_o.addCSource("int baz;");
        d_o.addArgs(&.{ "-fcommon", "-c" });
        const d_o_out = d_o.saveOutputAs("d.o");

        const lib = ar(b);
        lib.addFileSource(b_o_out.file);
        lib.addFileSource(c_o_out.file);
        lib.addFileSource(d_o_out.file);
        const lib_out = lib.saveOutputAs("libe.a");

        const exe = cc(b, opts);
        exe.addFileSource(a_o_out.file);
        exe.addFileSource(lib_out.file);

        const run = exe.run();
        run.expectStdOutEqual("5 0 0 -1\n");
        test_step.dependOn(run.step());
    }

    {
        const e_o = cc(b, opts);
        e_o.addCSource(
            \\int bar = 0;
            \\int baz = 7;
            \\int two() { return 2; }
        );
        e_o.addArgs(&.{ "-fcommon", "-c" });
        const e_o_out = e_o.saveOutputAs("e.o");

        const lib = ar(b);
        lib.addFileSource(b_o_out.file);
        lib.addFileSource(e_o_out.file);
        const lib_out = lib.saveOutputAs("libe.a");

        const exe = cc(b, opts);
        exe.addFileSource(a_o_out.file);
        exe.addFileSource(lib_out.file);

        const run = exe.run();
        run.expectStdOutEqual("5 0 7 2\n");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testCopyrel(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-copyrel", "");

    const dso = cc(b, opts);
    dso.addArgs(&.{ "-fPIC", "-shared" });
    dso.addCSource(
        \\int foo = 3;
        \\int bar = 5;
    );
    const dso_out = dso.saveOutputAs("liba.so");

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include<stdio.h>
        \\extern int foo, bar;
        \\int main() {
        \\  printf("%d %d\n", foo, bar);
        \\  return 0;
        \\}
    );
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

    const dso = cc(b, opts);
    dso.addArgs(&.{ "-fPIC", "-shared" });
    dso.addCSource(
        \\int bruh = 31;
        \\int foo = 42;
        \\extern int bar __attribute__((alias("foo")));
        \\extern int baz __attribute__((alias("foo")));
    );
    const dso_out = dso.saveOutputAs("c.so");

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include<stdio.h>
        \\extern int foo;
        \\extern int *get_bar();
        \\int main() {
        \\  printf("%d %d %d\n", foo, *get_bar(), &foo == get_bar());
        \\  return 0;
        \\}
    );
    exe.addCSource(
        \\extern int bar;
        \\int *get_bar() { return &bar; }
    );
    exe.addArgs(&.{ "-fno-PIC", "-no-pie" });
    exe.addFileSource(dso_out.file);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

    const run = exe.run();
    run.expectStdOutEqual("42 42 1\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testCopyrelAlignment(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-copyrel-alignment", "");

    const a_so = cc(b, opts);
    a_so.addCSource("__attribute__((aligned(32))) int foo = 5;");
    a_so.addArgs(&.{ "-shared", "-fPIC" });
    const a_so_out = a_so.saveOutputAs("a.so");

    const b_so = cc(b, opts);
    b_so.addCSource("__attribute__((aligned(8))) int foo = 5;");
    b_so.addArgs(&.{ "-shared", "-fPIC" });
    const b_so_out = b_so.saveOutputAs("b.so");

    const c_so = cc(b, opts);
    c_so.addCSource("__attribute__((aligned(256))) int foo = 5;");
    c_so.addArgs(&.{ "-shared", "-fPIC" });
    const c_so_out = c_so.saveOutputAs("c.so");

    const obj = cc(b, opts);
    obj.addCSource(
        \\#include <stdio.h>
        \\extern int foo;
        \\int main() { printf("%d\n", foo); }
    );
    obj.addArgs(&.{ "-c", "-fno-PIE" });
    const obj_out = obj.saveOutputAs("main.o");

    const exp_stdout = "5\n";

    {
        const exe = cc(b, opts);
        exe.addFileSource(obj_out.file);
        exe.addFileSource(a_so_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", a_so_out.dir);
        exe.addArg("-no-pie");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkStart();
        check.checkExact("section headers");
        check.checkExact("name .copyrel");
        check.checkExact("addralign 20");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(obj_out.file);
        exe.addFileSource(b_so_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", b_so_out.dir);
        exe.addArg("-no-pie");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkStart();
        check.checkExact("section headers");
        check.checkExact("name .copyrel");
        check.checkExact("addralign 8");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(obj_out.file);
        exe.addFileSource(c_so_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", c_so_out.dir);
        exe.addArg("-no-pie");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkStart();
        check.checkExact("section headers");
        check.checkExact("name .copyrel");
        check.checkExact("addralign 100");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testDsoIfunc(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-dso-ifunc", "");

    const dso = cc(b, opts);
    dso.addArgs(&.{ "-fPIC", "-shared" });
    dso.addCSource(
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
    );
    const dso_out = dso.saveOutputAs("liba.so");

    const exe = cc(b, opts);
    exe.addCSource(
        \\void foobar(void);
        \\int main() {
        \\  foobar();
        \\}
    );
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

    const dso = cc(b, opts);
    dso.addArgs(&.{ "-fPIC", "-shared" });
    dso.addCSource(
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
    );
    const dso_out = dso.saveOutputAs("liba.so");

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include<stdio.h>
        \\void world() {
        \\  printf("WORLD\n");
        \\}
        \\void hello();
        \\int main() {
        \\  hello();
        \\}
    );
    exe.addArg("-la");
    exe.addPrefixedDirectorySource("-L", dso_out.dir);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

    const run = exe.run();
    run.expectStdOutEqual("Hello WORLD\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testDsoUndef(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-dso-undef", "");

    const dso = cc(b, opts);
    dso.addCSource(
        \\extern int foo;
        \\int bar = 5;
        \\int baz() { return foo; }
    );
    dso.addArgs(&.{ "-shared", "-fPIC" });
    const dso_out = dso.saveOutputAs("a.so");

    const obj = cc(b, opts);
    obj.addCSource("int foo = 3;");
    obj.addArg("-c");
    const obj_out = obj.saveOutputAs("b.o");

    const lib = ar(b);
    lib.addFileSource(obj_out.file);
    const lib_out = lib.saveOutputAs("c.a");

    const exe = cc(b, opts);
    exe.addFileSource(dso_out.file);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);
    exe.addFileSource(lib_out.file);
    exe.addCSource(
        \\extern int bar;
        \\int main() {
        \\  return bar - 5;
        \\}
    );

    const run = exe.run();
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkInDynamicSymtab();
    check.checkContains("foo");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testEmptyObject(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-empty-object", "");

    const exe = cc(b, opts);
    exe.addHelloWorldMain();
    exe.addCSource("");

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    return test_step;
}

fn testEntryPoint(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-entry-point", "");

    const a_o = cc(b, opts);
    a_o.addAsmSource(
        \\.globl foo, bar
        \\foo = 0x1000
        \\bar = 0x2000
    );
    a_o.addArg("-c");
    const a_o_out = a_o.saveOutputAs("a.o");

    const b_o = cc(b, opts);
    b_o.addEmptyMain();
    b_o.addArg("-c");
    const b_o_out = b_o.saveOutputAs("b.o");

    {
        const exe = cc(b, opts);
        exe.addFileSource(a_o_out.file);
        exe.addFileSource(b_o_out.file);
        exe.addArg("-Wl,-e,foo");

        const check = exe.check();
        check.checkStart();
        check.checkExact("header");
        check.checkExact("entry 1000");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(a_o_out.file);
        exe.addFileSource(b_o_out.file);
        exe.addArg("-Wl,-e,bar");

        const check = exe.check();
        check.checkStart();
        check.checkExact("header");
        check.checkExact("entry 2000");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testExecStack(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-exec-stack", "");

    const obj = cc(b, opts);
    obj.addEmptyMain();
    obj.addArg("-c");
    const obj_out = obj.saveOutputAs("a.o");

    {
        const exe = cc(b, opts);
        exe.addFileSource(obj_out.file);
        exe.addArg("-Wl,-z,execstack");

        const check = exe.check();
        check.checkStart();
        check.checkExact("program headers");
        check.checkExact("type GNU_STACK");
        check.checkExact("flags RWE");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(obj_out.file);
        exe.addArgs(&.{ "-Wl,-z,execstack", "-Wl,-z,noexecstack" });

        const check = exe.check();
        check.checkStart();
        check.checkExact("program headers");
        check.checkExact("type GNU_STACK");
        check.checkExact("flags RW");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(obj_out.file);

        const check = exe.check();
        check.checkStart();
        check.checkExact("program headers");
        check.checkExact("type GNU_STACK");
        check.checkExact("flags RW");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testExportDynamic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-export-dynamic", "");

    const obj = cc(b, opts);
    obj.addAsmSource(
        \\.text
        \\  .globl foo
        \\  .hidden foo
        \\foo:
        \\  nop
        \\  .globl bar
        \\bar:
        \\  nop
        \\  .globl _start
        \\_start:
        \\  nop
    );
    obj.addArg("-c");
    const obj_out = obj.saveOutputAs("a.o");

    const dso = cc(b, opts);
    dso.addCSource("");
    dso.addArgs(&.{ "-fPIC", "-shared" });
    const dso_out = dso.saveOutputAs("a.so");

    const exe = ld(b, opts);
    exe.addFileSource(obj_out.file);
    exe.addFileSource(dso_out.file);
    exe.addArg("-rpath");
    exe.addDirectorySource(dso_out.dir);
    exe.addArg("--export-dynamic");

    const check = exe.check();
    check.checkInDynamicSymtab();
    check.checkContains("bar");
    check.checkContains("_start");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testExportSymbolsFromExe(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-export-symbols-from-exe", "");

    const dso = cc(b, opts);
    dso.addCSource(
        \\void expfn1();
        \\void expfn2() {}
        \\
        \\void foo() {
        \\  expfn1();
        \\}
    );
    dso.addArgs(&.{ "-fPIC", "-shared" });
    const dso_out = dso.saveOutputAs("a.so");

    const exe = cc(b, opts);
    exe.addCSource(
        \\void expfn1() {}
        \\void expfn2() {}
        \\void foo();
        \\
        \\int main() {
        \\  expfn1();
        \\  expfn2();
        \\  foo();
        \\}
    );
    exe.addFileSource(dso_out.file);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

    const check = exe.check();
    check.checkInDynamicSymtab();
    check.checkContains("expfn2");
    check.checkInDynamicSymtab();
    check.checkContains("expfn1");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testFuncAddress(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-func-address", "");

    const dso = cc(b, opts);
    dso.addCSource("void fn() {}");
    dso.addArgs(&.{ "-fPIC", "-shared" });
    const dso_out = dso.saveOutputAs("a.so");

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include <assert.h>
        \\typedef void Func();
        \\void fn();
        \\Func *const ptr = fn;
        \\int main() {
        \\  assert(fn == ptr);
        \\}
    );
    exe.addFileSource(dso_out.file);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);
    exe.addArgs(&.{ "-fno-PIC", "-no-pie" });

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testGcSections(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-gc-sections", "");

    const obj = cc(b, opts);
    obj.addCppSource(
        \\#include <stdio.h>
        \\int two() { return 2; }
        \\int live_var1 = 1;
        \\int live_var2 = two();
        \\int dead_var1 = 3;
        \\int dead_var2 = 4;
        \\void live_fn1() {}
        \\void live_fn2() { live_fn1(); }
        \\void dead_fn1() {}
        \\void dead_fn2() { dead_fn1(); }
        \\int main() {
        \\  printf("%d %d\n", live_var1, live_var2);
        \\  live_fn2();
        \\}
    );
    obj.addArgs(&.{ "-c", "-ffunction-sections", "-fdata-sections" });
    const obj_out = obj.saveOutputAs("a.o");

    {
        const exe = cc(b, opts);
        exe.addFileSource(obj_out.file);

        const run = exe.run();
        run.expectStdOutEqual("1 2\n");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkContains("live_var1");
        check.checkInSymtab();
        check.checkContains("live_var2");
        check.checkInSymtab();
        check.checkContains("dead_var1");
        check.checkInSymtab();
        check.checkContains("dead_var2");
        check.checkInSymtab();
        check.checkContains("live_fn1");
        check.checkInSymtab();
        check.checkContains("live_fn2");
        check.checkInSymtab();
        check.checkContains("dead_fn1");
        check.checkInSymtab();
        check.checkContains("dead_fn2");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(obj_out.file);
        exe.addArg("-Wl,-gc-sections");

        const run = exe.run();
        run.expectStdOutEqual("1 2\n");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkContains("live_var1");
        check.checkInSymtab();
        check.checkContains("live_var2");
        check.checkInSymtab();
        check.checkNotPresent("dead_var1");
        check.checkInSymtab();
        check.checkNotPresent("dead_var2");
        check.checkInSymtab();
        check.checkContains("live_fn1");
        check.checkInSymtab();
        check.checkContains("live_fn2");
        check.checkInSymtab();
        check.checkNotPresent("dead_fn1");
        check.checkInSymtab();
        check.checkNotPresent("dead_fn2");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testHelloDynamic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-hello-dynamic", "");

    const exe = cc(b, opts);
    exe.addHelloWorldMain();
    exe.addArg("-no-pie");

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkStart();
    check.checkExact("header");
    check.checkExact("type EXEC");
    check.checkStart();
    check.checkExact("section headers");
    check.checkExact("name .dynamic");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testHelloPie(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-hello-pie", "");

    const exe = cc(b, opts);
    exe.addHelloWorldMain();
    exe.addArgs(&.{ "-fPIC", "-pie" });

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkStart();
    check.checkExact("header");
    check.checkExact("type DYN");
    check.checkStart();
    check.checkExact("section headers");
    check.checkExact("name .dynamic");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testHelloStatic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-hello-static", "");

    if (!opts.has_static) {
        skipTestStep(test_step);
        return test_step;
    }

    const exe = cc(b, opts);
    exe.addHelloWorldMain();
    exe.addArg("-static");

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkStart();
    check.checkExact("header");
    check.checkExact("type EXEC");
    check.checkStart();
    check.checkExact("section headers");
    check.checkNotPresent("name .dynamic");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testHiddenWeakUndef(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-hidden-weak-undef", "");

    const dso = cc(b, opts);
    dso.addCSource(
        \\__attribute__((weak, visibility("hidden"))) void foo();
        \\void bar() { foo(); }
    );
    dso.addArgs(&.{ "-fPIC", "-shared" });

    const check = dso.check();
    check.checkInDynamicSymtab();
    check.checkNotPresent("foo");
    check.checkInDynamicSymtab();
    check.checkContains("bar");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testIfuncAlias(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-ifunc-alias", "");

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include <assert.h>
        \\void foo() {}
        \\int bar() __attribute__((ifunc("resolve_bar")));
        \\void *resolve_bar() { return foo; }
        \\void *bar2 = bar;
        \\int main() {
        \\  assert(bar == bar2);
        \\}
    );
    exe.addArg("-fPIC");

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testIfuncDlopen(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-ifunc-dlopen", "");

    const dso = cc(b, opts);
    dso.addCSource(
        \\__attribute__((ifunc("resolve_foo")))
        \\void foo(void);
        \\static void real_foo(void) {
        \\}
        \\typedef void Func();
        \\static Func *resolve_foo(void) {
        \\  return real_foo;
        \\}
    );
    dso.addArgs(&.{ "-fPIC", "-shared" });
    const dso_out = dso.saveOutputAs("a.so");

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include <dlfcn.h>
        \\#include <assert.h>
        \\#include <stdlib.h>
        \\typedef void Func();
        \\void foo(void);
        \\int main() {
        \\  void *handle = dlopen(NULL, RTLD_NOW);
        \\  Func *p = dlsym(handle, "foo");
        \\
        \\  foo();
        \\  p();
        \\  assert(foo == p);
        \\}
    );
    exe.addFileSource(dso_out.file);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);
    exe.addArgs(&.{ "-fno-PIE", "-no-pie", "-ldl" });

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
        const exe = cc(b, opts);
        exe.addCSource(main_c);
        exe.addArg("-Wl,-z,lazy");

        const run = exe.run();
        run.expectStdOutEqual("Hello world\n");
        test_step.dependOn(run.step());
    }
    {
        const exe = cc(b, opts);
        exe.addCSource(main_c);
        exe.addArg("-Wl,-z,now");

        const run = exe.run();
        run.expectStdOutEqual("Hello world\n");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testIfuncExport(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-ifunc-export", "");

    const dso = cc(b, opts);
    dso.addCSource(
        \\#include <stdio.h>
        \\__attribute__((ifunc("resolve_foobar")))
        \\void foobar(void);
        \\void real_foobar(void) {
        \\  printf("Hello world\n");
        \\}
        \\typedef void Func();
        \\Func *resolve_foobar(void) {
        \\  return real_foobar;
        \\}
    );
    dso.addArgs(&.{ "-fPIC", "-shared" });

    const check = dso.check();
    check.checkInDynamicSymtab();
    check.checkContains("IFUNC GLOBAL DEFAULT foobar");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testIfuncFuncPtr(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-ifunc-func-ptr", "");

    const exe = cc(b, opts);
    exe.addCSource(
        \\typedef int Fn();
        \\int foo() __attribute__((ifunc("resolve_foo")));
        \\int real_foo() { return 3; }
        \\Fn *resolve_foo(void) {
        \\  return real_foo;
        \\}
    );
    exe.addCSource(
        \\typedef int Fn();
        \\int foo();
        \\Fn *get_foo() { return foo; }
    );
    exe.addCSource(
        \\#include <stdio.h>
        \\typedef int Fn();
        \\Fn *get_foo();
        \\int main() {
        \\  Fn *f = get_foo();
        \\  printf("%d\n", f());
        \\}
    );
    exe.addArg("-fPIC");

    const run = exe.run();
    run.expectStdOutEqual("3\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testIfuncNoPlt(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-ifunc-noplt", "");

    const exe = cc(b, opts);
    exe.addCSource(
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
    );
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

    const exe = cc(b, opts);
    exe.addCSource(
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
    );
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

    const exe = cc(b, opts);
    exe.addCSource(
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
    );
    exe.addArgs(&.{ "-fPIC", "-static-pie" });

    const run = exe.run();
    run.expectStdOutEqual("Hello world\n");
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkStart();
    check.checkExact("header");
    check.checkExact("type DYN");
    check.checkStart();
    check.checkExact("section headers");
    check.checkExact("name .dynamic");
    check.checkStart();
    check.checkExact("section headers");
    check.checkNotPresent("name .interp");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testImageBase(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-image-base", "");

    {
        const exe = cc(b, opts);
        exe.addHelloWorldMain();
        exe.addArgs(&.{ "-no-pie", "-Wl,-image-base,0x8000000" });

        const run = exe.run();
        run.expectHelloWorld();
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkStart();
        check.checkExact("section headers");
        check.checkExact("name .interp");
        check.checkExact("type PROGBITS");
        check.checkExtract("addr {addr}");
        check.checkComputeCompare("addr", .{ .op = .gte, .value = .{ .literal = 0x8000000 } });
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, opts);
        exe.addCSource("void _start() {}");
        exe.addArgs(&.{ "-no-pie", "-nostdlib", "-Wl,-image-base,0xffffffff8000000" });

        const check = exe.check();
        check.checkStart();
        check.checkExact("section headers");
        check.checkExact("name .interp");
        check.checkExact("type PROGBITS");
        check.checkExtract("addr {addr}");
        check.checkComputeCompare("addr", .{ .op = .gte, .value = .{ .literal = 0xffffffff8000000 } });
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testInitArrayOrder(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-init-array-order", "");

    const a_o = cc(b, opts);
    a_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((constructor(10000))) void init4() { printf("1"); }
    );
    a_o.addArg("-c");

    const b_o = cc(b, opts);
    b_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((constructor(1000))) void init3() { printf("2"); }
    );
    b_o.addArg("-c");

    const c_o = cc(b, opts);
    c_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((constructor)) void init1() { printf("3"); }
    );
    c_o.addArg("-c");

    const d_o = cc(b, opts);
    d_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((constructor)) void init2() { printf("4"); }
    );
    d_o.addArg("-c");

    const e_o = cc(b, opts);
    e_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((destructor(10000))) void fini4() { printf("5"); }
    );
    e_o.addArg("-c");

    const f_o = cc(b, opts);
    f_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((destructor(1000))) void fini3() { printf("6"); }
    );
    f_o.addArg("-c");

    const g_o = cc(b, opts);
    g_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((destructor)) void fini1() { printf("7"); }
    );
    g_o.addArg("-c");

    const h_o = cc(b, opts);
    h_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((destructor)) void fini2() { printf("8"); }
    );
    h_o.addArg("-c");

    const exe = cc(b, opts);
    exe.addEmptyMain();
    exe.addFileSource(a_o.out);
    exe.addFileSource(b_o.out);
    exe.addFileSource(c_o.out);
    exe.addFileSource(d_o.out);
    exe.addFileSource(e_o.out);
    exe.addFileSource(f_o.out);
    exe.addFileSource(g_o.out);
    exe.addFileSource(h_o.out);

    const run = exe.run();
    run.expectStdOutEqual("21348756");
    test_step.dependOn(run.step());

    return test_step;
}

fn testLargeAlignmentDso(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-large-alignment-dso", "");

    const dso = cc(b, opts);
    dso.addCSource(
        \\#include <stdio.h>
        \\#include <stdint.h>
        \\void hello() __attribute__((aligned(32768), section(".hello")));
        \\void world() __attribute__((aligned(32768), section(".world")));
        \\void hello() {
        \\  printf("Hello");
        \\}
        \\void world() {
        \\  printf(" world");
        \\}
        \\void greet() {
        \\  hello();
        \\  world();
        \\}
    );
    dso.addArgs(&.{ "-fPIC", "-ffunction-sections", "-shared" });
    const dso_out = dso.saveOutputAs("a.so");

    const check = dso.check();
    check.checkInSymtab();
    check.checkExtract("{addr1} {size1} {shndx1} FUNC GLOBAL DEFAULT hello");
    check.checkInSymtab();
    check.checkExtract("{addr2} {size2} {shndx2} FUNC GLOBAL DEFAULT world");
    check.checkComputeCompare("addr1 16 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.checkComputeCompare("addr2 16 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    test_step.dependOn(&check.step);

    const exe = cc(b, opts);
    exe.addCSource(
        \\void greet();
        \\int main() { greet(); }
    );
    exe.addFileSource(dso_out.file);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

    const run = exe.run();
    run.expectStdOutEqual("Hello world");
    test_step.dependOn(run.step());

    return test_step;
}

fn testLargeAlignmentExe(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-large-alignment-exe", "");

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include <stdio.h>
        \\#include <stdint.h>
        \\
        \\void hello() __attribute__((aligned(32768), section(".hello")));
        \\void world() __attribute__((aligned(32768), section(".world")));
        \\
        \\void hello() {
        \\  printf("Hello");
        \\}
        \\
        \\void world() {
        \\  printf(" world");
        \\}
        \\
        \\int main() {
        \\  hello();
        \\  world();
        \\}
    );
    exe.addArgs(&.{"-ffunction-sections"});

    const run = exe.run();
    run.expectStdOutEqual("Hello world");
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkInSymtab();
    check.checkExtract("{addr1} {size1} {shndx1} FUNC LOCAL DEFAULT hello");
    check.checkInSymtab();
    check.checkExtract("{addr2} {size2} {shndx2} FUNC LOCAL DEFAULT world");
    check.checkComputeCompare("addr1 16 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.checkComputeCompare("addr2 16 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    test_step.dependOn(&check.step);

    return test_step;
}

fn testLinkOrder(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-link-order", "");

    const obj = cc(b, opts);
    obj.addCSource("void foo() {}");
    obj.addArgs(&.{ "-fPIC", "-c" });
    const obj_out = obj.saveOutputAs("a.o");

    const dso = cc(b, opts);
    dso.addFileSource(obj_out.file);
    dso.addArg("-shared");
    const dso_out = dso.saveOutputAs("a.so");

    const lib = ar(b);
    lib.addFileSource(obj_out.file);
    const lib_out = lib.saveOutputAs("a.a");

    const main_o = cc(b, opts);
    main_o.addCSource(
        \\void foo();
        \\int main() {
        \\  foo();
        \\}
    );
    main_o.addArg("-c");
    const main_o_out = main_o.saveOutputAs("main.o");

    {
        const exe = cc(b, opts);
        exe.addFileSource(main_o_out.file);
        exe.addArg("-Wl,--as-needed");
        exe.addFileSource(dso_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);
        exe.addFileSource(lib_out.file);

        const check = exe.check();
        check.checkInDynamicSection();
        check.checkContains("a.so");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(main_o_out.file);
        exe.addArg("-Wl,--as-needed");
        exe.addFileSource(lib_out.file);
        exe.addFileSource(dso_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

        const check = exe.check();
        check.checkInDynamicSection();
        check.checkNotPresent("a.so");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testLinkerScript(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-linker-script", "");

    const dso = cc(b, opts);
    dso.addCSource("int foo() { return 42; }");
    dso.addArgs(&.{ "-fPIC", "-shared" });
    const dso_out = dso.saveOutputAs("libfoo.so");

    const scr = scr: {
        const wf = WriteFile.create(b);
        break :scr wf.add("script", "GROUP(AS_NEEDED(-lfoo))");
    };

    const exe = cc(b, opts);
    exe.addCSource(
        \\int foo();
        \\int main() {
        \\  return foo() - 42;
        \\}
    );
    exe.addFileSource(scr);
    exe.addPrefixedDirectorySource("-L", dso_out.dir);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testNoEhFrameHdr(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-no-eh-frame-hdr", "");

    const exe = cc(b, opts);
    exe.addEmptyMain();
    exe.addArgs(&.{"-Wl,--no-eh-frame-hdr"});

    const check = exe.check();
    check.checkStart();
    check.checkExact("section headers");
    check.checkNotPresent("name .eh_frame_hdr");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testPltGot(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-plt-got", "");

    const dso = cc(b, opts);
    dso.addCSource(
        \\#include <stdio.h>
        \\void ignore(void *foo) {}
        \\void hello() {
        \\  printf("Hello world\n");
        \\}
    );
    dso.addArgs(&.{ "-fPIC", "-shared" });
    const dso_out = dso.saveOutputAs("a.so");

    const exe = cc(b, opts);
    exe.addCSource(
        \\void ignore(void *);
        \\int hello();
        \\void foo() { ignore(hello); }
        \\int main() { hello(); }
    );
    exe.addFileSource(dso_out.file);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);
    exe.addArg("-fPIC");

    const run = exe.run();
    run.expectStdOutEqual("Hello world\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testPreinitArray(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-preinit-array", "");

    {
        const obj = cc(b, opts);
        obj.addCSource("void _start() {}");
        obj.addArg("-c");

        const exe = ld(b, opts);
        exe.addFileSource(obj.out);

        const check = exe.check();
        check.checkInDynamicSection();
        check.checkNotPresent("PREINIT_ARRAY");
    }

    {
        const exe = cc(b, opts);
        exe.addCSource(
            \\void preinit_fn() {}
            \\int main() {}
            \\__attribute__((section(".preinit_array")))
            \\void *preinit[] = { preinit_fn };
        );

        const check = exe.check();
        check.checkInDynamicSection();
        check.checkContains("PREINIT_ARRAY");
    }

    return test_step;
}

fn testPushPopState(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-push-pop-state", "");

    const a_so = cc(b, opts);
    a_so.addCSource("int foo = 1;");
    a_so.addArgs(&.{ "-fPIC", "-shared" });
    const a_so_out = a_so.saveOutputAs("a.so");

    const b_so = cc(b, opts);
    b_so.addCSource("int bar = 1;");
    b_so.addArgs(&.{ "-fPIC", "-shared" });
    const b_so_out = b_so.saveOutputAs("b.so");

    const exe = cc(b, opts);
    exe.addEmptyMain();
    exe.addArgs(&.{ "-Wl,--as-needed", "-Wl,--push-state", "-Wl,--no-as-needed" });
    exe.addFileSource(a_so_out.file);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", a_so_out.dir);
    exe.addArg("-Wl,--pop-state");
    exe.addFileSource(b_so_out.file);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", b_so_out.dir);

    const check = exe.check();
    check.checkInDynamicSection();
    check.checkContains("a.so");
    check.checkInDynamicSection();
    check.checkNotPresent("b.so");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testSharedAbsSymbol(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-shared-abs-symbol", "");

    const dso = cc(b, opts);
    dso.addAsmSource(
        \\.globl foo
        \\foo = 3;
    );
    dso.addArgs(&.{ "-fPIC", "-shared" });
    const dso_out = dso.saveOutputAs("a.so");

    const obj = cc(b, opts);
    obj.addCSource(
        \\#include <stdio.h>
        \\extern char foo;
        \\int main() { printf("foo=%p\n", &foo); }
    );
    obj.addArgs(&.{ "-fPIC", "-c" });

    {
        const exe = cc(b, opts);
        exe.addFileSource(obj.out);
        exe.addFileSource(dso_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);
        exe.addArg("-pie");

        const run = exe.run();
        run.expectStdOutEqual("foo=0x3\n");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkNotPresent("foo");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(obj.out);
        exe.addFileSource(dso_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);
        exe.addArg("-no-pie");

        const run = exe.run();
        run.expectStdOutEqual("foo=0x3\n");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkNotPresent("foo");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testStrip(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-strip", "");

    const obj = cc(b, opts);
    obj.addAsmSource(
        \\.globl _start, foo
        \\_start:
        \\foo:
        \\bar:
        \\.L.baz:
    );
    obj.addArgs(&.{ "-c", "-Wa,-L" });

    {
        const exe = ld(b, opts);
        exe.addFileSource(obj.out);

        const check = exe.check();
        check.checkStart();
        check.checkExact("symbol table");
        test_step.dependOn(&check.step);
    }

    {
        const exe = ld(b, opts);
        exe.addFileSource(obj.out);
        exe.addArg("--strip-all");

        const check = exe.check();
        check.checkStart();
        check.checkNotPresent("symbol table");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testTlsCommon(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-common", "");

    const a_o = cc(b, opts);
    a_o.addAsmSource(
        \\.globl foo
        \\.tls_common foo,4,4
    );
    a_o.addArg("-c");

    const b_o = cc(b, opts);
    b_o.addCSource(
        \\#include <stdio.h>
        \\extern _Thread_local int foo;
        \\int main() {
        \\  printf("foo=%d\n", foo);
        \\}
    );
    b_o.addArgs(&.{ "-c", "-std=c11" });

    const exe = cc(b, opts);
    exe.addFileSource(a_o.out);
    exe.addFileSource(b_o.out);

    const run = exe.run();
    run.expectStdOutEqual("foo=0\n");
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkStart();
    check.checkExact("section headers");
    check.checkExact("name .tls_common");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testTlsDesc(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-desc", "");

    const main_o = cc(b, opts);
    main_o.addCSource(
        \\#include <stdio.h>
        \\_Thread_local int foo;
        \\int get_foo();
        \\int get_bar();
        \\int main() {
        \\  foo = 42;
        \\  printf("%d %d\n", get_foo(), get_bar());
        \\  return 0;
        \\}
    );
    main_o.addArgs(&.{ "-c", "-fPIC", "-mtls-dialect=gnu2" });
    const main_o_out = main_o.saveOutputAs("main.o");

    const a_o = cc(b, opts);
    a_o.addCSource(
        \\extern _Thread_local int foo;
        \\int get_foo() {
        \\  return foo;
        \\}
        \\static _Thread_local int bar = 5;
        \\int get_bar() {
        \\  return bar;
        \\}
    );
    a_o.addArgs(&.{ "-c", "-fPIC", "-mtls-dialect=gnu2" });
    const a_o_out = a_o.saveOutputAs("a.o");

    const exp_stdout = "42 5\n";

    {
        const exe = cc(b, opts);
        exe.addFileSource(main_o_out.file);
        exe.addFileSource(a_o_out.file);

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(main_o_out.file);
        exe.addFileSource(a_o_out.file);
        exe.addArg("-Wl,-no-relax");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const dso = cc(b, opts);
        dso.addFileSource(a_o_out.file);
        dso.addArg("-shared");
        const dso_out = dso.saveOutputAs("a.so");

        const exe = cc(b, opts);
        exe.addFileSource(main_o_out.file);
        exe.addFileSource(dso_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const dso = cc(b, opts);
        dso.addFileSource(a_o_out.file);
        dso.addArgs(&.{ "-shared", "-Wl,-no-relax" });
        const dso_out = dso.saveOutputAs("a.so");

        const exe = cc(b, opts);
        exe.addFileSource(main_o_out.file);
        exe.addFileSource(dso_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);
        exe.addArg("-Wl,-no-relax");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsDescImport(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-desc-import", "");

    const dso = cc(b, opts);
    dso.addCSource(
        \\_Thread_local int foo = 5;
        \\_Thread_local int bar;
    );
    dso.addArgs(&.{ "-fPIC", "-shared", "-mtls-dialect=gnu2" });
    const dso_out = dso.saveOutputAs("a.so");

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include <stdio.h>
        \\extern _Thread_local int foo;
        \\extern _Thread_local int bar;
        \\int main() {
        \\  bar = 7;
        \\  printf("%d %d\n", foo, bar);
        \\}
    );
    exe.addArgs(&.{ "-fPIC", "-mtls-dialect=gnu2" });
    exe.addFileSource(dso_out.file);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

    const run = exe.run();
    run.expectStdOutEqual("5 7\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testTlsDescStatic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-desc-static", "");

    if (!opts.has_static) {
        skipTestStep(test_step);
        return test_step;
    }

    const main_o = cc(b, opts);
    main_o.addCSource(
        \\#include <stdio.h>
        \\extern _Thread_local int foo;
        \\int main() {
        \\  foo = 42;
        \\  printf("%d\n", foo);
        \\}
    );
    main_o.addArgs(&.{ "-c", "-fPIC", "-mtls-dialect=gnu2" });
    const main_o_out = main_o.saveOutputAs("main.o");

    const a_o = cc(b, opts);
    a_o.addCSource(
        \\_Thread_local int foo;
    );
    a_o.addArgs(&.{ "-c", "-fPIC", "-mtls-dialect=gnu2" });
    const a_o_out = a_o.saveOutputAs("a.o");

    const exp_stdout = "42\n";

    {
        const exe = cc(b, opts);
        exe.addFileSource(main_o_out.file);
        exe.addFileSource(a_o_out.file);
        exe.addArg("-static");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(main_o_out.file);
        exe.addFileSource(a_o_out.file);
        exe.addArgs(&.{ "-static", "-Wl,-no-relax" });

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsDfStaticTls(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-df-static-tls", "");

    const obj = cc(b, opts);
    obj.addCSource(
        \\#include <stdio.h>
        \\static _Thread_local int foo = 5;
        \\int bar() { return foo; }
    );
    obj.addArgs(&.{ "-fPIC", "-c", "-ftls-model=initial-exec" });

    {
        const dso = cc(b, opts);
        dso.addFileSource(obj.out);
        dso.addArgs(&.{ "-shared", "-Wl,-relax" });

        const check = dso.check();
        check.checkInDynamicSection();
        check.checkContains("STATIC_TLS");
        test_step.dependOn(&check.step);
    }

    {
        const dso = cc(b, opts);
        dso.addFileSource(obj.out);
        dso.addArgs(&.{ "-shared", "-Wl,-no-relax" });

        const check = dso.check();
        check.checkInDynamicSection();
        check.checkContains("STATIC_TLS");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testTlsDso(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-dso", "");

    const dso = cc(b, opts);
    dso.addCSource(
        \\extern _Thread_local int foo;
        \\_Thread_local int bar;
        \\int get_foo1() { return foo; }
        \\int get_bar1() { return bar; }
    );
    dso.addArgs(&.{ "-fPIC", "-shared" });
    const dso_out = dso.saveOutputAs("a.so");

    const exe = cc(b, opts);
    exe.addCSource(
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
    );
    exe.addFileSource(dso_out.file);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

    const run = exe.run();
    run.expectStdOutEqual("5 3 5 3 5 3\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testTlsGd(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-gd", "");

    const main_o = cc(b, opts);
    main_o.addCSource(
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
    );
    main_o.addArgs(&.{ "-c", "-fPIC" });
    const main_o_out = main_o.saveOutputAs("main.o");

    const a_o = cc(b, opts);
    a_o.addCSource(
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x3 = 3;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x5 = 5;
        \\int get_x5() { return x5; }
    );
    a_o.addArgs(&.{ "-c", "-fPIC" });
    const a_o_out = a_o.saveOutputAs("a.o");

    const b_o = cc(b, opts);
    b_o.addCSource(
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x4 = 4;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x6 = 6;
        \\int get_x6() { return x6; }
    );
    b_o.addArgs(&.{ "-c", "-fPIC" });
    const b_o_out = b_o.saveOutputAs("b.o");

    const exp_stdout = "1 2 3 4 5 6\n";

    const dso1 = cc(b, opts);
    dso1.addArg("-shared");
    dso1.addFileSource(a_o_out.file);
    const dso1_out = dso1.saveOutputAs("a.so");

    const dso2 = cc(b, opts);
    dso2.addArgs(&.{ "-shared", "-Wl,-no-relax" });
    dso2.addFileSource(b_o_out.file);
    const dso2_out = dso2.saveOutputAs("b.so");

    {
        const exe = cc(b, opts);
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
        const exe = cc(b, opts);
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
            const exe = cc(b, opts);
            exe.addFileSource(main_o_out.file);
            exe.addFileSource(a_o_out.file);
            exe.addFileSource(b_o_out.file);
            exe.addArg("-static");

            const run = exe.run();
            run.expectStdOutEqual(exp_stdout);
            test_step.dependOn(run.step());
        }

        {
            const exe = cc(b, opts);
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

fn testTlsGdNoPlt(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-gd-no-plt", "");

    const obj = cc(b, opts);
    obj.addCSource(
        \\#include <stdio.h>
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x1 = 1;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x2;
        \\__attribute__((tls_model("global-dynamic"))) extern _Thread_local int x3;
        \\__attribute__((tls_model("global-dynamic"))) extern _Thread_local int x4;
        \\int get_x5();
        \\int get_x6();
        \\int main() {
        \\  x2 = 2;
        \\
        \\  printf("%d %d %d %d %d %d\n", x1, x2, x3, x4, get_x5(), get_x6());
        \\  return 0;
        \\}
    );
    obj.addArgs(&.{ "-fPIC", "-fno-plt", "-c" });

    const a_so = cc(b, opts);
    a_so.addCSource(
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x3 = 3;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x5 = 5;
        \\int get_x5() { return x5; }
    );
    a_so.addArgs(&.{ "-fPIC", "-shared", "-fno-plt" });
    const a_so_out = a_so.saveOutputAs("a.so");

    const b_so = cc(b, opts);
    b_so.addCSource(
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x4 = 4;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x6 = 6;
        \\int get_x6() { return x6; }
    );
    b_so.addArgs(&.{ "-fPIC", "-shared", "-fno-plt", "-Wl,-no-relax" });
    const b_so_out = b_so.saveOutputAs("b.so");

    {
        const exe = cc(b, opts);
        exe.addFileSource(obj.out);
        exe.addFileSource(a_so_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", a_so_out.dir);
        exe.addFileSource(b_so_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", b_so_out.dir);

        const run = exe.run();
        run.expectStdOutEqual("1 2 3 4 5 6\n");
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(obj.out);
        exe.addFileSource(a_so_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", a_so_out.dir);
        exe.addFileSource(b_so_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", b_so_out.dir);
        exe.addArg("-Wl,-no-relax");

        const run = exe.run();
        run.expectStdOutEqual("1 2 3 4 5 6\n");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsGdToIe(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-gd-to-ie", "");

    const a_o = cc(b, opts);
    a_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x1 = 1;
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x2 = 2;
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x3;
        \\int foo() {
        \\  x3 = 3;
        \\
        \\  printf("%d %d %d\n", x1, x2, x3);
        \\  return 0;
        \\}
    );
    a_o.addArgs(&.{ "-c", "-fPIC" });

    const b_o = cc(b, opts);
    b_o.addCSource(
        \\int foo();
        \\int main() { foo(); }
    );
    b_o.addArgs(&.{ "-c", "-fPIC" });

    {
        const dso = cc(b, opts);
        dso.addFileSource(a_o.out);
        dso.addArg("-shared");
        const dso_out = dso.saveOutputAs("a.so");

        const exe = cc(b, opts);
        exe.addFileSource(b_o.out);
        exe.addFileSource(dso_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

        const run = exe.run();
        run.expectStdOutEqual("1 2 3\n");
        test_step.dependOn(run.step());
    }

    {
        const dso = cc(b, opts);
        dso.addFileSource(a_o.out);
        dso.addArgs(&.{ "-shared", "-Wl,-no-relax" });
        const dso_out = dso.saveOutputAs("a.so");

        const exe = cc(b, opts);
        exe.addFileSource(b_o.out);
        exe.addFileSource(dso_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

        const run = exe.run();
        run.expectStdOutEqual("1 2 3\n");
        test_step.dependOn(run.step());
    }

    {
        const dso = cc(b, opts);
        dso.addFileSource(a_o.out);
        dso.addArgs(&.{ "-shared", "-Wl,-z,nodlopen" });
        const dso_out = dso.saveOutputAs("a.so");

        const exe = cc(b, opts);
        exe.addFileSource(b_o.out);
        exe.addFileSource(dso_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

        const run = exe.run();
        run.expectStdOutEqual("1 2 3\n");
        test_step.dependOn(run.step());
    }

    {
        const dso = cc(b, opts);
        dso.addFileSource(a_o.out);
        dso.addArgs(&.{ "-shared", "-Wl,-z,nodlopen", "-Wl,-no-relax" });
        const dso_out = dso.saveOutputAs("a.so");

        const exe = cc(b, opts);
        exe.addFileSource(b_o.out);
        exe.addFileSource(dso_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

        const run = exe.run();
        run.expectStdOutEqual("1 2 3\n");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsIe(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-ie", "");

    const dso = cc(b, opts);
    dso.addCSource(
        \\#include <stdio.h>
        \\__attribute__((tls_model("initial-exec"))) static _Thread_local int foo;
        \\__attribute__((tls_model("initial-exec"))) static _Thread_local int bar;
        \\void set() {
        \\  foo = 3;
        \\  bar = 5;
        \\}
        \\void print() {
        \\  printf("%d %d ", foo, bar);
        \\}
    );
    dso.addArgs(&.{ "-shared", "-fPIC" });
    const dso_out = dso.saveOutputAs("a.so");

    const main_o = cc(b, opts);
    main_o.addCSource(
        \\#include <stdio.h>
        \\_Thread_local int baz;
        \\void set();
        \\void print();
        \\int main() {
        \\  baz = 7;
        \\  print();
        \\  set();
        \\  print();
        \\  printf("%d\n", baz);
        \\}
    );
    main_o.addArg("-c");
    const main_o_out = main_o.saveOutputAs("main.o");

    const exp_stdout = "0 0 3 5 7\n";

    {
        const exe = cc(b, opts);
        exe.addFileSource(main_o_out.file);
        exe.addFileSource(dso_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(main_o_out.file);
        exe.addFileSource(dso_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);
        exe.addArg("-Wl,-no-relax");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsLargeAlignment(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-large-alignment", "");

    const a_o = cc(b, opts);
    a_o.addCSource(
        \\__attribute__((section(".tdata1")))
        \\_Thread_local int x = 42;
    );
    a_o.addArgs(&.{ "-fPIC", "-std=c11", "-c" });

    const b_o = cc(b, opts);
    b_o.addCSource(
        \\__attribute__((section(".tdata2")))
        \\_Alignas(256) _Thread_local int y[] = { 1, 2, 3 };
    );
    b_o.addArgs(&.{ "-fPIC", "-std=c11", "-c" });

    const c_o = cc(b, opts);
    c_o.addCSource(
        \\#include <stdio.h>
        \\extern _Thread_local int x;
        \\extern _Thread_local int y[];
        \\int main() {
        \\  printf("%d %d %d %d\n", x, y[0], y[1], y[2]);
        \\}
    );
    c_o.addArgs(&.{ "-fPIC", "-c" });

    {
        const dso = cc(b, opts);
        dso.addFileSource(a_o.out);
        dso.addFileSource(b_o.out);
        dso.addArg("-shared");
        const dso_out = dso.saveOutputAs("a.so");

        const exe = cc(b, opts);
        exe.addFileSource(c_o.out);
        exe.addFileSource(dso_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

        const run = exe.run();
        run.expectStdOutEqual("42 1 2 3\n");
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(a_o.out);
        exe.addFileSource(b_o.out);
        exe.addFileSource(c_o.out);

        const run = exe.run();
        run.expectStdOutEqual("42 1 2 3\n");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsLargeStaticImage(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-large-static-image", "");

    const exe = cc(b, opts);
    exe.addCSource("_Thread_local int x[] = { 1, 2, 3, [10000] = 5 };");
    exe.addCSource(
        \\#include <stdio.h>
        \\extern _Thread_local int x[];
        \\int main() {
        \\  printf("%d %d %d %d %d\n", x[0], x[1], x[2], x[3], x[10000]);
        \\}
    );
    exe.addArg("-fPIC");

    const run = exe.run();
    run.expectStdOutEqual("1 2 3 0 5\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testTlsLd(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-ld", "");

    const main_o = cc(b, opts);
    main_o.addCSource(
        \\#include <stdio.h>
        \\extern _Thread_local int foo;
        \\static _Thread_local int bar;
        \\int *get_foo_addr() { return &foo; }
        \\int *get_bar_addr() { return &bar; }
        \\int main() {
        \\  bar = 5;
        \\  printf("%d %d %d %d\n", *get_foo_addr(), *get_bar_addr(), foo, bar);
        \\  return 0;
        \\}
    );
    main_o.addArgs(&.{ "-c", "-fPIC", "-ftls-model=local-dynamic" });
    const main_o_out = main_o.saveOutputAs("main.o");

    const a_o = cc(b, opts);
    a_o.addCSource("_Thread_local int foo = 3;");
    a_o.addArgs(&.{ "-c", "-fPIC", "-ftls-model=local-dynamic" });
    const a_o_out = a_o.saveOutputAs("a.o");

    const exp_stdout = "3 5 3 5\n";

    {
        const exe = cc(b, opts);
        exe.addFileSource(main_o_out.file);
        exe.addFileSource(a_o_out.file);
        exe.addArg("-Wl,-relax");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(main_o_out.file);
        exe.addFileSource(a_o_out.file);
        exe.addArg("-Wl,-no-relax");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsLdDso(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-ld-dso", "");

    const dso = cc(b, opts);
    dso.addCSource(
        \\static _Thread_local int def, def1;
        \\int f0() { return ++def; }
        \\int f1() { return ++def1 + def; }
    );
    dso.addArgs(&.{ "-shared", "-fPIC", "-ftls-model=local-dynamic" });
    const dso_out = dso.saveOutputAs("a.so");

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include <stdio.h>
        \\extern int f0();
        \\extern int f1();
        \\int main() {
        \\  printf("%d %d\n", f0(), f1());
        \\  return 0;
        \\}
    );
    exe.addFileSource(dso_out.file);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

    const run = exe.run();
    run.expectStdOutEqual("1 1\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testTlsLdNoPlt(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-ld-no-plt", "");

    const a_o = cc(b, opts);
    a_o.addCSource(
        \\#include <stdio.h>
        \\extern _Thread_local int foo;
        \\static _Thread_local int bar;
        \\int *get_foo_addr() { return &foo; }
        \\int *get_bar_addr() { return &bar; }
        \\int main() {
        \\  bar = 5;
        \\
        \\  printf("%d %d %d %d\n", *get_foo_addr(), *get_bar_addr(), foo, bar);
        \\  return 0;
        \\}
    );
    a_o.addArgs(&.{ "-fPIC", "-ftls-model=local-dynamic", "-fno-plt", "-c" });

    const b_o = cc(b, opts);
    b_o.addCSource("_Thread_local int foo = 3;");
    b_o.addArgs(&.{ "-fPIC", "-ftls-model=local-dynamic", "-fno-plt", "-c" });

    {
        const exe = cc(b, opts);
        exe.addFileSource(a_o.out);
        exe.addFileSource(b_o.out);

        const run = exe.run();
        run.expectStdOutEqual("3 5 3 5\n");
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(a_o.out);
        exe.addFileSource(b_o.out);
        exe.addArg("-Wl,-no-relax");

        const run = exe.run();
        run.expectStdOutEqual("3 5 3 5\n");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsNoPic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-no-pic", "");

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include <stdio.h>
        \\__attribute__((tls_model("global-dynamic"))) extern _Thread_local int foo;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int bar;
        \\int *get_foo_addr() { return &foo; }
        \\int *get_bar_addr() { return &bar; }
        \\int main() {
        \\  foo = 3;
        \\  bar = 5;
        \\
        \\  printf("%d %d %d %d\n", *get_foo_addr(), *get_bar_addr(), foo, bar);
        \\  return 0;
        \\}
    );
    exe.addCSource(
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int foo;
    );

    const run = exe.run();
    run.expectStdOutEqual("3 5 3 5\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testTlsOffsetAlignment(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-offset-alignment", "");

    const dso = cc(b, opts);
    dso.addCSource(
        \\#include <assert.h>
        \\#include <stdlib.h>
        \\
        \\// .tdata
        \\_Thread_local int x = 42;
        \\// .tbss
        \\__attribute__ ((aligned(64)))
        \\_Thread_local int y = 0;
        \\
        \\void *verify(void *unused) {
        \\  assert((unsigned long)(&y) % 64 == 0);
        \\  return NULL;
        \\}
    );
    dso.addArgs(&.{ "-fPIC", "-shared" });
    const dso_out = dso.saveOutputAs("a.so");

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include <pthread.h>
        \\#include <dlfcn.h>
        \\#include <assert.h>
        \\void *(*verify)(void *);
        \\
        \\int main() {
        \\  void *handle = dlopen("a.so", RTLD_NOW);
        \\  assert(handle);
        \\  *(void**)(&verify) = dlsym(handle, "verify");
        \\  assert(verify);
        \\
        \\  pthread_t thread;
        \\
        \\  verify(NULL);
        \\
        \\  pthread_create(&thread, NULL, verify, NULL);
        \\  pthread_join(thread, NULL);
        \\}
    );
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);
    exe.addArgs(&.{ "-fPIC", "-ldl", "-lpthread" });

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testTlsPic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-pic", "");

    const obj = cc(b, opts);
    obj.addCSource(
        \\#include <stdio.h>
        \\__attribute__((tls_model("global-dynamic"))) extern _Thread_local int foo;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int bar;
        \\int *get_foo_addr() { return &foo; }
        \\int *get_bar_addr() { return &bar; }
        \\int main() {
        \\  bar = 5;
        \\
        \\  printf("%d %d %d %d\n", *get_foo_addr(), *get_bar_addr(), foo, bar);
        \\  return 0;
        \\}
    );
    obj.addArgs(&.{ "-fPIC", "-c" });

    const exe = cc(b, opts);
    exe.addCSource(
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int foo = 3;
    );
    exe.addFileSource(obj.out);

    const run = exe.run();
    run.expectStdOutEqual("3 5 3 5\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testTlsSmallAlignment(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-small-alignment", "");

    const a_o = cc(b, opts);
    a_o.addAsmSource(
        \\.text
        \\.byte 0
    );
    a_o.addArgs(&.{ "-c", "-fPIC" });

    const b_o = cc(b, opts);
    b_o.addCSource("_Thread_local char x = 42;");
    b_o.addArgs(&.{ "-fPIC", "-std=c11", "-c" });

    const c_o = cc(b, opts);
    c_o.addCSource(
        \\#include <stdio.h>
        \\extern _Thread_local char x;
        \\int main() {
        \\  printf("%d\n", x);
        \\}
    );
    c_o.addArgs(&.{ "-fPIC", "-c" });

    {
        const exe = cc(b, opts);
        exe.addFileSource(a_o.out);
        exe.addFileSource(b_o.out);
        exe.addFileSource(c_o.out);

        const run = exe.run();
        run.expectStdOutEqual("42\n");
        test_step.dependOn(run.step());
    }

    {
        const dso = cc(b, opts);
        dso.addFileSource(a_o.out);
        dso.addFileSource(b_o.out);
        dso.addArg("-shared");
        const dso_out = dso.saveOutputAs("a.so");

        const exe = cc(b, opts);
        exe.addFileSource(c_o.out);
        exe.addFileSource(dso_out.file);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso_out.dir);

        const run = exe.run();
        run.expectStdOutEqual("42\n");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsStatic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-static", "");

    if (!opts.has_static) {
        skipTestStep(test_step);
        return test_step;
    }

    const exe = cc(b, opts);
    exe.addCSource(
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
    );
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

fn testZNow(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-z-now", "");

    const obj = cc(b, opts);
    obj.addEmptyMain();
    obj.addArgs(&.{ "-fPIC", "-c" });

    {
        const dso = cc(b, opts);
        dso.addFileSource(obj.out);
        dso.addArgs(&.{ "-shared", "-Wl,-z,now" });

        const check = dso.check();
        check.checkInDynamicSection();
        check.checkContains("NOW");
        test_step.dependOn(&check.step);
    }

    {
        const dso = cc(b, opts);
        dso.addFileSource(obj.out);
        dso.addArgs(&.{ "-shared", "-Wl,-z,now", "-Wl,-z,lazy" });

        const check = dso.check();
        check.checkInDynamicSection();
        check.checkNotPresent("NOW");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn cc(b: *Build, opts: Options) SysCmd {
    const cmd = Run.create(b, "cc");
    cmd.addArgs(&.{ "cc", "-fno-lto" });
    cmd.addArg("-o");
    const out = cmd.addOutputFileArg("a.out");
    cmd.addPrefixedDirectorySourceArg("-B", opts.zld.dir);
    return .{ .cmd = cmd, .out = out };
}

fn ar(b: *Build) SysCmd {
    const cmd = Run.create(b, "ar");
    cmd.addArgs(&.{ "ar", "rcs" });
    const out = cmd.addOutputFileArg("a.out");
    return .{ .cmd = cmd, .out = out };
}

fn ld(b: *Build, opts: Options) SysCmd {
    const cmd = Run.create(b, "ld");
    cmd.addFileSourceArg(opts.zld.file);
    cmd.addArg("-o");
    const out = cmd.addOutputFileArg("a.out");
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
const WriteFile = Step.WriteFile;
