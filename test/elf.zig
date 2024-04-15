pub fn addElfTests(b: *Build, options: common.Options) *Step {
    const elf_step = b.step("test-elf", "Run ELF tests");

    if (builtin.target.ofmt != .elf) return skipTestStep(elf_step);

    const opts = Options{
        .zld = options.zld,
        .is_musl = options.is_musl,
        .has_zig = options.has_zig,
        .has_static = options.has_static,
        .cc_override = options.cc_override,
        .system_compiler = options.system_compiler,
    };

    elf_step.dependOn(testAbsSymbols(b, opts));
    elf_step.dependOn(testAllowMultipleDefinitions(b, opts));
    elf_step.dependOn(testAsNeeded(b, opts));
    elf_step.dependOn(testCanonicalPlt(b, opts));
    elf_step.dependOn(testComment(b, opts));
    elf_step.dependOn(testCommon(b, opts));
    elf_step.dependOn(testCommonArchive(b, opts));
    elf_step.dependOn(testCopyrel(b, opts));
    elf_step.dependOn(testCopyrelAlias(b, opts));
    elf_step.dependOn(testCopyrelAlignment(b, opts));
    elf_step.dependOn(testDsoPlt(b, opts));
    elf_step.dependOn(testDsoUndef(b, opts));
    elf_step.dependOn(testEmptyObject(b, opts));
    elf_step.dependOn(testEntryPoint(b, opts));
    elf_step.dependOn(testExecStack(b, opts));
    elf_step.dependOn(testExportDynamic(b, opts));
    elf_step.dependOn(testExportSymbolsFromExe(b, opts));
    elf_step.dependOn(testEmitRelocatable(b, opts));
    elf_step.dependOn(testFuncAddress(b, opts));
    elf_step.dependOn(testGcSections(b, opts));
    elf_step.dependOn(testHelloDynamic(b, opts));
    elf_step.dependOn(testHelloPie(b, opts));
    elf_step.dependOn(testHelloStatic(b, opts));
    elf_step.dependOn(testHiddenWeakUndef(b, opts));
    elf_step.dependOn(testIfuncAlias(b, opts));
    elf_step.dependOn(testIfuncDlopen(b, opts));
    elf_step.dependOn(testIfuncDso(b, opts));
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
    elf_step.dependOn(testLargeBss(b, opts));
    elf_step.dependOn(testLinkOrder(b, opts));
    elf_step.dependOn(testLinkerScript(b, opts));
    elf_step.dependOn(testMergeStrings(b, opts));
    elf_step.dependOn(testNoEhFrameHdr(b, opts));
    elf_step.dependOn(testPltGot(b, opts));
    elf_step.dependOn(testPreinitArray(b, opts));
    elf_step.dependOn(testPushPopState(b, opts));
    elf_step.dependOn(testRelocatableArchive(b, opts));
    elf_step.dependOn(testRelocatableEhFrame(b, opts));
    elf_step.dependOn(testRelocatableMergeStrings(b, opts));
    elf_step.dependOn(testRelocatableNoEhFrame(b, opts));
    elf_step.dependOn(testSectionStart(b, opts));
    elf_step.dependOn(testSharedAbsSymbol(b, opts));
    elf_step.dependOn(testStrip(b, opts));
    elf_step.dependOn(testThunks(b, opts));
    elf_step.dependOn(testThunks2(b, opts));
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
    elf_step.dependOn(testTlsLargeTbss(b, opts));
    elf_step.dependOn(testTlsLargeStaticImage(b, opts));
    elf_step.dependOn(testTlsLd(b, opts));
    elf_step.dependOn(testTlsLdDso(b, opts));
    elf_step.dependOn(testTlsLdNoPlt(b, opts));
    elf_step.dependOn(testTlsNoPic(b, opts));
    elf_step.dependOn(testTlsOffsetAlignment(b, opts));
    elf_step.dependOn(testTlsPic(b, opts));
    elf_step.dependOn(testTlsSmallAlignment(b, opts));
    elf_step.dependOn(testTlsStatic(b, opts));
    elf_step.dependOn(testWeakExportDso(b, opts));
    elf_step.dependOn(testWeakExportExe(b, opts));
    elf_step.dependOn(testWeakUndefDso(b, opts));
    elf_step.dependOn(testZNow(b, opts));
    elf_step.dependOn(testZStackSize(b, opts));
    elf_step.dependOn(testZText(b, opts));

    return elf_step;
}

fn testAbsSymbols(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-abs-symbols", "");

    const obj = cc(b, "a.o", opts);
    obj.addAsmSource(
        \\.globl foo
        \\foo = 0x800008
    );
    obj.addArg("-c");

    const exe = cc(b, "a.out", opts);
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
        \\extern int foo;
        \\int main() {
        \\  struct sigaction act;
        \\  act.sa_flags = SA_SIGINFO | SA_RESETHAND;
        \\  act.sa_sigaction = handler;
        \\  sigemptyset(&act.sa_mask);
        \\  sigaction(SIGSEGV, &act, 0);
        \\  foo = 5;
        \\}
    );
    exe.addArgs(&.{ "-fno-PIC", "-no-pie" });
    exe.addFileSource(obj.getFile());

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testAllowMultipleDefinitions(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-allow-multiple-definitions", "");

    const a_o = cc(b, "a.o", opts);
    a_o.addCSource("int main() { return 0; }");
    a_o.addArg("-c");

    const b_o = cc(b, "b.o", opts);
    b_o.addCSource("int main() { return 1; }");
    b_o.addArg("-c");

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(a_o.getFile());
        exe.addFileSource(b_o.getFile());
        exe.addArg("-Wl,--allow-multiple-definition");

        const run = exe.run();
        test_step.dependOn(run.step());
    }
    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(a_o.getFile());
        exe.addFileSource(b_o.getFile());
        exe.addArg("-Wl,-z,muldefs");

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testAsNeeded(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-as-needed", "");

    const main_o = cc(b, "main.o", opts);
    main_o.addCSource(
        \\#include <stdio.h>
        \\int baz();
        \\int main() {
        \\  printf("%d\n", baz());
        \\  return 0;
        \\}
    );
    main_o.addArg("-c");

    const libfoo = cc(b, "libfoo.so", opts);
    libfoo.addCSource("int foo() { return 42; }");
    libfoo.addArgs(&.{ "-shared", "-fPIC", "-Wl,-soname,libfoo.so" });

    const libbar = cc(b, "libbar.so", opts);
    libbar.addCSource("int bar() { return 42; }");
    libbar.addArgs(&.{ "-shared", "-fPIC", "-Wl,-soname,libbar.so" });

    const libbaz = cc(b, "libbaz.so", opts);
    libbaz.addCSource(
        \\int foo();
        \\int baz() { return foo(); }
    );
    libbaz.addArgs(&.{ "-shared", "-fPIC", "-Wl,-soname,libbaz.so", "-lfoo" });
    libbaz.addPrefixedDirectorySource("-L", libfoo.getDir());

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addArg("-Wl,--no-as-needed");
        exe.addFileSource(libfoo.getFile());
        exe.addFileSource(libbar.getFile());
        exe.addFileSource(libbaz.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libfoo.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libbar.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libbaz.getDir());

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
        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addArg("-Wl,--as-needed");
        exe.addFileSource(libfoo.getFile());
        exe.addFileSource(libbar.getFile());
        exe.addFileSource(libbaz.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libfoo.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libbar.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libbaz.getDir());

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

    const dso = cc(b, "a.so", opts);
    dso.addCSource(
        \\void *foo() {
        \\  return foo;
        \\}
        \\void *bar() {
        \\  return bar;
        \\}
    );
    dso.addArgs(&.{ "-fPIC", "-shared" });

    const b_o = cc(b, "b.o", opts);
    b_o.addCSource(
        \\void *bar();
        \\void *baz() {
        \\  return bar;
        \\}
    );
    b_o.addArgs(&.{ "-fPIC", "-c" });

    const main_o = cc(b, "main.o", opts);
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

    const exe = cc(b, "main", opts);
    exe.addFileSource(main_o.getFile());
    exe.addFileSource(b_o.getFile());
    exe.addFileSource(dso.getFile());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());
    exe.addArg("-no-pie");

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testComment(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-comment", "");

    const exe = cc(b, "a.out", opts);
    exe.addHelloWorldMain();

    const check = exe.check();
    check.dumpSection(".comment");
    check.checkContains("ld.zld");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testCommon(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-common", "");

    const exe = cc(b, "a.out", opts);
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

    const a_o = cc(b, "a.o", opts);
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

    const b_o = cc(b, "b.o", opts);
    b_o.addCSource("int foo = 5;");
    b_o.addArgs(&.{ "-fcommon", "-c" });

    {
        const c_o = cc(b, "c.o", opts);
        c_o.addCSource(
            \\int bar;
            \\int two() { return 2; }
        );
        c_o.addArgs(&.{ "-fcommon", "-c" });

        const d_o = cc(b, "d.o", opts);
        d_o.addCSource("int baz;");
        d_o.addArgs(&.{ "-fcommon", "-c" });

        const lib = ar(b, "libe.a");
        lib.addFileSource(b_o.getFile());
        lib.addFileSource(c_o.getFile());
        lib.addFileSource(d_o.getFile());

        const exe = cc(b, "a.out", opts);
        exe.addFileSource(a_o.getFile());
        exe.addFileSource(lib.getFile());

        const run = exe.run();
        run.expectStdOutEqual("5 0 0 -1\n");
        test_step.dependOn(run.step());
    }

    {
        const e_o = cc(b, "e.o", opts);
        e_o.addCSource(
            \\int bar = 0;
            \\int baz = 7;
            \\int two() { return 2; }
        );
        e_o.addArgs(&.{ "-fcommon", "-c" });

        const lib = ar(b, "libe.a");
        lib.addFileSource(b_o.getFile());
        lib.addFileSource(e_o.getFile());

        const exe = cc(b, "a.out", opts);
        exe.addFileSource(a_o.getFile());
        exe.addFileSource(lib.getFile());

        const run = exe.run();
        run.expectStdOutEqual("5 0 7 2\n");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testCopyrel(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-copyrel", "");

    const dso = cc(b, "liba.so", opts);
    dso.addArgs(&.{ "-fPIC", "-shared" });
    dso.addCSource(
        \\int foo = 3;
        \\int bar = 5;
    );

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\#include<stdio.h>
        \\extern int foo, bar;
        \\int main() {
        \\  printf("%d %d\n", foo, bar);
        \\  return 0;
        \\}
    );
    exe.addArg("-la");
    exe.addPrefixedDirectorySource("-L", dso.getDir());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

    const run = exe.run();
    run.expectStdOutEqual("3 5\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testCopyrelAlias(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-copyrel-alias", "");

    const dso = cc(b, "c.so", opts);
    dso.addArgs(&.{ "-fPIC", "-shared" });
    dso.addCSource(
        \\int bruh = 31;
        \\int foo = 42;
        \\extern int bar __attribute__((alias("foo")));
        \\extern int baz __attribute__((alias("foo")));
    );

    const exe = cc(b, "a.out", opts);
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
    exe.addFileSource(dso.getFile());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

    const run = exe.run();
    run.expectStdOutEqual("42 42 1\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testCopyrelAlignment(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-copyrel-alignment", "");

    const a_so = cc(b, "a.so", opts);
    a_so.addCSource("__attribute__((aligned(32))) int foo = 5;");
    a_so.addArgs(&.{ "-shared", "-fPIC" });

    const b_so = cc(b, "b.so", opts);
    b_so.addCSource("__attribute__((aligned(8))) int foo = 5;");
    b_so.addArgs(&.{ "-shared", "-fPIC" });

    const c_so = cc(b, "c.so", opts);
    c_so.addCSource("__attribute__((aligned(256))) int foo = 5;");
    c_so.addArgs(&.{ "-shared", "-fPIC" });

    const obj = cc(b, "main.o", opts);
    obj.addCSource(
        \\#include <stdio.h>
        \\extern int foo;
        \\int main() { printf("%d\n", foo); }
    );
    obj.addArgs(&.{ "-c", "-fno-PIE" });

    const exp_stdout = "5\n";

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(obj.getFile());
        exe.addFileSource(a_so.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", a_so.getDir());
        exe.addArg("-no-pie");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("section headers");
        check.checkExact("name .copyrel");
        check.checkExact("addralign 20");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(obj.getFile());
        exe.addFileSource(b_so.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", b_so.getDir());
        exe.addArg("-no-pie");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("section headers");
        check.checkExact("name .copyrel");
        check.checkExact("addralign 8");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(obj.getFile());
        exe.addFileSource(c_so.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", c_so.getDir());
        exe.addArg("-no-pie");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("section headers");
        check.checkExact("name .copyrel");
        check.checkExact("addralign 100");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testDsoPlt(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-dso-plt", "");

    const dso = cc(b, "liba.so", opts);
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

    const exe = cc(b, "a.out", opts);
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
    exe.addPrefixedDirectorySource("-L", dso.getDir());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

    const run = exe.run();
    run.expectStdOutEqual("Hello WORLD\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testDsoUndef(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-dso-undef", "");

    const dso = cc(b, "a.so", opts);
    dso.addCSource(
        \\extern int foo;
        \\int bar = 5;
        \\int baz() { return foo; }
    );
    dso.addArgs(&.{ "-shared", "-fPIC" });

    const obj = cc(b, "b.o", opts);
    obj.addCSource("int foo = 3;");
    obj.addArg("-c");

    const lib = ar(b, "c.a");
    lib.addFileSource(obj.getFile());

    const exe = cc(b, "a.out", opts);
    exe.addFileSource(dso.getFile());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());
    exe.addFileSource(lib.getFile());
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

    const exe = cc(b, "a.out", opts);
    exe.addHelloWorldMain();
    exe.addCSource("");

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    return test_step;
}

fn testEntryPoint(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-entry-point", "");

    const a_o = cc(b, "a.o", opts);
    a_o.addAsmSource(
        \\.globl foo, bar
        \\foo = 0x1000
        \\bar = 0x2000
    );
    a_o.addArg("-c");

    const b_o = cc(b, "b.o", opts);
    b_o.addEmptyMain();
    b_o.addArg("-c");

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(a_o.getFile());
        exe.addFileSource(b_o.getFile());
        exe.addArg("-Wl,-e,foo");

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("header");
        check.checkExact("entry 1000");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(a_o.getFile());
        exe.addFileSource(b_o.getFile());
        exe.addArg("-Wl,-e,bar");

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("header");
        check.checkExact("entry 2000");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testExecStack(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-exec-stack", "");

    const obj = cc(b, "a.o", opts);
    obj.addEmptyMain();
    obj.addArg("-c");

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(obj.getFile());
        exe.addArg("-Wl,-z,execstack");

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("program headers");
        check.checkExact("type GNU_STACK");
        check.checkExact("flags RWE");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(obj.getFile());
        exe.addArgs(&.{ "-Wl,-z,execstack", "-Wl,-z,noexecstack" });

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("program headers");
        check.checkExact("type GNU_STACK");
        check.checkExact("flags RW");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(obj.getFile());

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("program headers");
        check.checkExact("type GNU_STACK");
        check.checkExact("flags RW");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testExportDynamic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-export-dynamic", "");

    const obj = cc(b, "a.o", opts);
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

    const dso = cc(b, "a.so", opts);
    dso.addCSource("");
    dso.addArgs(&.{ "-fPIC", "-shared" });

    const exe = ld(b, "a.out", opts);
    exe.addFileSource(obj.getFile());
    exe.addFileSource(dso.getFile());
    exe.addArg("-rpath");
    exe.addDirectorySource(dso.getDir());
    exe.addArg("--export-dynamic");

    const check = exe.check();
    check.checkInDynamicSymtab();
    check.checkContains("bar");
    check.checkInDynamicSymtab();
    check.checkContains("_start");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testExportSymbolsFromExe(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-export-symbols-from-exe", "");

    const dso = cc(b, "a.so", opts);
    dso.addCSource(
        \\void expfn1();
        \\void expfn2() {}
        \\
        \\void foo() {
        \\  expfn1();
        \\}
    );
    dso.addArgs(&.{ "-fPIC", "-shared" });

    const exe = cc(b, "a.out", opts);
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
    exe.addFileSource(dso.getFile());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

    const check = exe.check();
    check.checkInDynamicSymtab();
    check.checkContains("expfn2");
    check.checkInDynamicSymtab();
    check.checkContains("expfn1");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testEmitRelocatable(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-emit-relocatable", "");

    const obj1 = cc(b, "a.o", opts);
    obj1.addCSource(
        \\#include <stdio.h>
        \\extern int bar;
        \\int foo() {
        \\   return bar;
        \\}
        \\void printFoo() {
        \\    printf("foo=%d\n", foo());
        \\}
    );
    obj1.addArgs(&.{ "-c", "-ffunction-sections" });

    const obj2 = cc(b, "b.o", opts);
    obj2.addCSource(
        \\#include <stdio.h>
        \\int bar = 42;
        \\void printBar() {
        \\    printf("bar=%d\n", bar);
        \\}
    );
    obj2.addArgs(&.{"-c"});

    const obj3 = ld(b, "c.o", opts);
    obj3.addFileSource(obj1.getFile());
    obj3.addFileSource(obj2.getFile());
    obj3.addArg("-r");

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\#include <stdio.h>
        \\void printFoo();
        \\void printBar();
        \\int main() {
        \\  printFoo();
        \\  printBar();
        \\}
    );
    exe.addFileSource(obj3.getFile());

    const run = exe.run();
    run.expectStdOutEqual(
        \\foo=42
        \\bar=42
        \\
    );
    test_step.dependOn(run.step());

    return test_step;
}

fn testFuncAddress(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-func-address", "");

    const dso = cc(b, "a.so", opts);
    dso.addCSource("void fn() {}");
    dso.addArgs(&.{ "-fPIC", "-shared" });

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\#include <assert.h>
        \\typedef void Func();
        \\void fn();
        \\Func *const ptr = fn;
        \\int main() {
        \\  assert(fn == ptr);
        \\}
    );
    exe.addFileSource(dso.getFile());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());
    exe.addArgs(&.{ "-fno-PIC", "-no-pie" });

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testGcSections(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-gc-sections", "");

    const obj = cc(b, "a.o", opts);
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

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(obj.getFile());

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
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(obj.getFile());
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

    const exe = cc(b, "a.out", opts);
    exe.addHelloWorldMain();
    exe.addArg("-no-pie");

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("header");
    check.checkExact("type EXEC");
    check.checkInHeaders();
    check.checkExact("section headers");
    check.checkExact("name .dynamic");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testHelloPie(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-hello-pie", "");

    const exe = cc(b, "a.out", opts);
    exe.addHelloWorldMain();
    exe.addArgs(&.{ "-fPIC", "-pie" });

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("header");
    check.checkExact("type DYN");
    check.checkInHeaders();
    check.checkExact("section headers");
    check.checkExact("name .dynamic");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testHelloStatic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-hello-static", "");

    if (!opts.has_static) return skipTestStep(test_step);

    const exe = cc(b, "a.out", opts);
    exe.addHelloWorldMain();
    exe.addArg("-static");

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("header");
    check.checkExact("type EXEC");
    check.checkInHeaders();
    check.checkExact("section headers");
    check.checkNotPresent("name .dynamic");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testHiddenWeakUndef(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-hidden-weak-undef", "");

    const dso = cc(b, "a.so", opts);
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

    if (opts.is_musl) return skipTestStep(test_step);

    const exe = cc(b, "a.out", opts);
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

    if (opts.is_musl) return skipTestStep(test_step);

    const dso = cc(b, "a.so", opts);
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

    const exe = cc(b, "a.out", opts);
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
    exe.addFileSource(dso.getFile());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());
    exe.addArgs(&.{ "-fno-PIE", "-no-pie", "-ldl" });

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testIfuncDso(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-ifunc-dso", "");

    if (opts.is_musl) return skipTestStep(test_step);

    const dso = cc(b, "liba.so", opts);
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

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\void foobar(void);
        \\int main() {
        \\  foobar();
        \\}
    );
    exe.addArg("-la");
    exe.addPrefixedDirectorySource("-L", dso.getDir());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

    const run = exe.run();
    run.expectStdOutEqual("Hello world\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testIfuncDynamic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-ifunc-dynamic", "");

    if (opts.is_musl) return skipTestStep(test_step);

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
        const exe = cc(b, "a.out", opts);
        exe.addCSource(main_c);
        exe.addArg("-Wl,-z,lazy");

        const run = exe.run();
        run.expectStdOutEqual("Hello world\n");
        test_step.dependOn(run.step());
    }
    {
        const exe = cc(b, "a.out", opts);
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

    if (opts.is_musl) return skipTestStep(test_step);

    const dso = cc(b, "a.so", opts);
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

    if (opts.is_musl) return skipTestStep(test_step);

    const exe = cc(b, "a.out", opts);
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

    if (opts.is_musl) return skipTestStep(test_step);

    const exe = cc(b, "a.out", opts);
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

    if (opts.is_musl or !opts.has_static) return skipTestStep(test_step);

    const exe = cc(b, "a.out", opts);
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

    if (opts.is_musl or !opts.has_static) return skipTestStep(test_step);

    const exe = cc(b, "a.out", opts);
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
    check.checkInHeaders();
    check.checkExact("header");
    check.checkExact("type DYN");
    check.checkInHeaders();
    check.checkExact("section headers");
    check.checkExact("name .dynamic");
    check.checkInHeaders();
    check.checkExact("section headers");
    check.checkNotPresent("name .interp");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testImageBase(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-image-base", "");

    {
        const exe = cc(b, "a.out", opts);
        exe.addHelloWorldMain();
        exe.addArgs(&.{ "-no-pie", "-Wl,-image-base,0x8000000" });

        const run = exe.run();
        run.expectHelloWorld();
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("section headers");
        check.checkExact("name .interp");
        check.checkExact("type PROGBITS");
        check.checkExtract("addr {addr}");
        check.checkComputeCompare("addr", .{ .op = .gte, .value = .{ .literal = 0x8000000 } });
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addCSource("void _start() {}");
        exe.addArgs(&.{ "-no-pie", "-nostdlib", "-Wl,-image-base,0xffffffff8000000" });

        const check = exe.check();
        check.checkInHeaders();
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

    const a_o = cc(b, "a.o", opts);
    a_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((constructor(10000))) void init4() { printf("1"); }
    );
    a_o.addArg("-c");

    const b_o = cc(b, "b.o", opts);
    b_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((constructor(1000))) void init3() { printf("2"); }
    );
    b_o.addArg("-c");

    const c_o = cc(b, "c.o", opts);
    c_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((constructor)) void init1() { printf("3"); }
    );
    c_o.addArg("-c");

    const d_o = cc(b, "d.o", opts);
    d_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((constructor)) void init2() { printf("4"); }
    );
    d_o.addArg("-c");

    const e_o = cc(b, "e.o", opts);
    e_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((destructor(10000))) void fini4() { printf("5"); }
    );
    e_o.addArg("-c");

    const f_o = cc(b, "f.o", opts);
    f_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((destructor(1000))) void fini3() { printf("6"); }
    );
    f_o.addArg("-c");

    const g_o = cc(b, "g.o", opts);
    g_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((destructor)) void fini1() { printf("7"); }
    );
    g_o.addArg("-c");

    const h_o = cc(b, "h.o", opts);
    h_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((destructor)) void fini2() { printf("8"); }
    );
    h_o.addArg("-c");

    const exe = cc(b, "a.out", opts);
    exe.addEmptyMain();
    exe.addFileSource(a_o.getFile());
    exe.addFileSource(b_o.getFile());
    exe.addFileSource(c_o.getFile());
    exe.addFileSource(d_o.getFile());
    exe.addFileSource(e_o.getFile());
    exe.addFileSource(f_o.getFile());
    exe.addFileSource(g_o.getFile());
    exe.addFileSource(h_o.getFile());

    const run = exe.run();
    run.expectStdOutEqual("21348756");
    test_step.dependOn(run.step());

    return test_step;
}

fn testLargeAlignmentDso(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-large-alignment-dso", "");

    const dso = cc(b, "a.so", opts);
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

    const check = dso.check();
    check.checkInSymtab();
    check.checkExtract("{addr1} {size1} {shndx1} FUNC GLOBAL DEFAULT hello");
    check.checkInSymtab();
    check.checkExtract("{addr2} {size2} {shndx2} FUNC GLOBAL DEFAULT world");
    check.checkComputeCompare("addr1 16 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.checkComputeCompare("addr2 16 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    test_step.dependOn(&check.step);

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\void greet();
        \\int main() { greet(); }
    );
    exe.addFileSource(dso.getFile());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

    const run = exe.run();
    run.expectStdOutEqual("Hello world");
    test_step.dependOn(run.step());

    return test_step;
}

fn testLargeAlignmentExe(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-large-alignment-exe", "");

    const exe = cc(b, "a.out", opts);
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

fn testLargeBss(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-large-bss", "");

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\char arr[0x100000000];
        \\int main() {
        \\  return arr[2000];
        \\}
    );

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testLinkOrder(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-link-order", "");

    const obj = cc(b, "a.o", opts);
    obj.addCSource("void foo() {}");
    obj.addArgs(&.{ "-fPIC", "-c" });

    const dso = cc(b, "a.so", opts);
    dso.addFileSource(obj.getFile());
    dso.addArg("-shared");

    const lib = ar(b, "a.a");
    lib.addFileSource(obj.getFile());

    const main_o = cc(b, "main.o", opts);
    main_o.addCSource(
        \\void foo();
        \\int main() {
        \\  foo();
        \\}
    );
    main_o.addArg("-c");

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(main_o.getFile());
        exe.addArg("-Wl,--as-needed");
        exe.addFileSource(dso.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());
        exe.addFileSource(lib.getFile());

        const check = exe.check();
        check.checkInDynamicSection();
        check.checkContains("a.so");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(main_o.getFile());
        exe.addArg("-Wl,--as-needed");
        exe.addFileSource(lib.getFile());
        exe.addFileSource(dso.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

        const check = exe.check();
        check.checkInDynamicSection();
        check.checkNotPresent("a.so");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testLinkerScript(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-linker-script", "");

    const dso = cc(b, "libbar.so", opts);
    dso.addCSource("int foo() { return 42; }");
    dso.addArgs(&.{ "-fPIC", "-shared" });

    const scripts = WriteFile.create(b);
    _ = scripts.add("liba.so", "INPUT(libfoo.so)");
    _ = scripts.add("libfoo.so", "GROUP(AS_NEEDED(-lbar))");

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\int foo();
        \\int main() {
        \\  return foo() - 42;
        \\}
    );
    exe.addArg("-la");
    exe.addPrefixedDirectorySource("-L", scripts.getDirectory());
    exe.addPrefixedDirectorySource("-L", dso.getDir());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

// Adapted from https://github.com/rui314/mold/blob/main/test/elf/mergeable-strings.sh
fn testMergeStrings(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-merge-strings", "");

    const obj1 = cc(b, "a.o", opts);
    obj1.addCSource(
        \\#include <uchar.h>
        \\#include <wchar.h>
        \\char *cstr1 = "foo";
        \\wchar_t *wide1 = L"foo";
        \\char16_t *utf16_1 = u"foo";
        \\char32_t *utf32_1 = U"foo";
    );
    obj1.addArg("-c");
    obj1.addArg("-O2");

    const obj2 = cc(b, "b.o", opts);
    obj2.addCSource(
        \\#include <stdio.h>
        \\#include <assert.h>
        \\#include <uchar.h>
        \\#include <wchar.h>
        \\extern char *cstr1;
        \\extern wchar_t *wide1;
        \\extern char16_t *utf16_1;
        \\extern char32_t *utf32_1;
        \\char *cstr2 = "foo";
        \\wchar_t *wide2 = L"foo";
        \\char16_t *utf16_2 = u"foo";
        \\char32_t *utf32_2 = U"foo";
        \\int main() {
        \\  assert((void*)cstr1 ==   (void*)cstr2);
        \\  assert((void*)wide1 ==   (void*)wide2);
        \\  assert((void*)utf16_1 == (void*)utf16_2);
        \\  assert((void*)utf32_1 == (void*)utf32_2);
        \\  assert((void*)wide1 ==   (void*)utf32_1);
        \\  assert((void*)cstr1 !=   (void*)wide1);
        \\  assert((void*)cstr1 !=   (void*)utf32_1);
        \\  assert((void*)wide1 !=   (void*)utf16_1);
        \\}
    );
    obj2.addArg("-c");
    obj2.addArg("-O2");

    const exe = cc(b, "a.out", opts);
    exe.addFileSource(obj1.getFile());
    exe.addFileSource(obj2.getFile());
    exe.addArg("-no-pie");

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testNoEhFrameHdr(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-no-eh-frame-hdr", "");

    const exe = cc(b, "a.out", opts);
    exe.addEmptyMain();
    exe.addArgs(&.{"-Wl,--no-eh-frame-hdr"});

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("section headers");
    check.checkNotPresent("name .eh_frame_hdr");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testPltGot(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-plt-got", "");

    const dso = cc(b, "a.so", opts);
    dso.addCSource(
        \\#include <stdio.h>
        \\void ignore(void *foo) {}
        \\void hello() {
        \\  printf("Hello world\n");
        \\}
    );
    dso.addArgs(&.{ "-fPIC", "-shared" });

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\void ignore(void *);
        \\int hello();
        \\void foo() { ignore(hello); }
        \\int main() { hello(); }
    );
    exe.addFileSource(dso.getFile());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());
    exe.addArg("-fPIC");

    const run = exe.run();
    run.expectStdOutEqual("Hello world\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testPreinitArray(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-preinit-array", "");

    {
        const obj = cc(b, "a.o", opts);
        obj.addCSource("void _start() {}");
        obj.addArg("-c");

        const exe = ld(b, "a.out", opts);
        exe.addFileSource(obj.getFile());

        const check = exe.check();
        check.checkInDynamicSection();
        check.checkNotPresent("PREINIT_ARRAY");
    }

    {
        const exe = cc(b, "a.out", opts);
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

    const a_so = cc(b, "a.so", opts);
    a_so.addCSource("int foo = 1;");
    a_so.addArgs(&.{ "-fPIC", "-shared" });

    const b_so = cc(b, "b.so", opts);
    b_so.addCSource("int bar = 1;");
    b_so.addArgs(&.{ "-fPIC", "-shared" });

    const exe = cc(b, "a.out", opts);
    exe.addEmptyMain();
    exe.addArgs(&.{ "-Wl,--as-needed", "-Wl,--push-state", "-Wl,--no-as-needed" });
    exe.addFileSource(a_so.getFile());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", a_so.getDir());
    exe.addArg("-Wl,--pop-state");
    exe.addFileSource(b_so.getFile());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", b_so.getDir());

    const check = exe.check();
    check.checkInDynamicSection();
    check.checkContains("a.so");
    check.checkInDynamicSection();
    check.checkNotPresent("b.so");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testRelocatableArchive(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-relocatable-archive", "");

    const obj1 = cc(b, "a.o", opts);
    obj1.addCSource(
        \\void bar();
        \\void foo() {
        \\  bar();
        \\}
    );
    obj1.addArg("-c");

    const obj2 = cc(b, "b.o", opts);
    obj2.addCSource(
        \\void bar() {}
    );
    obj2.addArg("-c");

    const obj3 = cc(b, "c.o", opts);
    obj3.addCSource(
        \\void baz();
    );
    obj3.addArg("-c");

    const obj4 = cc(b, "d.o", opts);
    obj4.addCSource(
        \\void foo();
        \\int main() {
        \\  foo();
        \\}
    );
    obj4.addArg("-c");

    const lib = ar(b, "libe.a");
    lib.addFileSource(obj1.getFile());
    lib.addFileSource(obj2.getFile());
    lib.addFileSource(obj3.getFile());

    const obj5 = ld(b, "f.o", opts);
    obj5.addFileSource(obj4.getFile());
    obj5.addFileSource(lib.getFile());
    obj5.addArg("-r");

    const check = obj5.check();
    check.checkInSymtab();
    check.checkContains("foo");
    check.checkInSymtab();
    check.checkContains("bar");
    check.checkInSymtab();
    check.checkNotPresent("baz");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testRelocatableEhFrame(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-relocatable-eh-frame", "");

    if (!opts.has_zig) return skipTestStep(test_step);

    const obj1 = zig(b, "a.o", .obj);
    obj1.addCppSource(
        \\#include <stdexcept>
        \\int try_me() {
        \\  throw std::runtime_error("Oh no!");
        \\}
    );
    obj1.addArg("-lc++");

    const obj2 = zig(b, "b.o", .obj);
    obj2.addCppSource(
        \\extern int try_me();
        \\int try_again() {
        \\  return try_me();
        \\}
    );
    obj2.addArg("-lc++");

    {
        const obj3 = ld(b, "c.o", opts);
        obj3.addFileSource(obj1.getFile());
        obj3.addFileSource(obj2.getFile());
        obj3.addArg("-r");

        const exe = zig(b, "a.out", .exe);
        exe.addCppSource(
            \\#include <iostream>
            \\#include <stdexcept>
            \\extern int try_again();
            \\int main() {
            \\  try {
            \\    try_again();
            \\  } catch (const std::exception &e) {
            \\    std::cout << "exception=" << e.what();
            \\  }
            \\  return 0;
            \\}
        );
        exe.addFileSource(obj3.getFile());
        exe.addArg("-lc++");

        const run = exe.run();
        run.expectStdOutEqual("exception=Oh no!");
        test_step.dependOn(run.step());
    }

    {
        // Let's make the object file COMDAT group heavy!
        const obj3 = zig(b, "c.o", .obj);
        obj3.addCppSource(
            \\#include <iostream>
            \\#include <stdexcept>
            \\extern int try_again();
            \\int main() {
            \\  try {
            \\    try_again();
            \\  } catch (const std::exception &e) {
            \\    std::cout << "exception=" << e.what();
            \\  }
            \\  return 0;
            \\}
        );
        obj3.addArg("-lc++");

        const obj4 = ld(b, "d.o", opts);
        obj4.addFileSource(obj1.getFile());
        obj4.addFileSource(obj2.getFile());
        obj4.addFileSource(obj3.getFile());
        obj4.addArg("-r");

        const exe = zig(b, "a.out", .exe);
        exe.addFileSource(obj4.getFile());
        exe.addArg("-lc++");

        const run = exe.run();
        run.expectStdOutEqual("exception=Oh no!");
        test_step.dependOn(run.step());
    }

    return test_step;
}

// Adapted from https://github.com/rui314/mold/blob/main/test/elf/relocatable-mergeable-sections.sh
fn testRelocatableMergeStrings(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-relocatable-merge-strings", "");

    const obj1 = cc(b, "a.o", opts);
    obj1.addAsmSource(
        \\.section .rodata.str1.1,"aMS",@progbits,1
        \\val1:
        \\.ascii "Hello \0"
        \\.section .rodata.str1.1,"aMS",@progbits,1
        \\val5:
        \\.ascii "World \0"
        \\.section .rodata.str1.1,"aMS",@progbits,1
        \\val7:
        \\.ascii "Hello \0"
    );
    obj1.addArg("-c");

    const obj2 = ld(b, "b.o", opts);
    obj2.addFileSource(obj1.getFile());
    obj2.addArg("-r");

    const check = obj2.check();
    check.dumpSection(".rodata.str1.1");
    check.checkExact("Hello \x00World \x00");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testRelocatableNoEhFrame(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-relocatable-no-eh-frame", "");

    const obj1 = cc(b, "a.o", opts);
    obj1.addCSource("int bar() { return 42; }");
    obj1.addArgs(&.{ "-c", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables" });

    const obj2 = ld(b, "b.o", opts);
    obj2.addFileSource(obj1.getFile());
    obj2.addArg("-r");

    const check1 = obj1.check();
    check1.checkInHeaders();
    check1.checkExact("section headers");
    check1.checkNotPresent(".eh_frame");
    test_step.dependOn(&check1.step);

    const check2 = obj2.check();
    check2.checkInHeaders();
    check2.checkExact("section headers");
    check2.checkNotPresent(".eh_frame");
    test_step.dependOn(&check2.step);

    return test_step;
}

fn testSectionStart(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-section-start", "");

    {
        const exe = cc(b, "exe1", opts);
        exe.addCSource(
            \\#include <stdio.h>
            \\__attribute__((section(".dummy"))) void dummy() { printf("dummy"); }
            \\int main() { 
            \\  dummy();
            \\  return 0;
            \\}
        );
        exe.addArgs(&.{"-Wl,--section-start,.dummy=0x10000"});

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("section headers");
        check.checkExact("name .dummy");
        check.checkExact("addr 10000");
        test_step.dependOn(&check.step);

        const run = exe.run();
        run.expectStdOutEqual("dummy");
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "exe2", opts);
        exe.addCSource(
            \\#include <stdio.h>
            \\int foo;
            \\int main() { 
            \\  return foo;
            \\}
        );
        exe.addArgs(&.{"-Wl,-Tbss,0x10000"});

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("section headers");
        check.checkExact("name .bss");
        check.checkExact("addr 10000");
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "exe3", opts);
        exe.addCSource(
            \\#include <stdio.h>
            \\__attribute__((section(".dummy"))) void dummy() { printf("dummy"); }
            \\int main() { 
            \\  printf("hi ");
            \\  dummy();
            \\  return 0;
            \\}
        );
        exe.addArgs(&.{ "-Wl,--section-start,.dummy=0x10000", "-Wl,-Ttext,0x1000" });

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("section headers");
        check.checkExact("name .text");
        check.checkExact("addr 1000");
        check.checkInHeaders();
        check.checkExact("section headers");
        check.checkExact("name .dummy");
        check.checkExact("addr 10000");
        test_step.dependOn(&check.step);

        const run = exe.run();
        run.expectStdOutEqual("hi dummy");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testSharedAbsSymbol(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-shared-abs-symbol", "");

    const dso = cc(b, "a.so", opts);
    dso.addAsmSource(
        \\.globl foo
        \\foo = 3;
    );
    dso.addArgs(&.{ "-fPIC", "-shared" });

    const obj = cc(b, "main.o", opts);
    obj.addCSource(
        \\#include <stdio.h>
        \\extern char foo;
        \\int main() { printf("foo=%p\n", &foo); }
    );
    obj.addArgs(&.{ "-fPIC", "-c" });

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(obj.getFile());
        exe.addFileSource(dso.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());
        exe.addArg("-pie");

        const run = exe.run();
        run.expectStdOutEqual("foo=0x3\n");
        test_step.dependOn(run.step());

        // TODO fix/improve in CheckObject
        // const check = exe.check();
        // check.checkInSymtab();
        // check.checkNotPresent("foo");
        // test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(obj.getFile());
        exe.addFileSource(dso.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());
        exe.addArg("-no-pie");

        const run = exe.run();
        run.expectStdOutEqual("foo=0x3\n");
        test_step.dependOn(run.step());

        // TODO fix/improve in CheckObject
        // const check = exe.check();
        // check.checkInSymtab();
        // check.checkNotPresent("foo");
        // test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testStrip(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-strip", "");

    const obj = cc(b, "a.o", opts);
    obj.addAsmSource(
        \\.globl _start, foo
        \\_start:
        \\foo:
        \\bar:
        \\.L.baz:
    );
    obj.addArgs(&.{ "-c", "-Wa,-L" });

    {
        const exe = ld(b, "a.out", opts);
        exe.addFileSource(obj.getFile());

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("name .symtab");
        test_step.dependOn(&check.step);
    }

    {
        const exe = ld(b, "a.out", opts);
        exe.addFileSource(obj.getFile());
        exe.addArg("--strip-all");

        const check = exe.check();
        check.checkInHeaders();
        check.checkNotPresent("name .symtab");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testThunks(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-thunks", "");

    if (builtin.target.cpu.arch != .aarch64) return skipTestStep(test_step);

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\void foo();
        \\void foobar();
        \\__attribute__((section(".foo"))) void foo() { foobar(); }
        \\__attribute__((section(".foobar"))) void foobar() { foo(); }
        \\int main() {
        \\  foo();
        \\  return 0;
        \\}
    );
    exe.addArgs(&.{ "-Wl,--section-start,.foo=0x1000", "-Wl,--section-start,.foobar=0x20000000" });

    const check = exe.check();
    check.checkInSymtab();
    check.checkContains("foo$thunk");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testThunks2(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-thunks2", "");

    if (builtin.target.cpu.arch != .aarch64) return skipTestStep(test_step);

    const src =
        \\#include <stdio.h>
        \\__attribute__((aligned(0x8000000))) int bar() {
        \\  return 42;
        \\}
        \\int foobar();
        \\int foo() {
        \\  return bar() - foobar();
        \\}
        \\__attribute__((aligned(0x8000000))) int foobar() {
        \\  return 42;
        \\}
        \\int main() {
        \\  printf("bar=%d, foo=%d, foobar=%d", bar(), foo(), foobar());
        \\  return foo();
        \\}
    ;

    {
        const exe = cc(b, "a.out", opts);
        exe.addCSource(src);
        exe.addArg("-ffunction-sections");

        const run = exe.run();
        run.expectStdOutEqual("bar=42, foo=0, foobar=42");
        run.expectExitCode(0);
        test_step.dependOn(run.step());

        const check = exe.check();
        check.max_bytes = std.math.maxInt(u32);
        check.checkInSymtab();
        check.checkContains("_libc_start_main$thunk");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addCSource(src);

        const run = exe.run();
        run.expectStdOutEqual("bar=42, foo=0, foobar=42");
        run.expectExitCode(0);
        test_step.dependOn(run.step());

        const check = exe.check();
        check.max_bytes = std.math.maxInt(u32);
        check.checkInSymtab();
        check.checkContains("_libc_start_main$thunk");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testTlsCommon(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-common", "");

    if (opts.system_compiler != .gcc) return skipTestStep(test_step);

    const a_o = cc(b, "a.o", opts);
    a_o.addAsmSource(
        \\.globl foo
        \\.tls_common foo,4,4
    );
    a_o.addArg("-c");

    const b_o = cc(b, "b.o", opts);
    b_o.addCSource(
        \\#include <stdio.h>
        \\extern _Thread_local int foo;
        \\int main() {
        \\  printf("foo=%d\n", foo);
        \\}
    );
    b_o.addArgs(&.{ "-c", "-std=c11" });

    const exe = cc(b, "a.out", opts);
    exe.addFileSource(a_o.getFile());
    exe.addFileSource(b_o.getFile());

    const run = exe.run();
    run.expectStdOutEqual("foo=0\n");
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("section headers");
    check.checkExact("name .tls_common");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testTlsDesc(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-desc", "");

    if (opts.system_compiler != .gcc) return skipTestStep(test_step);

    const main_o = cc(b, "main.o", opts);
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
    main_o.addArgs(&.{ "-c", "-fPIC" });
    forceTlsDialect(main_o, .desc);

    const a_o = cc(b, "a.o", opts);
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
    a_o.addArgs(&.{ "-c", "-fPIC" });
    forceTlsDialect(a_o, .desc);

    const exp_stdout = "42 5\n";

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(main_o.getFile());
        exe.addFileSource(a_o.getFile());

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(main_o.getFile());
        exe.addFileSource(a_o.getFile());
        exe.addArg("-Wl,-no-relax");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const dso = cc(b, "a.so", opts);
        dso.addFileSource(a_o.getFile());
        dso.addArg("-shared");

        const exe = cc(b, "a.out", opts);
        exe.addFileSource(main_o.getFile());
        exe.addFileSource(dso.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const dso = cc(b, "a.so", opts);
        dso.addFileSource(a_o.getFile());
        dso.addArgs(&.{ "-shared", "-Wl,-no-relax" });

        const exe = cc(b, "a.out", opts);
        exe.addFileSource(main_o.getFile());
        exe.addFileSource(dso.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());
        exe.addArg("-Wl,-no-relax");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsDescImport(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-desc-import", "");

    if (opts.system_compiler != .gcc) return skipTestStep(test_step);

    const dso = cc(b, "a.so", opts);
    dso.addCSource(
        \\_Thread_local int foo = 5;
        \\_Thread_local int bar;
    );
    dso.addArgs(&.{ "-fPIC", "-shared" });
    forceTlsDialect(dso, .desc);

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\#include <stdio.h>
        \\extern _Thread_local int foo;
        \\extern _Thread_local int bar;
        \\int main() {
        \\  bar = 7;
        \\  printf("%d %d\n", foo, bar);
        \\}
    );
    exe.addArgs(&.{"-fPIC"});
    exe.addFileSource(dso.getFile());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());
    forceTlsDialect(exe, .desc);

    const run = exe.run();
    run.expectStdOutEqual("5 7\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testTlsDescStatic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-desc-static", "");

    if (opts.system_compiler != .gcc or !opts.has_static) return skipTestStep(test_step);

    const main_o = cc(b, "main.o", opts);
    main_o.addCSource(
        \\#include <stdio.h>
        \\extern _Thread_local int foo;
        \\int main() {
        \\  foo = 42;
        \\  printf("%d\n", foo);
        \\}
    );
    main_o.addArgs(&.{ "-c", "-fPIC" });
    forceTlsDialect(main_o, .desc);

    const a_o = cc(b, "a.o", opts);
    a_o.addCSource(
        \\_Thread_local int foo;
    );
    a_o.addArgs(&.{ "-c", "-fPIC" });
    forceTlsDialect(a_o, .desc);

    const exp_stdout = "42\n";

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addFileSource(a_o.getFile());
        exe.addArg("-static");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addFileSource(a_o.getFile());
        exe.addArgs(&.{ "-static", "-Wl,-no-relax" });

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsDfStaticTls(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-df-static-tls", "");

    const obj = cc(b, "a.o", opts);
    obj.addCSource(
        \\static _Thread_local int foo = 5;
        \\void mutate() { ++foo; }
        \\int bar() { return foo; }
    );
    obj.addArgs(&.{ "-fPIC", "-c", "-ftls-model=initial-exec" });

    {
        const dso = cc(b, "a.so", opts);
        dso.addFileSource(obj.getFile());
        dso.addArgs(&.{ "-shared", "-Wl,-relax" });

        const check = dso.check();
        check.checkInDynamicSection();
        check.checkContains("STATIC_TLS");
        test_step.dependOn(&check.step);
    }

    {
        const dso = cc(b, "a.so", opts);
        dso.addFileSource(obj.getFile());
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

    const dso = cc(b, "a.so", opts);
    dso.addCSource(
        \\extern _Thread_local int foo;
        \\_Thread_local int bar;
        \\int get_foo1() { return foo; }
        \\int get_bar1() { return bar; }
    );
    dso.addArgs(&.{ "-fPIC", "-shared" });

    const exe = cc(b, "a.out", opts);
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
    exe.addFileSource(dso.getFile());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

    const run = exe.run();
    run.expectStdOutEqual("5 3 5 3 5 3\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testTlsGd(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-gd", "");

    const main_o = cc(b, "main.o", opts);
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
    if (opts.system_compiler == .gcc) forceTlsDialect(main_o, .trad);

    const a_o = cc(b, "a.o", opts);
    a_o.addCSource(
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x3 = 3;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x5 = 5;
        \\int get_x5() { return x5; }
    );
    a_o.addArgs(&.{ "-c", "-fPIC" });
    if (opts.system_compiler == .gcc) forceTlsDialect(a_o, .trad);

    const b_o = cc(b, "b.o", opts);
    b_o.addCSource(
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x4 = 4;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x6 = 6;
        \\int get_x6() { return x6; }
    );
    b_o.addArgs(&.{ "-c", "-fPIC" });
    if (opts.system_compiler == .gcc) forceTlsDialect(b_o, .trad);

    const exp_stdout = "1 2 3 4 5 6\n";

    const dso1 = cc(b, "a.so", opts);
    dso1.addArg("-shared");
    dso1.addFileSource(a_o.getFile());

    const dso2 = cc(b, "b.so", opts);
    dso2.addArgs(&.{ "-shared", "-Wl,-no-relax" });
    dso2.addFileSource(b_o.getFile());

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addFileSource(dso1.getFile());
        exe.addFileSource(dso2.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso1.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso2.getDir());

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addArg("-Wl,-no-relax");
        exe.addFileSource(dso1.getFile());
        exe.addFileSource(dso2.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso1.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso2.getDir());

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    if (opts.has_static) {
        {
            const exe = cc(b, "main", opts);
            exe.addFileSource(main_o.getFile());
            exe.addFileSource(a_o.getFile());
            exe.addFileSource(b_o.getFile());
            exe.addArg("-static");

            const run = exe.run();
            run.expectStdOutEqual(exp_stdout);
            test_step.dependOn(run.step());
        }

        {
            const exe = cc(b, "main", opts);
            exe.addFileSource(main_o.getFile());
            exe.addFileSource(a_o.getFile());
            exe.addFileSource(b_o.getFile());
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

    const obj = cc(b, "a.o", opts);
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
    if (opts.system_compiler == .gcc) forceTlsDialect(obj, .trad);

    const a_so = cc(b, "a.so", opts);
    a_so.addCSource(
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x3 = 3;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x5 = 5;
        \\int get_x5() { return x5; }
    );
    a_so.addArgs(&.{ "-fPIC", "-shared", "-fno-plt" });
    if (opts.system_compiler == .gcc) forceTlsDialect(a_so, .trad);

    const b_so = cc(b, "b.so", opts);
    b_so.addCSource(
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int x4 = 4;
        \\__attribute__((tls_model("global-dynamic"))) static _Thread_local int x6 = 6;
        \\int get_x6() { return x6; }
    );
    b_so.addArgs(&.{ "-fPIC", "-shared", "-fno-plt", "-Wl,-no-relax" });
    if (opts.system_compiler == .gcc) forceTlsDialect(b_so, .trad);

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(obj.getFile());
        exe.addFileSource(a_so.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", a_so.getDir());
        exe.addFileSource(b_so.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", b_so.getDir());

        const run = exe.run();
        run.expectStdOutEqual("1 2 3 4 5 6\n");
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(obj.getFile());
        exe.addFileSource(a_so.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", a_so.getDir());
        exe.addFileSource(b_so.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", b_so.getDir());
        exe.addArg("-Wl,-no-relax");

        const run = exe.run();
        run.expectStdOutEqual("1 2 3 4 5 6\n");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsGdToIe(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-gd-to-ie", "");

    if (builtin.target.cpu.arch != .x86_64) return skipTestStep(test_step);

    const a_o = cc(b, "a.o", opts);
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

    const b_o = cc(b, "b.o", opts);
    b_o.addCSource(
        \\int foo();
        \\int main() { foo(); }
    );
    b_o.addArgs(&.{ "-c", "-fPIC" });

    {
        const dso = cc(b, "a.so", opts);
        dso.addFileSource(a_o.getFile());
        dso.addArg("-shared");

        const exe = cc(b, "a.out", opts);
        exe.addFileSource(b_o.getFile());
        exe.addFileSource(dso.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

        const run = exe.run();
        run.expectStdOutEqual("1 2 3\n");
        test_step.dependOn(run.step());
    }

    {
        const dso = cc(b, "a.so", opts);
        dso.addFileSource(a_o.getFile());
        dso.addArgs(&.{ "-shared", "-Wl,-no-relax" });

        const exe = cc(b, "a.out", opts);
        exe.addFileSource(b_o.getFile());
        exe.addFileSource(dso.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

        const run = exe.run();
        run.expectStdOutEqual("1 2 3\n");
        test_step.dependOn(run.step());
    }

    {
        const dso = cc(b, "a.so", opts);
        dso.addFileSource(a_o.getFile());
        dso.addArgs(&.{ "-shared", "-Wl,-z,nodlopen" });

        const exe = cc(b, "a.out", opts);
        exe.addFileSource(b_o.getFile());
        exe.addFileSource(dso.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

        const run = exe.run();
        run.expectStdOutEqual("1 2 3\n");
        test_step.dependOn(run.step());
    }

    {
        const dso = cc(b, "a.so", opts);
        dso.addFileSource(a_o.getFile());
        dso.addArgs(&.{ "-shared", "-Wl,-z,nodlopen", "-Wl,-no-relax" });

        const exe = cc(b, "a.out", opts);
        exe.addFileSource(b_o.getFile());
        exe.addFileSource(dso.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

        const run = exe.run();
        run.expectStdOutEqual("1 2 3\n");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsIe(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-ie", "");

    const dso = cc(b, "a.so", opts);
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

    const main_o = cc(b, "main.o", opts);
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

    const exp_stdout = "0 0 3 5 7\n";

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addFileSource(dso.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addFileSource(dso.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());
        exe.addArg("-Wl,-no-relax");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsLargeAlignment(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-large-alignment", "");

    const a_o = cc(b, "a.o", opts);
    a_o.addCSource(
        \\__attribute__((section(".tdata1")))
        \\_Thread_local int x = 42;
    );
    a_o.addArgs(&.{ "-fPIC", "-std=c11", "-c" });

    const b_o = cc(b, "b.o", opts);
    b_o.addCSource(
        \\__attribute__((section(".tdata2")))
        \\_Alignas(256) _Thread_local int y[] = { 1, 2, 3 };
    );
    b_o.addArgs(&.{ "-fPIC", "-std=c11", "-c" });

    const c_o = cc(b, "c.o", opts);
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
        const dso = cc(b, "a.so", opts);
        dso.addFileSource(a_o.getFile());
        dso.addFileSource(b_o.getFile());
        dso.addArg("-shared");

        const exe = cc(b, "a.out", opts);
        exe.addFileSource(c_o.getFile());
        exe.addFileSource(dso.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

        const run = exe.run();
        run.expectStdOutEqual("42 1 2 3\n");
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(a_o.getFile());
        exe.addFileSource(b_o.getFile());
        exe.addFileSource(c_o.getFile());

        const run = exe.run();
        run.expectStdOutEqual("42 1 2 3\n");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsLargeTbss(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-large-tbss", "");

    const exe = cc(b, "a.out", opts);
    exe.addAsmSource(
        \\.globl x, y
        \\.section .tbss,"awT",@nobits
        \\x:
        \\.zero 1024
        \\.section .tcommon,"awT",@nobits
        \\y:
        \\.zero 1024
    );
    exe.addCSource(
        \\#include <stdio.h>
        \\extern _Thread_local char x[1024000];
        \\extern _Thread_local char y[1024000];
        \\int main() {
        \\  x[0] = 3;
        \\  x[1023] = 5;
        \\  printf("%d %d %d %d %d %d\n", x[0], x[1], x[1023], y[0], y[1], y[1023]);
        \\}
    );

    const run = exe.run();
    run.expectStdOutEqual("3 0 5 0 0 0\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testTlsLargeStaticImage(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-large-static-image", "");

    const exe = cc(b, "a.out", opts);
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

    const main_o = cc(b, "main.o", opts);
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

    const a_o = cc(b, "a.o", opts);
    a_o.addCSource("_Thread_local int foo = 3;");
    a_o.addArgs(&.{ "-c", "-fPIC", "-ftls-model=local-dynamic" });

    const exp_stdout = "3 5 3 5\n";

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(main_o.getFile());
        exe.addFileSource(a_o.getFile());
        exe.addArg("-Wl,-relax");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(main_o.getFile());
        exe.addFileSource(a_o.getFile());
        exe.addArg("-Wl,-no-relax");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsLdDso(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-ld-dso", "");

    const dso = cc(b, "a.so", opts);
    dso.addCSource(
        \\static _Thread_local int def, def1;
        \\int f0() { return ++def; }
        \\int f1() { return ++def1 + def; }
    );
    dso.addArgs(&.{ "-shared", "-fPIC", "-ftls-model=local-dynamic" });

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\#include <stdio.h>
        \\extern int f0();
        \\extern int f1();
        \\int main() {
        \\  int x = f0();
        \\  int y = f1();
        \\  printf("%d %d\n", x, y);
        \\  return 0;
        \\}
    );
    exe.addFileSource(dso.getFile());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

    const run = exe.run();
    run.expectStdOutEqual("1 2\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testTlsLdNoPlt(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-ld-no-plt", "");

    const a_o = cc(b, "a.o", opts);
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

    const b_o = cc(b, "b.o", opts);
    b_o.addCSource("_Thread_local int foo = 3;");
    b_o.addArgs(&.{ "-fPIC", "-ftls-model=local-dynamic", "-fno-plt", "-c" });

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(a_o.getFile());
        exe.addFileSource(b_o.getFile());

        const run = exe.run();
        run.expectStdOutEqual("3 5 3 5\n");
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(a_o.getFile());
        exe.addFileSource(b_o.getFile());
        exe.addArg("-Wl,-no-relax");

        const run = exe.run();
        run.expectStdOutEqual("3 5 3 5\n");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsNoPic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-no-pic", "");

    const exe = cc(b, "a.out", opts);
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

    const dso = cc(b, "a.so", opts);
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

    const exe = cc(b, "a.out", opts);
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
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());
    exe.addArgs(&.{ "-fPIC", "-ldl", "-lpthread" });

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testTlsPic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-pic", "");

    const obj = cc(b, "a.o", opts);
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

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\__attribute__((tls_model("global-dynamic"))) _Thread_local int foo = 3;
    );
    exe.addFileSource(obj.getFile());

    const run = exe.run();
    run.expectStdOutEqual("3 5 3 5\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testTlsSmallAlignment(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-small-alignment", "");

    const a_o = cc(b, "a.o", opts);
    a_o.addAsmSource(
        \\.text
        \\.byte 0
    );
    a_o.addArgs(&.{ "-c", "-fPIC" });

    const b_o = cc(b, "b.o", opts);
    b_o.addCSource("_Thread_local char x = 42;");
    b_o.addArgs(&.{ "-fPIC", "-std=c11", "-c" });

    const c_o = cc(b, "c.o", opts);
    c_o.addCSource(
        \\#include <stdio.h>
        \\extern _Thread_local char x;
        \\int main() {
        \\  printf("%d\n", x);
        \\}
    );
    c_o.addArgs(&.{ "-fPIC", "-c" });

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(a_o.getFile());
        exe.addFileSource(b_o.getFile());
        exe.addFileSource(c_o.getFile());

        const run = exe.run();
        run.expectStdOutEqual("42\n");
        test_step.dependOn(run.step());
    }

    {
        const dso = cc(b, "a.so", opts);
        dso.addFileSource(a_o.getFile());
        dso.addFileSource(b_o.getFile());
        dso.addArg("-shared");

        const exe = cc(b, "a.out", opts);
        exe.addFileSource(c_o.getFile());
        exe.addFileSource(dso.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

        const run = exe.run();
        run.expectStdOutEqual("42\n");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsStatic(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-tls-static", "");

    if (!opts.has_static) return skipTestStep(test_step);

    const exe = cc(b, "a.out", opts);
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

fn testWeakExportDso(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-weak-export-dso", "");

    const obj = cc(b, "a.o", opts);
    obj.addCSource(
        \\#include <stdio.h>
        \\__attribute__((weak)) int foo();
        \\int main() {
        \\  printf("%d\n", foo ? foo() : 3);
        \\}
    );
    obj.addArgs(&.{ "-fPIC", "-c" });

    const dso = cc(b, "a.so", opts);
    dso.addFileSource(obj.getFile());
    dso.addArg("-shared");

    const check = dso.check();
    check.checkInDynamicSymtab();
    check.checkContains("UND NOTYPE WEAK DEFAULT foo");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testWeakExportExe(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-weak-export-exe", "");

    const obj = cc(b, "a.o", opts);
    obj.addCSource(
        \\#include <stdio.h>
        \\__attribute__((weak)) int foo();
        \\int main() {
        \\  printf("%d\n", foo ? foo() : 3);
        \\}
    );
    obj.addArgs(&.{ "-fPIC", "-c" });

    const exe = cc(b, "a.out", opts);
    exe.addFileSource(obj.getFile());

    const check = exe.check();
    check.checkInDynamicSymtab();
    check.checkNotPresent("UND NOTYPE WEAK DEFAULT foo");
    test_step.dependOn(&check.step);

    const run = exe.run();
    run.expectStdOutEqual("3\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testWeakUndefDso(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-weak-undef-dso", "");

    const dso = cc(b, "a.so", opts);
    dso.addCSource(
        \\__attribute__((weak)) int foo();
        \\int bar() { return foo ? foo() : -1; }
    );
    dso.addArgs(&.{ "-fPIC", "-shared" });

    {
        const exe = cc(b, "a.out", opts);
        exe.addCSource(
            \\#include <stdio.h>
            \\int bar();
            \\int main() { printf("bar=%d\n", bar()); }
        );
        exe.addFileSource(dso.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

        const run = exe.run();
        run.expectStdOutEqual("bar=-1\n");
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addCSource(
            \\#include <stdio.h>
            \\int foo() { return 5; }
            \\int bar();
            \\int main() { printf("bar=%d\n", bar()); }
        );
        exe.addFileSource(dso.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

        const run = exe.run();
        run.expectStdOutEqual("bar=5\n");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testZNow(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-z-now", "");

    const obj = cc(b, "a.o", opts);
    obj.addEmptyMain();
    obj.addArgs(&.{ "-fPIC", "-c" });

    {
        const dso = cc(b, "a.so", opts);
        dso.addFileSource(obj.getFile());
        dso.addArgs(&.{ "-shared", "-Wl,-z,now" });

        const check = dso.check();
        check.checkInDynamicSection();
        check.checkContains("NOW");
        test_step.dependOn(&check.step);
    }

    {
        const dso = cc(b, "a.so", opts);
        dso.addFileSource(obj.getFile());
        dso.addArgs(&.{ "-shared", "-Wl,-z,now", "-Wl,-z,lazy" });

        const check = dso.check();
        check.checkInDynamicSection();
        check.checkNotPresent("NOW");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testZStackSize(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-z-stack-size", "");

    const exe = cc(b, "a.out", opts);
    exe.addEmptyMain();
    exe.addArg("-Wl,-z,stack-size=0x800000");

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("program headers");
    check.checkExact("type GNU_STACK");
    check.checkExact("memsz 800000");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testZText(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-elf-z-text", "");

    if (builtin.target.cpu.arch != .x86_64) return skipTestStep(test_step);

    // Previously, following mold, this test tested text relocs present in a PIE executable.
    // However, as we want to cover musl AND glibc, it is now modified to test presence of
    // text relocs in a DSO which is then linked with an executable.
    // According to Rich and this thread https://www.openwall.com/lists/musl/2020/09/25/4
    // musl supports only a very limited number of text relocations and only in DSOs (and
    // rightly so!).

    const a_o = cc(b, "a.o", opts);
    a_o.addAsmSource(
        \\.globl fn1
        \\fn1:
        \\  sub $8, %rsp
        \\  movabs ptr, %rax
        \\  call *%rax
        \\  add $8, %rsp
        \\  ret
    );
    a_o.addArg("-c");

    const b_o = cc(b, "b.o", opts);
    b_o.addCSource(
        \\int fn1();
        \\int fn2() {
        \\  return 3;
        \\}
        \\void *ptr = fn2;
        \\int fnn() {
        \\  return fn1();
        \\}
    );
    b_o.addArgs(&.{ "-fPIC", "-c" });

    const dso = cc(b, "a.so", opts);
    dso.addFileSource(a_o.getFile());
    dso.addFileSource(b_o.getFile());
    dso.addArg("-shared");

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\#include <stdio.h>
        \\int fnn();
        \\int main() {
        \\  printf("%d\n", fnn());
        \\}
    );
    exe.addFileSource(dso.getFile());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dso.getDir());

    const run = exe.run();
    run.expectStdOutEqual("3\n");
    test_step.dependOn(run.step());

    // Check for DT_TEXTREL in a DSO
    const check = dso.check();
    check.checkInDynamicSection();
    // check.checkExact("TEXTREL 0"); // TODO fix in CheckObject parser
    check.checkExact("FLAGS TEXTREL");
    test_step.dependOn(&check.step);

    return test_step;
}

fn forceTlsDialect(cmd: SysCmd, dialect: enum { desc, trad }) void {
    const opt = "-mtls-dialect=";
    var buffer: [opt.len + 4]u8 = undefined;
    const arg = switch (builtin.target.cpu.arch) {
        .x86_64 => switch (dialect) {
            .desc => "gnu2",
            .trad => "gnu",
        },
        .aarch64 => switch (dialect) {
            .desc => "desc",
            .trad => "trad",
        },
        else => @panic("TODO handle this arch"),
    };
    @memcpy(buffer[0..opt.len], opt);
    @memcpy(buffer[opt.len..][0..arg.len], arg);
    const len = opt.len + arg.len;
    cmd.addArg(buffer[0..len]);
}

fn cc(b: *Build, name: []const u8, opts: Options) SysCmd {
    const cmd = Run.create(b, "cc");
    cmd.addArgs(&.{ opts.cc_override orelse "cc", "-fno-lto" });
    cmd.addArg("-o");
    const out = cmd.addOutputFileArg(name);
    cmd.addPrefixedDirectorySourceArg("-B", opts.zld.dirname());
    return .{ .cmd = cmd, .out = out };
}

fn ar(b: *Build, name: []const u8) SysCmd {
    const cmd = Run.create(b, "ar");
    cmd.addArgs(&.{ "ar", "rcs" });
    const out = cmd.addOutputFileArg(name);
    return .{ .cmd = cmd, .out = out };
}

fn ld(b: *Build, name: []const u8, opts: Options) SysCmd {
    const cmd = Run.create(b, "ld");
    cmd.addFileArg(opts.zld);
    cmd.addArg("-o");
    const out = cmd.addOutputFileArg(name);
    return .{ .cmd = cmd, .out = out };
}

fn zig(b: *Build, name: []const u8, comptime mode: enum { obj, exe, lib }) SysCmd {
    const cmd = Run.create(b, "zig");
    cmd.addArgs(&.{ "zig", "build-" ++ @tagName(mode) });
    const out = cmd.addPrefixedOutputFileArg("-femit-bin=", name);
    return .{ .cmd = cmd, .out = out };
}

const Options = struct {
    zld: LazyPath,
    system_compiler: common.SystemCompiler,
    has_static: bool,
    has_zig: bool,
    is_musl: bool,
    cc_override: ?[]const u8,
};

const std = @import("std");
const builtin = @import("builtin");
const common = @import("test.zig");
const skipTestStep = common.skipTestStep;

const Build = std.Build;
const Compile = Step.Compile;
const LazyPath = Build.LazyPath;
const Run = Step.Run;
const Step = Build.Step;
const SysCmd = common.SysCmd;
const WriteFile = Step.WriteFile;
