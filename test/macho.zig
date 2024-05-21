pub fn addMachOTests(b: *Build, options: common.Options) *Step {
    const macho_step = b.step("test-macho", "Run MachO tests");

    if (builtin.target.os.tag != .macos) return skipTestStep(macho_step);

    var opts = Options{
        .zld = options.zld,
        .has_zig = options.has_zig,
        .has_objc_msgsend_stubs = options.has_objc_msgsend_stubs,
        .macos_sdk = undefined,
        .ios_sdk = null,
        .cc_override = options.cc_override,
    };
    opts.macos_sdk = std.zig.system.darwin.getSdk(b.allocator, builtin.target) orelse @panic("no macOS SDK found");
    opts.ios_sdk = blk: {
        const target = std.zig.system.resolveTargetQuery(.{
            .cpu_arch = .aarch64,
            .os_tag = .ios,
        }) catch break :blk null;
        break :blk std.zig.system.darwin.getSdk(b.allocator, target);
    };

    macho_step.dependOn(testAllLoad(b, opts));
    macho_step.dependOn(testBuildVersionMacOS(b, opts));
    macho_step.dependOn(testBuildVersionIOS(b, opts));
    macho_step.dependOn(testDeadStrip(b, opts));
    macho_step.dependOn(testDeadStripDylibs(b, opts));
    macho_step.dependOn(testDylib(b, opts));
    macho_step.dependOn(testDylibReexport(b, opts));
    macho_step.dependOn(testDylibReexportDeep(b, opts));
    macho_step.dependOn(testDylibVersionTbd(b, opts));
    macho_step.dependOn(testEmptyObject(b, opts));
    macho_step.dependOn(testEntryPoint(b, opts));
    macho_step.dependOn(testEntryPointArchive(b, opts));
    macho_step.dependOn(testEntryPointDylib(b, opts));
    macho_step.dependOn(testFatArchive(b, opts));
    macho_step.dependOn(testFatDylib(b, opts));
    macho_step.dependOn(testFlatNamespace(b, opts));
    macho_step.dependOn(testFlatNamespaceExe(b, opts));
    macho_step.dependOn(testFlatNamespaceWeak(b, opts));
    macho_step.dependOn(testForceLoad(b, opts));
    macho_step.dependOn(testHeaderpad(b, opts));
    macho_step.dependOn(testHeaderWeakFlags(b, opts));
    macho_step.dependOn(testHelloC(b, opts));
    macho_step.dependOn(testHelloZig(b, opts));
    macho_step.dependOn(testLayout(b, opts));
    macho_step.dependOn(testLargeBss(b, opts));
    macho_step.dependOn(testLinkOrder(b, opts));
    macho_step.dependOn(testLoadHidden(b, opts));
    macho_step.dependOn(testMergeLiterals(b, opts));
    macho_step.dependOn(testMergeLiterals2(b, opts));
    macho_step.dependOn(testMergeLiteralsObjc(b, opts));
    macho_step.dependOn(testMhExecuteHeader(b, opts));
    macho_step.dependOn(testNeededFramework(b, opts));
    macho_step.dependOn(testNeededLibrary(b, opts));
    macho_step.dependOn(testNoDeadStrip(b, opts));
    macho_step.dependOn(testNoExportsDylib(b, opts));
    macho_step.dependOn(testObjc(b, opts));
    macho_step.dependOn(testObjcStubs(b, opts));
    macho_step.dependOn(testObjcStubs2(b, opts));
    macho_step.dependOn(testObjCpp(b, opts));
    macho_step.dependOn(testPagezeroSize(b, opts));
    macho_step.dependOn(testReexportsZig(b, opts));
    macho_step.dependOn(testRelocatable(b, opts));
    macho_step.dependOn(testRelocatableZig(b, opts));
    macho_step.dependOn(testSearchStrategy(b, opts));
    macho_step.dependOn(testSectionBoundarySymbols(b, opts));
    macho_step.dependOn(testSegmentBoundarySymbols(b, opts));
    macho_step.dependOn(testStackSize(b, opts));
    macho_step.dependOn(testSymbolStabs(b, opts));
    macho_step.dependOn(testTbdv3(b, opts));
    macho_step.dependOn(testTentative(b, opts));
    macho_step.dependOn(testThunks(b, opts));
    macho_step.dependOn(testTls(b, opts));
    macho_step.dependOn(testTlsLargeTbss(b, opts));
    macho_step.dependOn(testTlsPointers(b, opts));
    macho_step.dependOn(testTwoLevelNamespace(b, opts));
    macho_step.dependOn(testUndefinedFlag(b, opts));
    macho_step.dependOn(testUnwindInfo(b, opts));
    macho_step.dependOn(testUnwindInfoNoSubsectionsArm64(b, opts));
    macho_step.dependOn(testUnwindInfoNoSubsectionsX64(b, opts));
    macho_step.dependOn(testWeakBind(b, opts));
    macho_step.dependOn(testWeakFramework(b, opts));
    macho_step.dependOn(testWeakLibrary(b, opts));
    macho_step.dependOn(testWeakRef(b, opts));
    macho_step.dependOn(testWeakRef2(b, opts));

    return macho_step;
}

fn testAllLoad(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-all-load", "");

    const obj1 = cc(b, "a.o", opts);
    obj1.addCSource("int foo = 1;");
    obj1.addArg("-c");

    const obj2 = cc(b, "b.o", opts);
    obj2.addCSource("int bar = 42;");
    obj2.addArg("-c");

    const lib = ar(b, "liba.a");
    lib.addFileSource(obj1.getFile());
    lib.addFileSource(obj2.getFile());

    const main_o = cc(b, "main.o", opts);
    main_o.addCSource(
        \\extern int foo;
        \\int main() {
        \\  return foo;
        \\}
    );
    main_o.addArg("-c");

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(lib.getFile());
        exe.addFileSource(main_o.getFile());

        const check = exe.check();
        check.checkInSymtab();
        check.checkNotPresent("external _bar");
        check.checkInSymtab();
        check.checkContains("external _foo");
        test_step.dependOn(&check.step);

        const run = exe.run();
        run.expectExitCode(1);
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(lib.getFile());
        exe.addFileSource(main_o.getFile());
        exe.addArg("-Wl,-all_load");

        const check = exe.check();
        check.checkInSymtab();
        check.checkContains("external _bar");
        check.checkInSymtab();
        check.checkContains("external _foo");
        test_step.dependOn(&check.step);

        const run = exe.run();
        run.expectExitCode(1);
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testBuildVersionMacOS(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-build-version-macos", "");

    {
        const obj = cc(b, "a.o", opts);
        obj.addEmptyMain();
        obj.addArg("-c");

        const exe = ld(b, "a.out", opts);
        exe.addFileSource(obj.getFile());
        exe.addArgs(&.{ "-syslibroot", opts.macos_sdk });

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("cmd BUILD_VERSION");
        check.checkExact("platform MACOS");
        check.checkExact("tool 6");
        check.checkInHeaders();
        check.checkNotPresent("cmd VERSION_MIN_MACOSX");
        test_step.dependOn(&check.step);
    }

    if (builtin.target.cpu.arch == .x86_64) {
        const obj = cc(b, "a.o", opts);
        obj.addEmptyMain();
        obj.addArgs(&.{ "-c", "-mmacos-version-min=10.13" });

        const exe = ld(b, "a.out", opts);
        exe.addFileSource(obj.getFile());
        exe.addArgs(&.{
            "-syslibroot",
            opts.macos_sdk,
            "-platform_version",
            "macos",
            "10.13",
            "10.13",
        });

        const check = exe.check();
        check.checkInHeaders();
        check.checkNotPresent("cmd BUILD_VERSION");
        check.checkInHeaders();
        check.checkExact("cmd VERSION_MIN_MACOSX");
        check.checkExact("version 10.13.0");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testBuildVersionIOS(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-build-version-ios", "");

    const ios_sdk = opts.ios_sdk orelse return skipTestStep(test_step);

    {
        const obj = cc(b, "a.o", opts);
        obj.addEmptyMain();
        obj.addArgs(&.{ "-c", "-isysroot", ios_sdk, "--target=arm64-ios16.4" });

        const exe = ld(b, "a.out", opts);
        exe.addFileSource(obj.getFile());
        exe.addArgs(&.{ "-syslibroot", ios_sdk });

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("cmd BUILD_VERSION");
        check.checkExact("platform IOS");
        check.checkExact("tool 6");
        check.checkInHeaders();
        check.checkNotPresent("cmd VERSION_MIN_IPHONEOS");
        test_step.dependOn(&check.step);
    }

    {
        const obj = cc(b, "a.o", opts);
        obj.addEmptyMain();
        obj.addArgs(&.{ "-c", "-isysroot", ios_sdk, "--target=arm64-ios11" });

        const exe = ld(b, "a.out", opts);
        exe.addFileSource(obj.getFile());
        exe.addArgs(&.{ "-syslibroot", ios_sdk });

        const check = exe.check();
        check.checkInHeaders();
        check.checkNotPresent("cmd BUILD_VERSION");
        check.checkInHeaders();
        check.checkExact("cmd VERSION_MIN_IPHONEOS");
        check.checkExact("version 11.0.0");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testDeadStrip(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-dead-strip", "");

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
    obj.addArg("-c");

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(obj.getFile());

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

        const run = exe.run();
        run.expectStdOutEqual("1 2\n");
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(obj.getFile());
        exe.addArg("-Wl,-dead_strip");

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

        const run = exe.run();
        run.expectStdOutEqual("1 2\n");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testDeadStripDylibs(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-dead-strip-dylibs", "");
    const main_c =
        \\#include <objc/runtime.h>
        \\int main() {
        \\  if (objc_getClass("NSObject") == 0) {
        \\    return -1;
        \\  }
        \\  if (objc_getClass("NSApplication") == 0) {
        \\    return -2;
        \\  }
        \\  return 0;
        \\}
    ;

    {
        const exe = cc(b, "main", opts);
        exe.addCSource(main_c);
        exe.addArgs(&.{ "-framework", "Cocoa" });

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("cmd LOAD_DYLIB");
        check.checkContains("Cocoa");
        check.checkInHeaders();
        check.checkExact("cmd LOAD_DYLIB");
        check.checkContains("libobjc");
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "main", opts);
        exe.addCSource(main_c);
        exe.addArgs(&.{ "-framework", "Cocoa", "-Wl,-dead_strip_dylibs" });

        const run = exe.run();
        run.expectExitCode(@as(u8, @bitCast(@as(i8, -2))));
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testDylib(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-dylib", "");

    const dylib = cc(b, "liba.dylib", opts);
    dylib.addCSource(
        \\#include<stdio.h>
        \\char world[] = "world";
        \\char* hello() {
        \\  return "Hello";
        \\}
    );
    dylib.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/liba.dylib" });

    const check = dylib.check();
    check.checkInHeaders();
    check.checkExact("header");
    check.checkNotPresent("PIE");
    test_step.dependOn(&check.step);

    const exe = cc(b, "main", opts);
    exe.addCSource(
        \\#include<stdio.h>
        \\char* hello();
        \\extern char world[];
        \\int main() {
        \\  printf("%s %s", hello(), world);
        \\  return 0;
        \\}
    );
    exe.addArg("-la");
    exe.addPrefixedDirectorySource("-L", dylib.getDir());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib.getDir());

    const run = exe.run();
    run.expectStdOutEqual("Hello world");
    test_step.dependOn(run.step());

    return test_step;
}

fn testDylibReexport(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-dylib-reexport", "");

    const a_o = cc(b, "a.o", opts);
    a_o.addCSource(
        \\int foo = 42;
        \\int getFoo() {
        \\  return foo;
        \\}
    );
    a_o.addArg("-c");

    const b_o = cc(b, "b.o", opts);
    b_o.addCSource(
        \\int getFoo();
        \\int getBar() {
        \\  return getFoo();
        \\}
    );
    b_o.addArg("-c");

    const main_o = cc(b, "main.o", opts);
    main_o.addCSource(
        \\int getFoo();
        \\int getBar();
        \\int main() {
        \\  return getBar() - getFoo();
        \\}
    );
    main_o.addArg("-c");

    const liba = cc(b, "liba.dylib", opts);
    liba.addFileSource(a_o.getFile());
    liba.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/liba.dylib" });

    const libb = cc(b, "libb.dylib", opts);
    libb.addFileSource(b_o.getFile());
    libb.addPrefixedDirectorySource("-L", liba.getDir());
    libb.addPrefixedDirectorySource("-Wl,-rpath,", liba.getDir());
    libb.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libb.dylib", "-Wl,-reexport-la" });

    {
        const check = libb.check();
        check.checkInHeaders();
        check.checkExact("cmd REEXPORT_DYLIB");
        check.checkExact("name @rpath/liba.dylib");
        check.checkInSymtab();
        check.checkExact("(undefined) external _getFoo (from liba)");
        test_step.dependOn(&check.step);
    }

    const libc = cc(b, "libc.dylib", opts);
    libc.addFileSource(a_o.getFile());
    libc.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libc.dylib" });

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addPrefixedDirectorySource("-L", libb.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libb.getDir());
        exe.addPrefixedDirectorySource("-L", libc.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libc.getDir());
        exe.addArgs(&.{ "-lb", "-lc" });

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("cmd LOAD_DYLIB");
        check.checkExact("name @rpath/libb.dylib");
        check.checkExact("cmd LOAD_DYLIB");
        check.checkExact("name @rpath/libc.dylib");
        check.checkInHeaders();
        check.checkExact("cmd LOAD_DYLIB");
        check.checkNotPresent("liba.dylib");
        check.checkInSymtab();
        check.checkExact("(undefined) external _getFoo (from libb)");
        check.checkInSymtab();
        check.checkExact("(undefined) external _getBar (from libb)");
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addPrefixedDirectorySource("-L", libb.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libb.getDir());
        exe.addPrefixedDirectorySource("-L", libc.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libc.getDir());
        exe.addArgs(&.{ "-lc", "-lb" });

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("cmd LOAD_DYLIB");
        check.checkExact("name @rpath/libc.dylib");
        check.checkExact("cmd LOAD_DYLIB");
        check.checkExact("name @rpath/libb.dylib");
        check.checkInHeaders();
        check.checkExact("cmd LOAD_DYLIB");
        check.checkNotPresent("liba.dylib");
        check.checkInSymtab();
        check.checkExact("(undefined) external _getFoo (from libc)");
        check.checkInSymtab();
        check.checkExact("(undefined) external _getBar (from libb)");
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testDylibReexportDeep(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-dylib-reexport-deep", "");

    const liba = cc(b, "liba.dylib", opts);
    liba.addCSource(
        \\int foo = 42;
        \\int getFoo() {
        \\  return foo;
        \\}
    );
    liba.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/liba.dylib" });

    const libb = cc(b, "libb.dylib", opts);
    libb.addCSource(
        \\int bar = 21;
        \\int getFoo();
        \\int getBar() {
        \\  return getFoo() - bar;
        \\}
    );
    libb.addPrefixedDirectorySource("-L", liba.getDir());
    libb.addPrefixedDirectorySource("-Wl,-rpath,", liba.getDir());
    libb.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libb.dylib", "-Wl,-reexport-la" });

    const libc = cc(b, "libc.dylib", opts);
    libc.addCSource(
        \\int foobar = 21;
        \\int getFoo();
        \\int getBar();
        \\int getFoobar() {
        \\  return getFoo() - getBar() - foobar;
        \\}
    );
    libc.addPrefixedDirectorySource("-L", libb.getDir());
    libc.addPrefixedDirectorySource("-Wl,-rpath,", libb.getDir());
    libc.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libc.dylib", "-Wl,-reexport-lb" });

    const exe = cc(b, "main", opts);
    exe.addCSource(
        \\int getFoobar();
        \\int main() {
        \\  return getFoobar();
        \\}
    );
    exe.addPrefixedDirectorySource("-L", libc.getDir());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", libc.getDir());
    exe.addArg("-lc");

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("cmd LOAD_DYLIB");
    check.checkExact("name @rpath/libc.dylib");
    check.checkInHeaders();
    check.checkExact("cmd LOAD_DYLIB");
    check.checkNotPresent("liba.dylib");
    check.checkInHeaders();
    check.checkExact("cmd LOAD_DYLIB");
    check.checkNotPresent("libb.dylib");
    check.checkInSymtab();
    check.checkExact("(undefined) external _getFoobar (from libc)");
    test_step.dependOn(&check.step);

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testDylibVersionTbd(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-dylib-version-tbd", "");

    const tbd = saveBytesToFile(b, "liba.tbd",
        \\--- !tapi-tbd
        \\tbd-version:     4
        \\targets:         [ x86_64-macos, arm64-macos ]
        \\uuids:
        \\  - target:          x86_64-macos
        \\    value:           DEADBEEF
        \\  - target:          arm64-macos
        \\    value:           BEEFDEAD
        \\install-name:    '@rpath/liba.dylib'
        \\current-version: 1.2
        \\exports:
        \\  - targets:     [ x86_64-macos, arm64-macos ]
        \\    symbols:     [ _foo ]
    );

    const exe = cc(b, "main", opts);
    exe.addEmptyMain();
    exe.addFileSource(tbd);

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("cmd LOAD_DYLIB");
    check.checkExact("name @rpath/liba.dylib");
    check.checkExact("current version 10200");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testEmptyObject(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-empty-object", "");

    const exe = cc(b, "main", opts);
    exe.addHelloWorldMain();
    exe.addCSource("");

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    return test_step;
}

fn testEntryPoint(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-entry-point", "");

    const exe = cc(b, "main", opts);
    exe.addCSource(
        \\#include<stdio.h>
        \\int non_main() {
        \\  printf("%d", 42);
        \\  return 0;
        \\}
    );
    exe.addArg("-Wl,-e,_non_main");

    const run = exe.run();
    run.expectStdOutEqual("42");
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("segname __TEXT");
    check.checkExtract("vmaddr {vmaddr}");
    check.checkInHeaders();
    check.checkExact("cmd MAIN");
    check.checkExtract("entryoff {entryoff}");
    check.checkInSymtab();
    check.checkExtract("{n_value} (__TEXT,__text) external _non_main");
    check.checkComputeCompare("vmaddr entryoff +", .{ .op = .eq, .value = .{ .variable = "n_value" } });
    test_step.dependOn(&check.step);

    return test_step;
}

fn testEntryPointArchive(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-entry-point-archive", "");

    const obj = cc(b, "main.o", opts);
    obj.addArg("-c");
    obj.addEmptyMain();

    const lib = ar(b, "libmain.a");
    lib.addFileSource(obj.getFile());

    {
        const exe = cc(b, "a.out", opts);
        exe.addArg("-lmain");
        exe.addPrefixedDirectorySource("-L", lib.getDir());

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addArgs(&.{ "-lmain", "-Wl,-dead_strip" });
        exe.addPrefixedDirectorySource("-L", lib.getDir());

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testEntryPointDylib(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-entry-point-dylib", "");

    const dylib = cc(b, "liba.dylib", opts);
    dylib.addCSource(
        \\extern int my_main();
        \\int bootstrap() {
        \\  return my_main();
        \\}
    );
    dylib.addArgs(&.{ "-shared", "-Wl,-undefined,dynamic_lookup", "-Wl,-install_name,@rpath/liba.dylib" });

    const exe = cc(b, "main", opts);
    exe.addCSource(
        \\#include<stdio.h>
        \\int my_main() {
        \\  fprintf(stdout, "Hello!\n");
        \\  return 0;
        \\}
    );
    exe.addArgs(&.{ "-Wl,-e,_bootstrap", "-Wl,-u,_my_main", "-la" });
    exe.addPrefixedDirectorySource("-L", dylib.getDir());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib.getDir());

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("segname __TEXT");
    check.checkExtract("vmaddr {text_vmaddr}");
    check.checkInHeaders();
    check.checkExact("sectname __stubs");
    check.checkExtract("addr {stubs_vmaddr}");
    check.checkInHeaders();
    check.checkExact("sectname __stubs");
    check.checkExtract("size {stubs_vmsize}");
    check.checkInHeaders();
    check.checkExact("cmd MAIN");
    check.checkExtract("entryoff {entryoff}");
    check.checkComputeCompare("text_vmaddr entryoff +", .{
        .op = .gte,
        .value = .{ .variable = "stubs_vmaddr" }, // The entrypoint should be a synthetic stub
    });
    check.checkComputeCompare("text_vmaddr entryoff + stubs_vmaddr -", .{
        .op = .lt,
        .value = .{ .variable = "stubs_vmsize" }, // The entrypoint should be a synthetic stub
    });
    test_step.dependOn(&check.step);

    const run = exe.run();
    run.expectStdOutEqual("Hello!\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testFatArchive(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-fat-archive", "");

    const a_c = "int foo = 42;";

    const lib_arm64 = blk: {
        const obj = cc(b, "a.o", opts);
        obj.addCSource(a_c);
        obj.addArgs(&.{ "-c", "-arch", "arm64" });

        const lib = ar(b, "liba.a");
        lib.addFileSource(obj.getFile());

        break :blk lib;
    };

    const lib_x64 = blk: {
        const obj = cc(b, "a.o", opts);
        obj.addCSource(a_c);
        obj.addArgs(&.{ "-c", "-arch", "x86_64" });

        const lib = ar(b, "liba.a");
        lib.addFileSource(obj.getFile());

        break :blk lib;
    };

    const fat_lib = lipo(b, "liba.a");
    fat_lib.addFileSource(lib_arm64.getFile());
    fat_lib.addFileSource(lib_x64.getFile());

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\#include<stdio.h>
        \\extern int foo;
        \\int main() {
        \\  printf("%d\n", foo);
        \\  return 0;
        \\}
    );
    exe.addFileSource(fat_lib.getFile());

    const run = exe.run();
    run.expectStdOutEqual("42\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testFatDylib(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-fat-dylib", "");

    const a_c = "int foo = 42;";

    const dylib_arm64 = cc(b, "liba.dylib", opts);
    dylib_arm64.addCSource(a_c);
    dylib_arm64.addArgs(&.{ "-shared", "-arch", "arm64", "-Wl,-install_name,@rpath/liba.dylib" });

    const dylib_x64 = cc(b, "liba.dylib", opts);
    dylib_x64.addCSource(a_c);
    dylib_x64.addArgs(&.{ "-shared", "-arch", "x86_64", "-Wl,-install_name,@rpath/liba.dylib" });

    const fat_lib = lipo(b, "liba.dylib");
    fat_lib.addFileSource(dylib_arm64.getFile());
    fat_lib.addFileSource(dylib_x64.getFile());

    const exe = cc(b, "main", opts);
    exe.addCSource(
        \\#include<stdio.h>
        \\extern int foo;
        \\int main() {
        \\  printf("%d\n", foo);
        \\  return 0;
        \\}
    );
    exe.addFileSource(fat_lib.getFile());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", fat_lib.getDir());

    const run = exe.run();
    run.expectStdOutEqual("42\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testFlatNamespace(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-flat-namespace", "");

    const liba = cc(b, "liba.dylib", opts);
    liba.addCSource(
        \\#include <stdio.h>
        \\int foo = 1;
        \\int* ptr_to_foo = &foo;
        \\int getFoo() {
        \\  return foo;
        \\}
        \\void printInA() {
        \\  printf("liba: getFoo()=%d, ptr_to_foo=%d\n", getFoo(), *ptr_to_foo);
        \\}
    );
    liba.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/liba.dylib", "-Wl,-flat_namespace" });

    {
        const check = liba.check();
        check.checkInDyldLazyBind();
        check.checkContains("(flat lookup) _getFoo");
        check.checkInIndirectSymtab();
        check.checkContains("_getFoo");
        test_step.dependOn(&check.step);
    }

    const libb = cc(b, "libb.dylib", opts);
    libb.addCSource(
        \\#include <stdio.h>
        \\int foo = 2;
        \\int* ptr_to_foo = &foo;
        \\int getFoo() {
        \\  return foo;
        \\}
        \\void printInB() {
        \\  printf("libb: getFoo()=%d, ptr_to_foo=%d\n", getFoo(), *ptr_to_foo);
        \\}
    );
    libb.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libb.dylib", "-Wl,-flat_namespace" });

    {
        const check = liba.check();
        check.checkInDyldLazyBind();
        check.checkContains("(flat lookup) _getFoo");
        check.checkInIndirectSymtab();
        check.checkContains("_getFoo");
        test_step.dependOn(&check.step);
    }

    const main_o = cc(b, "main.o", opts);
    main_o.addCSource(
        \\#include <stdio.h>
        \\int getFoo();
        \\extern int* ptr_to_foo;
        \\void printInA();
        \\void printInB();
        \\int main() {
        \\  printf("main: getFoo()=%d, ptr_to_foo=%d\n", getFoo(), *ptr_to_foo);
        \\  printInA();
        \\  printInB();
        \\  return 0;
        \\}
    );
    main_o.addArg("-c");

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addPrefixedDirectorySource("-L", liba.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", liba.getDir());
        exe.addPrefixedDirectorySource("-L", libb.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libb.getDir());
        exe.addArgs(&.{ "-la", "-lb", "-Wl,-flat_namespace" });

        const check = exe.check();
        check.checkInSymtab();
        check.checkExact("(undefined) external _getFoo (from flat lookup)");
        check.checkInSymtab();
        check.checkExact("(undefined) external _printInA (from flat lookup)");
        check.checkInSymtab();
        check.checkExact("(undefined) external _printInB (from flat lookup)");
        test_step.dependOn(&check.step);

        const run = exe.run();
        run.expectStdOutEqual(
            \\main: getFoo()=1, ptr_to_foo=1
            \\liba: getFoo()=1, ptr_to_foo=1
            \\libb: getFoo()=1, ptr_to_foo=1
            \\
        );
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addPrefixedDirectorySource("-L", liba.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", liba.getDir());
        exe.addPrefixedDirectorySource("-L", libb.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libb.getDir());
        exe.addArgs(&.{ "-lb", "-la", "-Wl,-flat_namespace" });

        const check = exe.check();
        check.checkInSymtab();
        check.checkExact("(undefined) external _getFoo (from flat lookup)");
        check.checkInSymtab();
        check.checkExact("(undefined) external _printInA (from flat lookup)");
        check.checkInSymtab();
        check.checkExact("(undefined) external _printInB (from flat lookup)");
        test_step.dependOn(&check.step);

        const run = exe.run();
        run.expectStdOutEqual(
            \\main: getFoo()=2, ptr_to_foo=2
            \\liba: getFoo()=2, ptr_to_foo=2
            \\libb: getFoo()=2, ptr_to_foo=2
            \\
        );
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testFlatNamespaceExe(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-flat-namespace-exe", "");

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\void bar() {}
        \\int main() {
        \\  bar();
        \\  return 0;
        \\}
    );
    exe.addArg("-Wl,-flat_namespace");

    const check = exe.check();
    check.checkInIndirectSymtab();
    check.checkNotPresent("_bar");
    test_step.dependOn(&check.step);

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testFlatNamespaceWeak(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-flat-namespace-weak", "");

    const liba = cc(b, "liba.dylib", opts);
    liba.addCSource(
        \\#include <stdio.h>
        \\int foo = 1;
        \\int getFoo() {
        \\  return foo;
        \\}
        \\void printInA() {
        \\  printf("liba=%d\n", getFoo());
        \\}
    );
    liba.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/liba.dylib", "-Wl,-flat_namespace" });

    {
        const check = liba.check();
        check.checkInDyldLazyBind();
        check.checkContains("(flat lookup) _getFoo");
        test_step.dependOn(&check.step);
    }

    const libb = cc(b, "libb.dylib", opts);
    libb.addCSource(
        \\#include <stdio.h>
        \\int foo = 2;
        \\__attribute__((weak)) int getFoo() {
        \\  return foo;
        \\}
        \\void printInB() {
        \\  printf("libb=%d\n", getFoo());
        \\}
    );
    libb.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libb.dylib", "-Wl,-flat_namespace" });

    {
        const check = libb.check();
        check.checkInDyldWeakBind();
        check.checkContains("(self) _getFoo");
        check.checkInDyldLazyBind();
        check.checkNotPresent("_getFoo");
        test_step.dependOn(&check.step);
    }

    const main_o = cc(b, "main.o", opts);
    main_o.addCSource(
        \\#include <stdio.h>
        \\int getFoo();
        \\void printInA();
        \\void printInB();
        \\int main() {
        \\  printf("main=%d\n", getFoo());
        \\  printInA();
        \\  printInB();
        \\  return 0;
        \\}
    );
    main_o.addArg("-c");

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addPrefixedDirectorySource("-L", liba.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", liba.getDir());
        exe.addPrefixedDirectorySource("-L", libb.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libb.getDir());
        exe.addArgs(&.{ "-la", "-lb", "-Wl,-flat_namespace" });

        const check = exe.check();
        check.checkInSymtab();
        check.checkExact("(undefined) external _getFoo (from flat lookup)");
        check.checkInSymtab();
        check.checkExact("(undefined) external _printInA (from flat lookup)");
        check.checkInSymtab();
        check.checkExact("(undefined) external _printInB (from flat lookup)");
        test_step.dependOn(&check.step);

        const run = exe.run();
        run.expectStdOutEqual(
            \\main=1
            \\liba=1
            \\libb=2
            \\
        );
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addPrefixedDirectorySource("-L", liba.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", liba.getDir());
        exe.addPrefixedDirectorySource("-L", libb.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libb.getDir());
        exe.addArgs(&.{ "-lb", "-la", "-Wl,-flat_namespace" });

        const check = exe.check();
        check.checkInSymtab();
        check.checkExact("(undefined) external _getFoo (from flat lookup)");
        check.checkInSymtab();
        check.checkExact("(undefined) external _printInA (from flat lookup)");
        check.checkInSymtab();
        check.checkExact("(undefined) external _printInB (from flat lookup)");
        test_step.dependOn(&check.step);

        const run = exe.run();

        // TODO: this is quite a huge difference between macOS versions.
        // I wonder what changed in dyld's behaviour.
        if (builtin.target.os.version_range.semver.isAtLeast(.{ .major = 12, .minor = 0, .patch = 0 }) orelse false) {
            run.expectStdOutEqual(
                \\main=2
                \\liba=2
                \\libb=2
                \\
            );
        } else {
            run.expectStdOutEqual(
                \\main=2
                \\liba=1
                \\libb=2
                \\
            );
        }
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testForceLoad(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-force-load", "");

    const obj = cc(b, "a.o", opts);
    obj.addCSource("int foo = 1;");
    obj.addArg("-c");

    const lib = ar(b, "liba.a");
    lib.addFileSource(obj.getFile());

    const main_o = cc(b, "main.o", opts);
    main_o.addEmptyMain();
    main_o.addArg("-c");

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(main_o.getFile());
        exe.addFileSource(lib.getFile());

        const run = exe.run();
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkNotPresent("external _foo");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(main_o.getFile());
        exe.addArg("-force_load");
        exe.addFileSource(lib.getFile());

        const run = exe.run();
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkContains("external _foo");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testHeaderpad(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-headerpad", "");

    const flags: []const []const u8 = &.{
        "-framework", "CoreFoundation",
        "-framework", "Foundation",
        "-framework", "Cocoa",
        "-framework", "CoreGraphics",
        "-framework", "CoreHaptics",
        "-framework", "CoreAudio",
        "-framework", "AVFoundation",
        "-framework", "CoreImage",
        "-framework", "CoreLocation",
        "-framework", "CoreML",
        "-framework", "CoreVideo",
        "-framework", "CoreText",
        "-framework", "CryptoKit",
        "-framework", "GameKit",
        "-framework", "SwiftUI",
        "-framework", "StoreKit",
        "-framework", "SpriteKit",
    };

    {
        const exe = cc(b, "a.out", opts);
        exe.addArgs(flags);
        exe.addArg("-Wl,-headerpad_max_install_names");
        exe.addEmptyMain();

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("sectname __text");
        check.checkExtract("offset {offset}");
        switch (builtin.cpu.arch) {
            .aarch64 => check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x4000 } }),
            .x86_64 => check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x1000 } }),
            else => unreachable,
        }
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addArgs(flags);
        exe.addArg("-Wl,-headerpad,0x10000");
        exe.addEmptyMain();

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("sectname __text");
        check.checkExtract("offset {offset}");
        check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x10000 } });
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addArgs(flags);
        exe.addArg("-Wl,-headerpad,0x10000");
        exe.addArg("-Wl,-headerpad_max_install_names");
        exe.addEmptyMain();

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("sectname __text");
        check.checkExtract("offset {offset}");
        check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x10000 } });
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addArgs(flags);
        exe.addArg("-Wl,-headerpad,0x1000");
        exe.addArg("-Wl,-headerpad_max_install_names");
        exe.addEmptyMain();

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("sectname __text");
        check.checkExtract("offset {offset}");
        switch (builtin.cpu.arch) {
            .aarch64 => check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x4000 } }),
            .x86_64 => check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x1000 } }),
            else => unreachable,
        }
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    return test_step;
}

// Adapted from https://github.com/llvm/llvm-project/blob/main/lld/test/MachO/weak-header-flags.s
fn testHeaderWeakFlags(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-header-weak-flags", "");

    const obj1 = cc(b, "a.o", opts);
    obj1.addAsmSource(
        \\.globl _x
        \\.weak_definition _x
        \\_x:
        \\ ret
    );
    obj1.addArg("-c");

    const lib = cc(b, "liba.dylib", opts);
    lib.addFileSource(obj1.getFile());
    lib.addArg("-shared");

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(obj1.getFile());
        exe.addEmptyMain();

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("header");
        check.checkContains("WEAK_DEFINES");
        check.checkInHeaders();
        check.checkExact("header");
        check.checkContains("BINDS_TO_WEAK");
        check.checkInExports();
        check.checkExtract("[WEAK] {vmaddr} _x");
        test_step.dependOn(&check.step);
    }

    {
        const obj = cc(b, "b.o", opts);
        obj.addArg("-c");

        switch (builtin.target.cpu.arch) {
            .aarch64 => obj.addAsmSource(
                \\.globl _main
                \\_main:
                \\  bl _x
                \\  ret
            ),
            .x86_64 => obj.addAsmSource(
                \\.globl _main
                \\_main:
                \\  callq _x
                \\  ret
            ),
            else => unreachable,
        }

        const exe = cc(b, "a.out", opts);
        exe.addFileSource(lib.getFile());
        exe.addFileSource(obj.getFile());

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("header");
        check.checkNotPresent("WEAK_DEFINES");
        check.checkInHeaders();
        check.checkExact("header");
        check.checkContains("BINDS_TO_WEAK");
        check.checkInExports();
        check.checkNotPresent("[WEAK] {vmaddr} _x");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addFileSource(lib.getFile());
        exe.addAsmSource(
            \\.globl _main, _x
            \\_x:
            \\
            \\_main:
            \\  ret
        );

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("header");
        check.checkNotPresent("WEAK_DEFINES");
        check.checkInHeaders();
        check.checkExact("header");
        check.checkNotPresent("BINDS_TO_WEAK");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testHelloC(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-hello-c", "");

    const exe = cc(b, "a.out", opts);
    exe.addHelloWorldMain();

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("header");
    check.checkContains("PIE");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testHelloZig(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-hello-zig", "");

    if (!opts.has_zig) return skipTestStep(test_step);

    const obj = zig(b, "main.o");
    obj.addZigSource(
        \\const std = @import("std");
        \\pub fn main() void {
        \\    std.io.getStdOut().writer().print("Hello world!\n", .{}) catch unreachable;
        \\}
    );
    obj.addArg("-fno-stack-check"); // TODO find a way to include Zig's crt

    const exe = cc(b, "main", opts);
    exe.addFileSource(obj.getFile());

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    return test_step;
}

fn testLayout(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-layout", "");

    const exe = cc(b, "a.out", opts);
    exe.addHelloWorldMain();

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("cmd SEGMENT_64");
    check.checkExact("segname __LINKEDIT");
    check.checkExtract("fileoff {fileoff}");
    check.checkExtract("filesz {filesz}");
    check.checkInHeaders();
    check.checkExact("cmd DYLD_INFO_ONLY");
    check.checkExtract("rebaseoff {rebaseoff}");
    check.checkExtract("rebasesize {rebasesize}");
    check.checkExtract("bindoff {bindoff}");
    check.checkExtract("bindsize {bindsize}");
    check.checkExtract("lazybindoff {lazybindoff}");
    check.checkExtract("lazybindsize {lazybindsize}");
    check.checkExtract("exportoff {exportoff}");
    check.checkExtract("exportsize {exportsize}");
    check.checkInHeaders();
    check.checkExact("cmd FUNCTION_STARTS");
    check.checkExtract("dataoff {fstartoff}");
    check.checkExtract("datasize {fstartsize}");
    check.checkInHeaders();
    check.checkExact("cmd DATA_IN_CODE");
    check.checkExtract("dataoff {diceoff}");
    check.checkExtract("datasize {dicesize}");
    check.checkInHeaders();
    check.checkExact("cmd SYMTAB");
    check.checkExtract("symoff {symoff}");
    check.checkExtract("nsyms {symnsyms}");
    check.checkExtract("stroff {stroff}");
    check.checkExtract("strsize {strsize}");
    check.checkInHeaders();
    check.checkExact("cmd DYSYMTAB");
    check.checkExtract("indirectsymoff {dysymoff}");
    check.checkExtract("nindirectsyms {dysymnsyms}");

    switch (builtin.cpu.arch) {
        .aarch64 => {
            check.checkInHeaders();
            check.checkExact("cmd CODE_SIGNATURE");
            check.checkExtract("dataoff {codesigoff}");
            check.checkExtract("datasize {codesigsize}");
        },
        .x86_64 => {},
        else => unreachable,
    }

    // DYLD_INFO_ONLY subsections are in order: rebase < bind < lazy < export,
    // and there are no gaps between them
    check.checkComputeCompare("rebaseoff rebasesize +", .{ .op = .eq, .value = .{ .variable = "bindoff" } });
    check.checkComputeCompare("bindoff bindsize +", .{ .op = .eq, .value = .{ .variable = "lazybindoff" } });
    check.checkComputeCompare("lazybindoff lazybindsize +", .{ .op = .eq, .value = .{ .variable = "exportoff" } });

    // FUNCTION_STARTS directly follows DYLD_INFO_ONLY (no gap)
    check.checkComputeCompare("exportoff exportsize +", .{ .op = .eq, .value = .{ .variable = "fstartoff" } });

    // DATA_IN_CODE directly follows FUNCTION_STARTS (no gap)
    check.checkComputeCompare("fstartoff fstartsize +", .{ .op = .eq, .value = .{ .variable = "diceoff" } });

    // SYMTAB directly follows DATA_IN_CODE (no gap)
    check.checkComputeCompare("diceoff dicesize +", .{ .op = .eq, .value = .{ .variable = "symoff" } });

    // DYSYMTAB directly follows SYMTAB (no gap)
    check.checkComputeCompare("symnsyms 16 symoff * +", .{ .op = .eq, .value = .{ .variable = "dysymoff" } });

    // STRTAB follows DYSYMTAB with possible gap
    check.checkComputeCompare("dysymnsyms 4 dysymoff * +", .{ .op = .lte, .value = .{ .variable = "stroff" } });

    // all LINKEDIT sections apart from CODE_SIGNATURE are 8-bytes aligned
    check.checkComputeCompare("rebaseoff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.checkComputeCompare("bindoff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.checkComputeCompare("lazybindoff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.checkComputeCompare("exportoff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.checkComputeCompare("fstartoff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.checkComputeCompare("diceoff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.checkComputeCompare("symoff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.checkComputeCompare("stroff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });
    check.checkComputeCompare("dysymoff 8 %", .{ .op = .eq, .value = .{ .literal = 0 } });

    switch (builtin.cpu.arch) {
        .aarch64 => {
            // LINKEDIT segment does not extend beyond, or does not include, CODE_SIGNATURE data
            check.checkComputeCompare("fileoff filesz codesigoff codesigsize + - -", .{
                .op = .eq,
                .value = .{ .literal = 0 },
            });

            // CODE_SIGNATURE data offset is 16-bytes aligned
            check.checkComputeCompare("codesigoff 16 %", .{ .op = .eq, .value = .{ .literal = 0 } });
        },
        .x86_64 => {
            // LINKEDIT segment does not extend beyond, or does not include, strtab data
            check.checkComputeCompare("fileoff filesz stroff strsize + - -", .{
                .op = .eq,
                .value = .{ .literal = 0 },
            });
        },
        else => unreachable,
    }

    test_step.dependOn(&check.step);

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    return test_step;
}

fn testLargeBss(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-large-bss", "");

    // TODO this test used use a 4GB zerofill section but this actually fails and causes every
    // linker I tried misbehave in different ways. This only happened on arm64. I thought that
    // maybe S_GB_ZEROFILL section is an answer to this but it doesn't seem supported by dyld
    // anymore. When I get some free time I will re-investigate this.
    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\char arr[0x1000000];
        \\int main() {
        \\  return arr[2000];
        \\}
    );

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testLinkOrder(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-link-order", "");

    const a_o = cc(b, "a.o", opts);
    a_o.addCSource(
        \\int foo = 42;
        \\int bar;
        \\int foobar = -2;
        \\int get_foo() {
        \\  return foo;
        \\}
        \\int get_bar() {
        \\  return bar;
        \\}
    );
    a_o.addArg("-c");

    const c_o = cc(b, "c.o", opts);
    c_o.addCSource(
        \\int foo = -1;
        \\int bar = 42;
        \\int foobar = -1;
        \\int get_foo() {
        \\  return foo;
        \\}
        \\int get_bar() {
        \\  return bar;
        \\}
    );
    c_o.addArg("-c");

    const main_o = cc(b, "main.o", opts);
    main_o.addCSource(
        \\#include <stdio.h>
        \\__attribute__((weak)) int foobar = 42;
        \\extern int get_foo();
        \\extern int get_bar();
        \\int main() {
        \\  printf("%d %d %d", get_foo(), get_bar(), foobar);
        \\  return 0;
        \\}
    );
    main_o.addArg("-c");

    const liba = ar(b, "libb.a");
    liba.addFileSource(a_o.getFile());

    const libc = cc(b, "libc.dylib", opts);
    libc.addFileSource(c_o.getFile());
    libc.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libc.dylib" });

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(libc.getFile());
        exe.addFileSource(liba.getFile());
        exe.addFileSource(main_o.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libc.getDir());

        const run = exe.run();
        run.expectStdOutEqual("-1 42 42");
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(liba.getFile());
        exe.addFileSource(libc.getFile());
        exe.addFileSource(main_o.getFile());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libc.getDir());

        const run = exe.run();
        run.expectStdOutEqual("42 0 -2");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testLoadHidden(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-load-hidden", "");

    const obj = cc(b, "a.o", opts);
    obj.addCSource(
        \\int foo = 42;
        \\int getFoo() { return foo; }
    );
    obj.addArg("-c");

    const lib = ar(b, "liba.a");
    lib.addFileSource(obj.out);

    const main_o = cc(b, "main.o", opts);
    main_o.addCSource(
        \\int actuallyGetFoo();
        \\int main() {
        \\  return actuallyGetFoo();
        \\}
    );
    main_o.addArg("-c");

    const dylib_o = cc(b, "b.o", opts);
    dylib_o.addCSource(
        \\extern int foo;
        \\int getFoo();
        \\int actuallyGetFoo() { return foo; };
    );
    dylib_o.addArg("-c");

    {
        const dylib = cc(b, "libb.dylib", opts);
        dylib.addFileSource(dylib_o.getFile());
        dylib.addPrefixedDirectorySource("-L", lib.getDir());
        dylib.addArgs(&.{ "-shared", "-Wl,-hidden-la", "-Wl,-install_name,@rpath/libb.dylib" });

        const check = dylib.check();
        check.checkInSymtab();
        check.checkContains("external _actuallyGetFoo");
        check.checkNotPresent("external _foo");
        check.checkNotPresent("external _getFoo");
        test_step.dependOn(&check.step);

        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addPrefixedDirectorySource("-L", dylib.getDir());
        exe.addArg("-lb");
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib.getDir());

        const run = exe.run();
        run.expectExitCode(42);
        test_step.dependOn(run.step());
    }

    {
        const dylib = cc(b, "libb.dylib", opts);
        dylib.addFileSource(dylib_o.getFile());
        dylib.addArg("-load_hidden");
        dylib.addFileSource(lib.getFile());
        dylib.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libb.dylib" });

        const check = dylib.check();
        check.checkInSymtab();
        check.checkContains("external _actuallyGetFoo");
        check.checkNotPresent("external _foo");
        check.checkNotPresent("external _getFoo");
        test_step.dependOn(&check.step);

        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addPrefixedDirectorySource("-L", dylib.getDir());
        exe.addArg("-lb");
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib.getDir());

        const run = exe.run();
        run.expectExitCode(42);
        test_step.dependOn(run.step());
    }

    {
        const dylib = cc(b, "libb.dylib", opts);
        dylib.addFileSource(dylib_o.getFile());
        dylib.addFileSource(lib.getFile());
        dylib.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libb.dylib" });

        const check = dylib.check();
        check.checkInSymtab();
        check.checkContains("external _actuallyGetFoo");
        check.checkContains("external _foo");
        check.checkContains("external _getFoo");
        test_step.dependOn(&check.step);

        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addPrefixedDirectorySource("-L", dylib.getDir());
        exe.addArg("-lb");
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib.getDir());

        const run = exe.run();
        run.expectExitCode(42);
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testMergeLiterals(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-merge-literals", "");

    const a_o = cc(b, "a.o", opts);
    a_o.addCSource(
        \\double q1() { return 1.2345; }
        \\const char* s1 = "hello";
    );
    a_o.addArg("-c");

    const b_o = cc(b, "b.o", opts);
    b_o.addCSource(
        \\#include <stdio.h>
        \\double q2() { return 1.2345; }
        \\const char* s2 = "hello";
        \\const char* s3 = "world";
        \\extern double q1();
        \\extern const char* s1;
        \\int main() {
        \\  printf("%s, %s, %s, %f, %f", s1, s2, s3, q1(), q2());
        \\  return 0;
        \\}
    );
    b_o.addArg("-c");

    {
        const exe = cc(b, "main1", opts);
        exe.addFileSource(a_o.getFile());
        exe.addFileSource(b_o.getFile());

        const run = exe.run();
        run.expectStdOutEqual("hello, hello, world, 1.234500, 1.234500");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.dumpSection("__TEXT,__const");
        check.checkContains("\x8d\x97n\x12\x83\xc0\xf3?");
        check.dumpSection("__TEXT,__cstring");
        check.checkContains("hello\x00world\x00%s, %s, %s, %f, %f\x00");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "main2", opts);
        exe.addFileSource(b_o.getFile());
        exe.addFileSource(a_o.getFile());

        const run = exe.run();
        run.expectStdOutEqual("hello, hello, world, 1.234500, 1.234500");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.dumpSection("__TEXT,__const");
        check.checkContains("\x8d\x97n\x12\x83\xc0\xf3?");
        check.dumpSection("__TEXT,__cstring");
        check.checkContains("hello\x00world\x00%s, %s, %s, %f, %f\x00");
        test_step.dependOn(&check.step);
    }

    {
        const c_o = ld(b, "c.o", opts);
        c_o.addFileSource(a_o.getFile());
        c_o.addFileSource(b_o.getFile());
        c_o.addArg("-r");

        const exe = cc(b, "main3", opts);
        exe.addFileSource(c_o.getFile());

        const run = exe.run();
        run.expectStdOutEqual("hello, hello, world, 1.234500, 1.234500");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.dumpSection("__TEXT,__const");
        check.checkContains("\x8d\x97n\x12\x83\xc0\xf3?");
        check.dumpSection("__TEXT,__cstring");
        check.checkContains("hello\x00world\x00%s, %s, %s, %f, %f\x00");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

/// This particular test case will generate invalid machine code that will segfault at runtime.
/// However, this is by design as we want to test that the linker does not panic when linking it
/// which is also the case for the system linker and lld - linking succeeds, runtime segfaults.
/// It should also be mentioned that runtime segfault is not due to the linker but faulty input asm.
fn testMergeLiterals2(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-merge-literals-2", "");

    if (builtin.target.cpu.arch != .aarch64) return skipTestStep(test_step);

    const a_o = cc(b, "a.o", opts);
    a_o.addAsmSource(
        \\.globl _q1
        \\.globl _s1
        \\
        \\.align 4
        \\_q1:
        \\  adrp x0, L._q1@PAGE
        \\  ldr x0, [x0, L._q1@PAGEOFF]
        \\  ret
        \\
        \\.section __TEXT,__cstring,cstring_literals
        \\_s1:
        \\  .asciz "hello"
        \\
        \\.section __TEXT,__literal8,8byte_literals
        \\.align 8
        \\L._q1:
        \\  .double 1.2345
    );
    a_o.addArg("-c");

    const b_o = cc(b, "b.o", opts);
    b_o.addAsmSource(
        \\.globl _q2
        \\.globl _s2
        \\.globl _s3
        \\
        \\.align 4
        \\_q2:
        \\  adrp x0, L._q2@PAGE
        \\  ldr x0, [x0, L._q2@PAGEOFF]
        \\  ret
        \\
        \\.section __TEXT,__cstring,cstring_literals
        \\_s2:
        \\  .asciz "hello"
        \\_s3:
        \\  .asciz "world"
        \\
        \\.section __TEXT,__literal8,8byte_literals
        \\.align 8
        \\L._q2:
        \\  .double 1.2345
    );
    b_o.addArg("-c");

    const main_o = cc(b, "main.o", opts);
    main_o.addCSource(
        \\#include <stdio.h>
        \\extern double q1();
        \\extern double q2();
        \\extern const char* s1;
        \\extern const char* s2;
        \\extern const char* s3;
        \\int main() {
        \\  printf("%s, %s, %s, %f, %f", s1, s2, s3, q1(), q2());
        \\  return 0;
        \\}
    );
    main_o.addArg("-c");

    const exe = cc(b, "main1", opts);
    exe.addFileSource(a_o.getFile());
    exe.addFileSource(b_o.getFile());
    exe.addFileSource(main_o.getFile());

    const check = exe.check();
    check.dumpSection("__TEXT,__const");
    check.checkContains("\x8d\x97n\x12\x83\xc0\xf3?");
    check.dumpSection("__TEXT,__cstring");
    check.checkContains("hello\x00world\x00%s, %s, %s, %f, %f\x00");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testMergeLiteralsObjc(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-merge-literals-objc", "");

    const main_o = cc(b, "main.o", opts);
    main_o.addObjCSource(
        \\@import Foundation;
        \\
        \\extern void foo();
        \\
        \\int main() {
        \\  NSString *thing = @"aaa";
        \\
        \\  SEL sel = @selector(lowercaseString);
        \\  NSString *lower = (([thing respondsToSelector:sel]) ? @"YES" : @"NO");
        \\  NSLog (@"Responds to lowercaseString: %@", lower);
        \\  if ([thing respondsToSelector:sel]) //(lower == @"YES")
        \\      NSLog(@"lowercaseString is: %@", [thing lowercaseString]);
        \\
        \\  foo();
        \\}
    );
    main_o.addArgs(&.{ "-c", "-fmodules" });

    const a_o = cc(b, "a.o", opts);
    a_o.addObjCSource(
        \\@import Foundation;
        \\
        \\void foo() {
        \\  NSString *thing = @"aaa";
        \\  SEL sel = @selector(lowercaseString);
        \\  NSString *lower = (([thing respondsToSelector:sel]) ? @"YES" : @"NO");
        \\  NSLog (@"Responds to lowercaseString in foo(): %@", lower);
        \\  if ([thing respondsToSelector:sel]) //(lower == @"YES")
        \\      NSLog(@"lowercaseString in foo() is: %@", [thing lowercaseString]);
        \\  SEL sel2 = @selector(uppercaseString);
        \\  NSString *upper = (([thing respondsToSelector:sel2]) ? @"YES" : @"NO");
        \\  NSLog (@"Responds to uppercaseString in foo(): %@", upper);
        \\  if ([thing respondsToSelector:sel2]) //(upper == @"YES")
        \\      NSLog(@"uppercaseString in foo() is: %@", [thing uppercaseString]);
        \\}
    );
    a_o.addArgs(&.{ "-c", "-fmodules" });

    {
        const exe = cc(b, "main1", opts);
        exe.addFileSource(main_o.getFile());
        exe.addFileSource(a_o.getFile());
        exe.addArgs(&.{ "-framework", "Foundation" });

        const run = exe.run();
        run.expectStdErrFuzzy("Responds to lowercaseString: YES");
        run.expectStdErrFuzzy("lowercaseString is: aaa");
        run.expectStdErrFuzzy("Responds to lowercaseString in foo(): YES");
        run.expectStdErrFuzzy("lowercaseString in foo() is: aaa");
        run.expectStdErrFuzzy("Responds to uppercaseString in foo(): YES");
        run.expectStdErrFuzzy("uppercaseString in foo() is: AAA");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.dumpSection("__TEXT,__objc_methname");
        check.checkContains("lowercaseString\x00");
        check.dumpSection("__TEXT,__objc_methname");
        check.checkContains("uppercaseString\x00");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "main2", opts);
        exe.addFileSource(a_o.getFile());
        exe.addFileSource(main_o.getFile());
        exe.addArgs(&.{ "-framework", "Foundation" });

        const run = exe.run();
        run.expectStdErrFuzzy("Responds to lowercaseString: YES");
        run.expectStdErrFuzzy("lowercaseString is: aaa");
        run.expectStdErrFuzzy("Responds to lowercaseString in foo(): YES");
        run.expectStdErrFuzzy("lowercaseString in foo() is: aaa");
        run.expectStdErrFuzzy("Responds to uppercaseString in foo(): YES");
        run.expectStdErrFuzzy("uppercaseString in foo() is: AAA");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.dumpSection("__TEXT,__objc_methname");
        check.checkContains("lowercaseString\x00");
        check.dumpSection("__TEXT,__objc_methname");
        check.checkContains("uppercaseString\x00");
        test_step.dependOn(&check.step);
    }

    {
        const b_o = ld(b, "b.o", opts);
        b_o.addFileSource(a_o.getFile());
        b_o.addFileSource(main_o.getFile());
        b_o.addArg("-r");

        const exe = cc(b, "main3", opts);
        exe.addFileSource(b_o.getFile());
        exe.addArgs(&.{ "-framework", "Foundation" });

        const run = exe.run();
        run.expectStdErrFuzzy("Responds to lowercaseString: YES");
        run.expectStdErrFuzzy("lowercaseString is: aaa");
        run.expectStdErrFuzzy("Responds to lowercaseString in foo(): YES");
        run.expectStdErrFuzzy("lowercaseString in foo() is: aaa");
        run.expectStdErrFuzzy("Responds to uppercaseString in foo(): YES");
        run.expectStdErrFuzzy("uppercaseString in foo() is: AAA");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.dumpSection("__TEXT,__objc_methname");
        check.checkContains("lowercaseString\x00");
        check.dumpSection("__TEXT,__objc_methname");
        check.checkContains("uppercaseString\x00");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testMhExecuteHeader(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-mh-execute-header", "");

    const exe = cc(b, "a.out", opts);
    exe.addEmptyMain();

    const check = exe.check();
    check.checkInSymtab();
    check.checkContains("[referenced dynamically] external __mh_execute_header");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testNeededFramework(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-needed-framework", "");

    const exe = cc(b, "a.out", opts);
    exe.addArgs(&.{ "-Wl,-needed_framework,Cocoa", "-Wl,-dead_strip_dylibs" });
    exe.addEmptyMain();

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("cmd LOAD_DYLIB");
    check.checkContains("Cocoa");
    test_step.dependOn(&check.step);

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testNeededLibrary(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-needed-library", "");

    const dylib = cc(b, "liba.dylib", opts);
    dylib.addCSource("int a = 42;");
    dylib.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/liba.dylib" });

    const exe = cc(b, "a.out", opts);
    exe.addEmptyMain();
    exe.addArgs(&.{ "-Wl,-needed-la", "-Wl,-dead_strip_dylibs" });
    exe.addPrefixedDirectorySource("-L", dylib.getDir());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib.getDir());

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("cmd LOAD_DYLIB");
    check.checkContains("liba.dylib");
    test_step.dependOn(&check.step);

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testNoDeadStrip(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-no-dead-strip", "");

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\__attribute__((used)) int bogus1 = 0;
        \\int bogus2 = 0;
        \\int foo = 42;
        \\int main() {
        \\  return foo - 42;
        \\}
    );
    exe.addArg("-Wl,-dead_strip");

    const check = exe.check();
    check.checkInSymtab();
    check.checkContains("external _bogus1");
    check.checkInSymtab();
    check.checkNotPresent("external _bogus2");
    test_step.dependOn(&check.step);

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testNoExportsDylib(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-no-exports-dylib", "");

    const dylib = cc(b, "liba.dylib", opts);
    dylib.addCSource("static void abc() {}");
    dylib.addArg("-shared");

    const check = dylib.check();
    check.checkInSymtab();
    check.checkNotPresent("external _abc");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testObjc(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-objc", "");

    const a_o = cc(b, "a.o", opts);
    a_o.addObjCSource(
        \\#import <Foundation/Foundation.h>
        \\@interface Foo : NSObject
        \\@end
        \\@implementation Foo
        \\@end
    );
    a_o.addArg("-c");

    const liba = ar(b, "liba.a");
    liba.addFileSource(a_o.out);

    {
        const exe = cc(b, "a.out", opts);
        exe.addEmptyMain();
        exe.addPrefixedDirectorySource("-L", liba.getDir());
        exe.addArg("-la");

        const check = exe.check();
        check.checkInSymtab();
        check.checkNotPresent("_OBJC_");
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addEmptyMain();
        exe.addPrefixedDirectorySource("-L", liba.getDir());
        exe.addArgs(&.{ "-la", "-ObjC", "-framework", "Foundation" });

        const check = exe.check();
        check.checkInSymtab();
        check.checkContains("_OBJC_");
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testObjcStubs(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-objc-stubs", "");

    if (!opts.has_objc_msgsend_stubs) return skipTestStep(test_step);

    const exe = cc(b, "a.out", opts);
    exe.addObjCSource(
        \\@import Foundation;
        \\@interface Foo : NSObject
        \\@property (nonatomic, assign) NSString* name;
        \\@end
        \\@implementation Foo
        \\- (void)bar {
        \\    printf("%s", [self.name UTF8String]);
        \\}
        \\@end
        \\int main() {
        \\    Foo *foo = [[Foo alloc] init];
        \\    foo.name = @"Foo";
        \\    [foo bar];
        \\    return 0;
        \\}
    );
    exe.addArgs(&.{ "-fmodules", "-fobjc-msgsend-selector-stubs", "-framework", "Foundation" });

    const run = exe.run();
    run.expectStdOutEqual("Foo");
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("sectname __objc_stubs");
    check.checkInHeaders();
    check.checkExact("sectname __objc_methname");
    check.checkInHeaders();
    check.checkExact("sectname __objc_selrefs");
    check.checkInSymtab();
    check.checkContains("(__TEXT,__objc_stubs) (was private external) _objc_msgSend$bar");
    check.checkInSymtab();
    check.checkContains("(__TEXT,__objc_stubs) (was private external) _objc_msgSend$name");
    check.checkInSymtab();
    check.checkContains("(__TEXT,__objc_stubs) (was private external) _objc_msgSend$setName");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testObjcStubs2(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-objc-stubs-2", "");

    if (!opts.has_objc_msgsend_stubs) return skipTestStep(test_step);

    const all_h = saveBytesToFile(b, "all.h",
        \\#import <Foundation/Foundation.h>
        \\
        \\@interface Foo : NSObject
        \\@property (nonatomic, assign) NSString* name;
        \\- (void) foo;
        \\@end
        \\@interface Bar : NSObject
        \\@property (nonatomic, assign) NSString* name;
        \\- (void) bar;
        \\- (void) foobar: (Foo*) foo;
        \\@end
    );

    const foo_o = cc(b, "foo.o", opts);
    foo_o.addObjCSource(
        \\#import <Foundation/Foundation.h>
        \\#import "all.h"
        \\@implementation Foo
        \\- (void)foo {
        \\    printf("%s", [self.name UTF8String]);
        \\}
        \\@end
    );
    foo_o.addArgs(&.{ "-c", "-fobjc-msgsend-selector-stubs" });
    foo_o.addPrefixedDirectorySource("-I", all_h.dirname());

    const bar_o = cc(b, "bar.o", opts);
    bar_o.addObjCSource(
        \\#import <Foundation/Foundation.h>
        \\#import "all.h"
        \\@implementation Bar
        \\- (void)bar {
        \\    printf("%s", [self.name UTF8String]);
        \\}
        \\- (void)foobar: (Foo*) foo {
        \\    printf("%s%s", [foo.name UTF8String], [self.name UTF8String]);
        \\}
        \\@end
    );
    bar_o.addArgs(&.{ "-c", "-fobjc-msgsend-selector-stubs" });
    bar_o.addPrefixedDirectorySource("-I", all_h.dirname());

    const main_o = cc(b, "main.o", opts);
    main_o.addObjCSource(
        \\#import <Foundation/Foundation.h>
        \\#import "all.h"
        \\int main() {
        \\    Foo *foo = [[Foo alloc] init];
        \\    foo.name = @"Foo";
        \\    Bar *bar = [[Bar alloc] init];
        \\    bar.name = @"Bar";
        \\    [foo foo];
        \\    [bar bar];
        \\    [bar foobar:foo];
        \\    return 0;
        \\}
    );
    main_o.addArgs(&.{ "-c", "-fobjc-msgsend-selector-stubs" });
    main_o.addPrefixedDirectorySource("-I", all_h.dirname());

    const exe = cc(b, "main", opts);
    exe.addFileSource(main_o.getFile());
    exe.addFileSource(foo_o.getFile());
    exe.addFileSource(bar_o.getFile());
    exe.addArgs(&.{ "-framework", "Foundation" });

    const run = exe.run();
    run.expectStdOutEqual("FooBarFooBar");
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("sectname __objc_stubs");
    check.checkInHeaders();
    check.checkExact("sectname __objc_methname");
    check.checkInHeaders();
    check.checkExact("sectname __objc_selrefs");
    check.checkInSymtab();
    check.checkContains("(__TEXT,__objc_stubs) (was private external) _objc_msgSend$foo");
    check.checkInSymtab();
    check.checkContains("(__TEXT,__objc_stubs) (was private external) _objc_msgSend$bar");
    check.checkInSymtab();
    check.checkContains("(__TEXT,__objc_stubs) (was private external) _objc_msgSend$foobar");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testObjCpp(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-obj-cpp", "");

    const includes = WriteFile.create(b);
    _ = includes.add("Foo.h",
        \\#import <Foundation/Foundation.h>
        \\@interface Foo : NSObject
        \\- (NSString *)name;
        \\@end
    );

    const foo_o = cc(b, "foo.o", opts);
    foo_o.addObjCppSource(
        \\#import "Foo.h"
        \\@implementation Foo
        \\- (NSString *)name
        \\{
        \\      NSString *str = [[NSString alloc] initWithFormat:@"Zig"];
        \\      return str;
        \\}
        \\@end
    );
    foo_o.addPrefixedDirectorySource("-I", includes.getDirectory());
    foo_o.addArg("-c");

    const exe = cc(b, "a.out", opts);
    exe.addObjCppSource(
        \\#import "Foo.h"
        \\#import <assert.h>
        \\#include <iostream>
        \\int main(int argc, char *argv[])
        \\{
        \\  @autoreleasepool {
        \\      Foo *foo = [[Foo alloc] init];
        \\      NSString *result = [foo name];
        \\      std::cout << "Hello from C++ and " << [result UTF8String];
        \\      assert([result isEqualToString:@"Zig"]);
        \\      return 0;
        \\  }
        \\}
    );
    exe.addPrefixedDirectorySource("-I", includes.getDirectory());
    exe.addFileSource(foo_o.getFile());
    exe.addArgs(&.{ "-framework", "Foundation", "-lc++" });

    const run = exe.run();
    run.expectStdOutEqual("Hello from C++ and Zig");
    test_step.dependOn(run.step());

    return test_step;
}

fn testPagezeroSize(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-pagezero-size", "");

    {
        const exe = cc(b, "a.out", opts);
        exe.addArg("-Wl,-pagezero_size,0x4000");
        exe.addEmptyMain();

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("LC 0");
        check.checkExact("segname __PAGEZERO");
        check.checkExact("vmaddr 0");
        check.checkExact("vmsize 4000");
        check.checkInHeaders();
        check.checkExact("segname __TEXT");
        check.checkExact("vmaddr 4000");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addArg("-Wl,-pagezero_size,0");
        exe.addEmptyMain();

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("LC 0");
        check.checkExact("segname __TEXT");
        check.checkExact("vmaddr 0");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testReexportsZig(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-reexports-zig", "");

    if (!opts.has_zig) return skipTestStep(test_step);

    const obj = zig(b, "a.o");
    obj.addZigSource(
        \\const x: i32 = 42;
        \\export fn foo() i32 {
        \\    return x;
        \\}
        \\comptime {
        \\    @export(foo, .{ .name = "bar", .linkage = .strong });
        \\}
    );

    const lib = ar(b, "liba.a");
    lib.addFileSource(obj.getFile());

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\extern int foo();
        \\extern int bar();
        \\int main() {
        \\  return bar() - foo();
        \\}
    );
    exe.addFileSource(lib.getFile());

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testRelocatable(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-relocatable", "");

    const a_c =
        \\#include <stdexcept>
        \\int try_me() {
        \\  throw std::runtime_error("Oh no!");
        \\}
    ;
    const b_c =
        \\extern int try_me();
        \\int try_again() {
        \\  return try_me();
        \\}
    ;
    const main_c =
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
    ;
    const exp_stdout = "exception=Oh no!";

    {
        const a_o = cc(b, "a.o", opts);
        a_o.addCppSource(a_c);
        a_o.addArg("-c");

        const b_o = cc(b, "b.o", opts);
        b_o.addCppSource(b_c);
        b_o.addArg("-c");

        const c_o = ld(b, "c.o", opts);
        c_o.addFileSource(a_o.getFile());
        c_o.addFileSource(b_o.getFile());
        c_o.addArg("-r");

        const exe = cc(b, "a.out", opts);
        exe.addCppSource(main_c);
        exe.addFileSource(c_o.getFile());
        exe.addArg("-lc++");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    {
        const a_o = cc(b, "a.o", opts);
        a_o.addCppSource(a_c);
        a_o.addArg("-c");

        const b_o = cc(b, "b.o", opts);
        b_o.addCppSource(b_c);
        b_o.addArg("-c");

        const main_o = cc(b, "main.o", opts);
        main_o.addCppSource(main_c);
        main_o.addArg("-c");

        const c_o = ld(b, "c.o", opts);
        c_o.addFileSource(a_o.getFile());
        c_o.addFileSource(b_o.getFile());
        c_o.addFileSource(main_o.getFile());
        c_o.addArg("-r");

        const exe = cc(b, "a.out", opts);
        exe.addFileSource(c_o.getFile());
        exe.addArg("-lc++");

        const run = exe.run();
        run.expectStdOutEqual(exp_stdout);
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testRelocatableZig(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-relocatable-zig", "");

    if (!opts.has_zig) return skipTestStep(test_step);

    const a_o = zig(b, "a.o");
    a_o.addZigSource(
        \\const std = @import("std");
        \\export var foo: i32 = 0;
        \\export fn incrFoo() void {
        \\    foo += 1;
        \\    std.debug.print("incrFoo={d}\n", .{foo});
        \\}
    );
    a_o.addArg("-fno-stack-check");

    const b_o = zig(b, "b.o");
    b_o.addZigSource(
        \\const std = @import("std");
        \\extern var foo: i32;
        \\export fn decrFoo() void {
        \\    foo -= 1;
        \\    std.debug.print("decrFoo={d}\n", .{foo});
        \\}
    );
    b_o.addArg("-fno-stack-check");

    const main_o = zig(b, "main.o");
    main_o.addZigSource(
        \\const std = @import("std");
        \\extern var foo: i32;
        \\extern fn incrFoo() void;
        \\extern fn decrFoo() void;
        \\pub fn main() void {
        \\    const init = foo;
        \\    incrFoo();
        \\    decrFoo();
        \\    if (init == foo) @panic("Oh no!");
        \\}
    );
    main_o.addArg("-fno-stack-check");

    const c_o = ld(b, "c.o", opts);
    c_o.addFileSource(a_o.getFile());
    c_o.addFileSource(b_o.getFile());
    c_o.addFileSource(main_o.getFile());
    c_o.addArg("-r");

    const exe = cc(b, "a.out", opts);
    exe.addFileSource(c_o.getFile());

    const run = exe.run();
    run.expectStdErrFuzzy("incrFoo=1");
    run.expectStdErrFuzzy("decrFoo=0");
    run.expectStdErrFuzzy("panic: Oh no!");
    test_step.dependOn(run.step());

    return test_step;
}

fn testSearchStrategy(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-search-strategy", "");

    const obj = cc(b, "a.o", opts);
    obj.addArg("-c");
    obj.addCSource(
        \\#include<stdio.h>
        \\char world[] = "world";
        \\char* hello() {
        \\  return "Hello";
        \\}
    );

    const lib = ar(b, "liba.a");
    lib.addFileSource(obj.getFile());

    const dylib = ld(b, "liba.dylib", opts);
    dylib.addFileSource(obj.getFile());
    dylib.addArgs(&.{ "-syslibroot", opts.macos_sdk, "-dylib", "-install_name", "@rpath/liba.dylib" });

    const main_c =
        \\#include<stdio.h>
        \\char* hello();
        \\extern char world[];
        \\int main() {
        \\  printf("%s %s", hello(), world);
        \\  return 0;
        \\}
    ;

    {
        const exe = cc(b, "a.out", opts);
        exe.addCSource(main_c);
        exe.addArgs(&.{ "-Wl,-search_dylibs_first", "-la" });
        exe.addPrefixedDirectorySource("-L", lib.getDir());
        exe.addPrefixedDirectorySource("-L", dylib.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib.getDir());

        const run = exe.run();
        run.expectStdOutEqual("Hello world");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("cmd LOAD_DYLIB");
        check.checkContains("liba.dylib");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addCSource(main_c);
        exe.addArgs(&.{ "-Wl,-search_paths_first", "-la" });
        exe.addPrefixedDirectorySource("-L", lib.getDir());
        exe.addPrefixedDirectorySource("-L", dylib.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib.getDir());

        const run = exe.run();
        run.expectStdOutEqual("Hello world");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("cmd LOAD_DYLIB");
        check.checkNotPresent("liba.dylib");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testSectionBoundarySymbols(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-section-boundary-symbols", "");

    const obj1 = cc(b, "a.o", opts);
    obj1.addCppSource(
        \\constexpr const char* MESSAGE __attribute__((used, section("__DATA_CONST,__message_ptr"))) = "codebase";
    );
    obj1.addArgs(&.{ "-std=c++17", "-c" });

    const main_o = cc(b, "main.o", opts);
    main_o.addCSource(
        \\#include <stdio.h>
        \\const char* interop();
        \\int main() {
        \\  printf("All your %s are belong to us.\n", interop());
        \\  return 0;
        \\}
    );
    main_o.addArg("-c");

    {
        const obj2 = cc(b, "b.o", opts);
        obj2.addCppSource(
            \\extern const char* message_pointer __asm("section$start$__DATA_CONST$__message_ptr");
            \\extern "C" const char* interop() {
            \\  return message_pointer;
            \\}
        );
        obj2.addArgs(&.{ "-std=c++17", "-c" });

        const exe = cc(b, "main", opts);
        exe.addFileSource(obj1.getFile());
        exe.addFileSource(obj2.getFile());
        exe.addFileSource(main_o.getFile());

        const run = exe.run();
        run.expectStdOutEqual("All your codebase are belong to us.\n");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkNotPresent("external section$start$__DATA_CONST$__message_ptr");
        test_step.dependOn(&check.step);
    }

    {
        const obj2 = cc(b, "b.o", opts);
        obj2.addCppSource(
            \\extern const char* message_pointer __asm("section$start$__DATA_CONST$__not_present");
            \\extern "C" const char* interop() {
            \\  return message_pointer;
            \\}
        );
        obj2.addArgs(&.{ "-std=c++17", "-c" });

        const exe = cc(b, "main", opts);
        exe.addFileSource(obj1.getFile());
        exe.addFileSource(obj2.getFile());
        exe.addFileSource(main_o.getFile());

        const run = exe.run();
        run.expectStdOutEqual("All your (null) are belong to us.\n");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkNotPresent("external section$start$__DATA_CONST$__not_present");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testSegmentBoundarySymbols(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-segment-boundary-symbols", "");

    const obj1 = cc(b, "a.o", opts);
    obj1.addCppSource(
        \\constexpr const char* MESSAGE __attribute__((used, section("__DATA_CONST_1,__message_ptr"))) = "codebase";
    );
    obj1.addArgs(&.{ "-std=c++17", "-c" });

    const main_o = cc(b, "main.o", opts);
    main_o.addCSource(
        \\#include <stdio.h>
        \\const char* interop();
        \\int main() {
        \\  printf("All your %s are belong to us.\n", interop());
        \\  return 0;
        \\}
    );
    main_o.addArg("-c");

    {
        const obj2 = cc(b, "b.o", opts);
        obj2.addCppSource(
            \\extern const char* message_pointer __asm("segment$start$__DATA_CONST_1");
            \\extern "C" const char* interop() {
            \\  return message_pointer;
            \\}
        );
        obj2.addArgs(&.{ "-std=c++17", "-c" });

        const exe = cc(b, "main", opts);
        exe.addFileSource(obj1.getFile());
        exe.addFileSource(obj2.getFile());
        exe.addFileSource(main_o.getFile());

        const run = exe.run();
        run.expectStdOutEqual("All your codebase are belong to us.\n");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkNotPresent("external segment$start$__DATA_CONST_1");
        test_step.dependOn(&check.step);
    }

    {
        const obj2 = cc(b, "b.o", opts);
        obj2.addCppSource(
            \\extern const char* message_pointer __asm("segment$start$__DATA_1");
            \\extern "C" const char* interop() {
            \\  return message_pointer;
            \\}
        );
        obj2.addArgs(&.{ "-std=c++17", "-c" });

        const exe = cc(b, "main", opts);
        exe.addFileSource(obj1.getFile());
        exe.addFileSource(obj2.getFile());
        exe.addFileSource(main_o.getFile());

        const check = exe.check();
        check.checkInHeaders();
        check.checkExact("cmd SEGMENT_64");
        check.checkExact("segname __DATA_1");
        check.checkExtract("vmsize {vmsize}");
        check.checkExtract("filesz {filesz}");
        check.checkComputeCompare("vmsize", .{ .op = .eq, .value = .{ .literal = 0 } });
        check.checkComputeCompare("filesz", .{ .op = .eq, .value = .{ .literal = 0 } });
        check.checkInSymtab();
        check.checkNotPresent("external segment$start$__DATA_1");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testStackSize(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-stack-size", "");

    const exe = cc(b, "a.out", opts);
    exe.addEmptyMain();
    exe.addArg("-Wl,-stack_size,0x100000000");

    const run = exe.run();
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("cmd MAIN");
    check.checkExact("stacksize 100000000");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testSymbolStabs(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-symbol-stabs", "");

    const a_o = cc(b, "a.o", opts);
    a_o.addCSource(
        \\int x;
        \\int get_x() {
        \\  return x;
        \\}
        \\void incr_x() {
        \\  x += 1;
        \\}
    );
    a_o.addArgs(&.{ "-c", "-g" });

    const b_o = cc(b, "b.o", opts);
    b_o.addArgs(&.{ "-c", "-g" });

    switch (builtin.target.cpu.arch) {
        .aarch64 => b_o.addAsmSource(
            \\.globl _foo
            \\_foo:
            \\  mov x0, #42
            \\  ret
            \\.globl _bar
            \\_bar:
            \\  stp fp, lr, [sp, #-0x10]!
            \\  bl _foo
            \\  ldp fp, lr, [sp], #0x10
            \\  ret
        ),
        .x86_64 => b_o.addAsmSource(
            \\.globl _foo
            \\_foo:
            \\  mov $42, %rax
            \\  ret
            \\.globl _bar
            \\_bar:
            \\  sub $8, %rsp
            \\  call _foo
            \\  add $8, %rsp
            \\  ret
        ),
        else => unreachable,
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addCSource(
            \\#include <stdio.h>
            \\int get_x();
            \\void incr_x();
            \\int bar();
            \\void print_x() {
            \\  printf("x=%d\n", get_x());
            \\}
            \\void print_bar() {
            \\  printf("bar=%d\n", bar());
            \\}
            \\int main() {
            \\  print_x();
            \\  incr_x();
            \\  print_x();
            \\  print_bar();
            \\  return 0;
            \\}
        );
        exe.addFileSource(a_o.getFile());
        exe.addFileSource(b_o.getFile());
        exe.addArg("-g");

        const run = exe.run();
        run.expectStdOutEqual(
            \\x=0
            \\x=1
            \\bar=42
            \\
        );
        test_step.dependOn(run.step());

        // TODO check for _foo and _bar having set sizes in stabs

    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addCSource(
            \\#include <stdio.h>
            \\int get_x();
            \\void incr_x();
            \\int bar();
            \\void print_x() {
            \\  printf("x=%d\n", get_x());
            \\}
            \\void print_bar() {
            \\  printf("bar=%d\n", bar());
            \\}
            \\int main() {
            \\  print_x();
            \\  incr_x();
            \\  print_x();
            \\  print_bar();
            \\  return 0;
            \\}
        );
        exe.addFileSource(a_o.getFile());
        exe.addFileSource(b_o.getFile());
        exe.addArgs(&.{ "-g", "-Wl,-dead_strip" });

        const run = exe.run();
        run.expectStdOutEqual(
            \\x=0
            \\x=1
            \\bar=42
            \\
        );
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTbdv3(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-tbdv3", "");

    const dylib = cc(b, "liba.dylib", opts);
    dylib.addArg("-shared");
    dylib.addCSource("int getFoo() { return 42; }");

    const tbd = saveBytesToFile(b, "liba.tbd",
        \\--- !tapi-tbd-v3
        \\archs:           [ arm64, x86_64 ]
        \\uuids:           [ 'arm64: DEADBEEF', 'x86_64: BEEFDEAD' ]
        \\platform:        macos
        \\install-name:    @rpath/liba.dylib
        \\current-version: 0
        \\exports:         
        \\  - archs:           [ arm64, x86_64 ]
        \\    symbols:         [ _getFoo ]
    );

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\#include <stdio.h>
        \\int getFoo();
        \\int main() {
        \\  return getFoo() - 42;
        \\}
    );
    exe.addFileSource(tbd);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib.getDir());

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testTentative(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-tentative", "");

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

fn testThunks(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-thunks", "");

    if (builtin.target.cpu.arch != .aarch64) return skipTestStep(test_step);

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
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
    );

    const run = exe.run();
    run.expectStdOutEqual("bar=42, foo=0, foobar=42");
    run.expectExitCode(0);
    test_step.dependOn(run.step());

    return test_step;
}

fn testTls(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-tls", "");

    const dylib = cc(b, "liba.dylib", opts);
    dylib.addCSource(
        \\_Thread_local int a;
        \\int getA() {
        \\  return a;
        \\}
    );
    dylib.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/liba.dylib" });

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\#include<stdio.h>
        \\extern _Thread_local int a;
        \\extern int getA();
        \\int getA2() {
        \\  return a;
        \\}
        \\int main() {
        \\  a = 2;
        \\  printf("%d %d %d", a, getA(), getA2());
        \\  return 0;
        \\}
    );
    exe.addArg("-la");
    exe.addPrefixedDirectorySource("-L", dylib.getDir());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib.getDir());

    const run = exe.run();
    run.expectStdOutEqual("2 2 2");
    test_step.dependOn(run.step());

    return test_step;
}

fn testTwoLevelNamespace(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-two-level-namespace", "");

    const liba = cc(b, "liba.dylib", opts);
    liba.addCSource(
        \\#include <stdio.h>
        \\int foo = 1;
        \\int* ptr_to_foo = &foo;
        \\int getFoo() {
        \\  return foo;
        \\}
        \\void printInA() {
        \\  printf("liba: getFoo()=%d, ptr_to_foo=%d\n", getFoo(), *ptr_to_foo);
        \\}
    );
    liba.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/liba.dylib", "-Wl,-two_levelnamespace" });

    {
        const check = liba.check();
        check.checkInDyldLazyBind();
        check.checkNotPresent("(flat lookup) _getFoo");
        check.checkInIndirectSymtab();
        check.checkNotPresent("_getFoo");
        test_step.dependOn(&check.step);
    }

    const libb = cc(b, "libb.dylib", opts);
    libb.addCSource(
        \\#include <stdio.h>
        \\int foo = 2;
        \\int* ptr_to_foo = &foo;
        \\int getFoo() {
        \\  return foo;
        \\}
        \\void printInB() {
        \\  printf("libb: getFoo()=%d, ptr_to_foo=%d\n", getFoo(), *ptr_to_foo);
        \\}
    );
    libb.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libb.dylib", "-Wl,-two_levelnamespace" });

    {
        const check = libb.check();
        check.checkInDyldLazyBind();
        check.checkNotPresent("(flat lookup) _getFoo");
        check.checkInIndirectSymtab();
        check.checkNotPresent("_getFoo");
        test_step.dependOn(&check.step);
    }

    const main_o = cc(b, "main.o", opts);
    main_o.addCSource(
        \\#include <stdio.h>
        \\int getFoo();
        \\extern int* ptr_to_foo;
        \\void printInA();
        \\void printInB();
        \\int main() {
        \\  printf("main: getFoo()=%d, ptr_to_foo=%d\n", getFoo(), *ptr_to_foo);
        \\  printInA();
        \\  printInB();
        \\  return 0;
        \\}
    );
    main_o.addArg("-c");

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addPrefixedDirectorySource("-L", liba.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", liba.getDir());
        exe.addPrefixedDirectorySource("-L", libb.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libb.getDir());
        exe.addArgs(&.{ "-la", "-lb", "-Wl,-two_levelnamespace" });

        const check = exe.check();
        check.checkInSymtab();
        check.checkExact("(undefined) external _getFoo (from liba)");
        check.checkInSymtab();
        check.checkExact("(undefined) external _printInA (from liba)");
        check.checkInSymtab();
        check.checkExact("(undefined) external _printInB (from libb)");
        test_step.dependOn(&check.step);

        const run = exe.run();
        run.expectStdOutEqual(
            \\main: getFoo()=1, ptr_to_foo=1
            \\liba: getFoo()=1, ptr_to_foo=1
            \\libb: getFoo()=2, ptr_to_foo=2
            \\
        );
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, "main", opts);
        exe.addFileSource(main_o.getFile());
        exe.addPrefixedDirectorySource("-L", liba.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", liba.getDir());
        exe.addPrefixedDirectorySource("-L", libb.getDir());
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libb.getDir());
        exe.addArgs(&.{ "-lb", "-la", "-Wl,-two_levelnamespace" });

        const check = exe.check();
        check.checkInSymtab();
        check.checkExact("(undefined) external _getFoo (from libb)");
        check.checkInSymtab();
        check.checkExact("(undefined) external _printInA (from liba)");
        check.checkInSymtab();
        check.checkExact("(undefined) external _printInB (from libb)");
        test_step.dependOn(&check.step);

        const run = exe.run();
        run.expectStdOutEqual(
            \\main: getFoo()=2, ptr_to_foo=2
            \\liba: getFoo()=1, ptr_to_foo=1
            \\libb: getFoo()=2, ptr_to_foo=2
            \\
        );
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testTlsLargeTbss(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-tls-large-tbss", "");

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\#include <stdio.h>
        \\_Thread_local int x[0x8000];
        \\_Thread_local int y[0x8000];
        \\int main() {
        \\  x[0] = 3;
        \\  x[0x7fff] = 5;
        \\  printf("%d %d %d %d %d %d\n", x[0], x[1], x[0x7fff], y[0], y[1], y[0x7fff]);
        \\}
    );

    const run = exe.run();
    run.expectStdOutEqual("3 0 5 0 0 0\n");
    test_step.dependOn(run.step());

    return test_step;
}

// https://github.com/ziglang/zig/issues/19221
fn testTlsPointers(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-tls-pointers", "");

    const includes = WriteFile.create(b);
    _ = includes.add("foo.h",
        \\template<typename just4fun>
        \\struct Foo {
        \\  
        \\public:
        \\  static int getVar() {
        \\  static int thread_local var = 0;
        \\  ++var;
        \\  return var;
        \\}
        \\};
    );

    const bar_o = cc(b, "bar.o", opts);
    bar_o.addCppSource(
        \\#include "foo.h"
        \\int bar() {
        \\  int v1 = Foo<int>::getVar();
        \\  return v1;
        \\}
    );
    bar_o.addArgs(&.{ "-c", "-std=c++17" });
    bar_o.addPrefixedDirectorySource("-I", includes.getDirectory());

    const baz_o = cc(b, "baz.o", opts);
    baz_o.addCppSource(
        \\#include "foo.h"
        \\int baz() {
        \\  int v1 = Foo<unsigned>::getVar();
        \\  return v1;
        \\}
    );
    baz_o.addArgs(&.{ "-c", "-std=c++17" });
    baz_o.addPrefixedDirectorySource("-I", includes.getDirectory());

    const main_o = cc(b, "main.o", opts);
    main_o.addCppSource(
        \\extern int bar();
        \\extern int baz();
        \\int main() {
        \\  int v1 = bar();
        \\  int v2 = baz();
        \\  return v1 != v2;
        \\}
    );
    main_o.addArgs(&.{ "-c", "-std=c++17" });
    main_o.addPrefixedDirectorySource("-I", includes.getDirectory());

    const exe = cc(b, "a.out", opts);
    exe.addFileSource(bar_o.getFile());
    exe.addFileSource(baz_o.getFile());
    exe.addFileSource(main_o.getFile());
    exe.addArg("-lc++");

    const run = exe.run();
    run.expectExitCode(0);
    test_step.dependOn(run.step());

    return test_step;
}

fn testUndefinedFlag(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-undefined-flag", "");

    const obj = cc(b, "a.o", opts);
    obj.addCSource("int foo = 42;");
    obj.addArg("-c");

    const lib = ar(b, "liba.a");
    lib.addFileSource(obj.getFile());

    {
        const exe = cc(b, "a.out", opts);
        exe.addEmptyMain();
        exe.addArgs(&.{ "-Wl,-u,_foo", "-la" });
        exe.addPrefixedDirectorySource("-L", lib.getDir());

        const run = exe.run();
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkContains("_foo");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addEmptyMain();
        exe.addArgs(&.{ "-Wl,-u,_foo", "-la", "-Wl,-dead_strip" });
        exe.addPrefixedDirectorySource("-L", lib.getDir());

        const run = exe.run();
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkContains("_foo");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addEmptyMain();
        exe.addFileSource(obj.getFile());

        const run = exe.run();
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkContains("_foo");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, "a.out", opts);
        exe.addEmptyMain();
        exe.addFileSource(obj.getFile());
        exe.addArg("-Wl,-dead_strip");

        const run = exe.run();
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkNotPresent("_foo");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testUnwindInfo(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-unwind-info", "");

    const all_h = saveBytesToFile(b, "all.h",
        \\#ifndef ALL
        \\#define ALL
        \\
        \\#include <cstddef>
        \\#include <string>
        \\#include <stdexcept>
        \\
        \\struct SimpleString {
        \\  SimpleString(size_t max_size);
        \\  ~SimpleString();
        \\
        \\  void print(const char* tag) const;
        \\  bool append_line(const char* x);
        \\
        \\private:
        \\  size_t max_size;
        \\  char* buffer;
        \\  size_t length;
        \\};
        \\
        \\struct SimpleStringOwner {
        \\  SimpleStringOwner(const char* x);
        \\  ~SimpleStringOwner();
        \\
        \\private:
        \\  SimpleString string;
        \\};
        \\
        \\class Error: public std::exception {
        \\public:
        \\  explicit Error(const char* msg) : msg{ msg } {}
        \\  virtual ~Error() noexcept {}
        \\  virtual const char* what() const noexcept {
        \\    return msg.c_str();
        \\  }
        \\
        \\protected:
        \\  std::string msg;
        \\};
        \\
        \\#endif
    );

    const main_c =
        \\#include "all.h"
        \\#include <cstdio>
        \\
        \\void fn_c() {
        \\  SimpleStringOwner c{ "cccccccccc" };
        \\}
        \\
        \\void fn_b() {
        \\  SimpleStringOwner b{ "b" };
        \\  fn_c();
        \\}
        \\
        \\int main() {
        \\  try {
        \\    SimpleStringOwner a{ "a" };
        \\    fn_b();
        \\    SimpleStringOwner d{ "d" };
        \\  } catch (const Error& e) {
        \\    printf("Error: %s\n", e.what());
        \\  } catch(const std::exception& e) {
        \\    printf("Exception: %s\n", e.what());
        \\  }
        \\  return 0;
        \\}
    ;
    const simple_string_c =
        \\#include "all.h"
        \\#include <cstdio>
        \\#include <cstring>
        \\
        \\SimpleString::SimpleString(size_t max_size)
        \\: max_size{ max_size }, length{} {
        \\  if (max_size == 0) {
        \\    throw Error{ "Max size must be at least 1." };
        \\  }
        \\  buffer = new char[max_size];
        \\  buffer[0] = 0;
        \\}
        \\
        \\SimpleString::~SimpleString() {
        \\  delete[] buffer;
        \\}
        \\
        \\void SimpleString::print(const char* tag) const {
        \\  printf("%s: %s", tag, buffer);
        \\}
        \\
        \\bool SimpleString::append_line(const char* x) {
        \\  const auto x_len = strlen(x);
        \\  if (x_len + length + 2 > max_size) return false;
        \\  std::strncpy(buffer + length, x, max_size - length);
        \\  length += x_len;
        \\  buffer[length++] = '\n';
        \\  buffer[length] = 0;
        \\  return true;
        \\}
    ;
    const simple_string_owner_c =
        \\#include "all.h"
        \\
        \\SimpleStringOwner::SimpleStringOwner(const char* x) : string{ 10 } {
        \\  if (!string.append_line(x)) {
        \\    throw Error{ "Not enough memory!" };
        \\  }
        \\  string.print("Constructed");
        \\}
        \\
        \\SimpleStringOwner::~SimpleStringOwner() {
        \\  string.print("About to destroy");
        \\}
    ;
    const exp_stdout =
        \\Constructed: a
        \\Constructed: b
        \\About to destroy: b
        \\About to destroy: a
        \\Error: Not enough memory!
        \\
    ;

    const flags: []const []const u8 = &.{ "-std=c++17", "-c" };
    const obj = cc(b, "main.o", opts);
    obj.addCppSource(main_c);
    obj.addPrefixedDirectorySource("-I", all_h.dirname());
    obj.addArgs(flags);

    const obj1 = cc(b, "simple_string.o", opts);
    obj1.addCppSource(simple_string_c);
    obj1.addPrefixedDirectorySource("-I", all_h.dirname());
    obj1.addArgs(flags);

    const obj2 = cc(b, "simple_string_owner.o", opts);
    obj2.addCppSource(simple_string_owner_c);
    obj2.addPrefixedDirectorySource("-I", all_h.dirname());
    obj2.addArgs(flags);

    const exe = ld(b, "main", opts);
    exe.addArgs(&.{ "-syslibroot", opts.macos_sdk, "-lc++" });
    exe.addFileSource(obj.getFile());
    exe.addFileSource(obj1.getFile());
    exe.addFileSource(obj2.getFile());

    const run = exe.run();
    run.expectStdOutEqual(exp_stdout);
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkInSymtab();
    check.checkContains("external ___gxx_personality_v0");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testUnwindInfoNoSubsectionsArm64(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-unwind-info-no-subsections-arm64", "");

    if (builtin.target.cpu.arch != .aarch64) return skipTestStep(test_step);

    const a_o = cc(b, "a.o", opts);
    a_o.addAsmSource(
        \\.globl _foo
        \\.align 4
        \\_foo: 
        \\  .cfi_startproc
        \\  stp     x29, x30, [sp, #-32]!
        \\  .cfi_def_cfa_offset 32
        \\  .cfi_offset w30, -24
        \\  .cfi_offset w29, -32
        \\  mov x29, sp
        \\  .cfi_def_cfa w29, 32
        \\  bl      _bar
        \\  ldp     x29, x30, [sp], #32
        \\  .cfi_restore w29
        \\  .cfi_restore w30
        \\  .cfi_def_cfa_offset 0
        \\  ret
        \\  .cfi_endproc
        \\
        \\.globl _bar
        \\.align 4
        \\_bar:
        \\  .cfi_startproc
        \\  sub     sp, sp, #32
        \\  .cfi_def_cfa_offset -32
        \\  stp     x29, x30, [sp, #16]
        \\  .cfi_offset w30, -24
        \\  .cfi_offset w29, -32
        \\  mov x29, sp
        \\  .cfi_def_cfa w29, 32
        \\  mov     w0, #4
        \\  ldp     x29, x30, [sp, #16]
        \\  .cfi_restore w29
        \\  .cfi_restore w30
        \\  add     sp, sp, #32
        \\  .cfi_def_cfa_offset 0
        \\  ret
        \\  .cfi_endproc
    );
    a_o.addArg("-c");

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\#include <stdio.h>
        \\int foo();
        \\int main() {
        \\  printf("%d\n", foo());
        \\  return 0;
        \\}
    );
    exe.addFileSource(a_o.getFile());

    const run = exe.run();
    run.expectStdOutEqual("4\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testUnwindInfoNoSubsectionsX64(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-unwind-info-no-subsections-x64", "");

    if (builtin.target.cpu.arch != .x86_64) return skipTestStep(test_step);

    const a_o = cc(b, "a.o", opts);
    a_o.addAsmSource(
        \\.globl _foo
        \\_foo: 
        \\  .cfi_startproc
        \\  push    %rbp
        \\  .cfi_def_cfa_offset 8
        \\  .cfi_offset %rbp, -8
        \\  mov     %rsp, %rbp
        \\  .cfi_def_cfa_register %rbp
        \\  call    _bar
        \\  pop     %rbp
        \\  .cfi_restore %rbp
        \\  .cfi_def_cfa_offset 0
        \\  ret
        \\  .cfi_endproc
        \\
        \\.globl _bar
        \\_bar:
        \\  .cfi_startproc
        \\  push     %rbp
        \\  .cfi_def_cfa_offset 8
        \\  .cfi_offset %rbp, -8
        \\  mov     %rsp, %rbp
        \\  .cfi_def_cfa_register %rbp
        \\  mov     $4, %rax
        \\  pop     %rbp
        \\  .cfi_restore %rbp
        \\  .cfi_def_cfa_offset 0
        \\  ret
        \\  .cfi_endproc
    );
    a_o.addArg("-c");

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\#include <stdio.h>
        \\int foo();
        \\int main() {
        \\  printf("%d\n", foo());
        \\  return 0;
        \\}
    );
    exe.addFileSource(a_o.getFile());

    const run = exe.run();
    run.expectStdOutEqual("4\n");
    test_step.dependOn(run.step());

    return test_step;
}

// Adapted from https://github.com/llvm/llvm-project/blob/main/lld/test/MachO/weak-binding.s
fn testWeakBind(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-weak-bind", "");

    if (builtin.target.cpu.arch != .x86_64) return skipTestStep(test_step); // TODO

    const lib = cc(b, "libfoo.dylib", opts);
    lib.addAsmSource(
        \\.globl _weak_dysym
        \\.weak_definition _weak_dysym
        \\_weak_dysym:
        \\  .quad 0x1234
        \\
        \\.globl _weak_dysym_for_gotpcrel
        \\.weak_definition _weak_dysym_for_gotpcrel
        \\_weak_dysym_for_gotpcrel:
        \\  .quad 0x1234
        \\
        \\.globl _weak_dysym_fn
        \\.weak_definition _weak_dysym_fn
        \\_weak_dysym_fn:
        \\  ret
        \\
        \\.section __DATA,__thread_vars,thread_local_variables
        \\
        \\.globl _weak_dysym_tlv
        \\.weak_definition _weak_dysym_tlv
        \\_weak_dysym_tlv:
        \\  .quad 0x1234
    );
    lib.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libfoo.dylib" });

    {
        const check = lib.check();
        check.checkInExports();
        check.checkExtract("[WEAK] {vmaddr1} _weak_dysym");
        check.checkExtract("[WEAK] {vmaddr2} _weak_dysym_for_gotpcrel");
        check.checkExtract("[WEAK] {vmaddr3} _weak_dysym_fn");
        check.checkExtract("[THREAD_LOCAL, WEAK] {vmaddr4} _weak_dysym_tlv");
        test_step.dependOn(&check.step);
    }

    const exe = cc(b, "a.out", opts);
    exe.addAsmSource(
        \\.globl _main, _weak_external, _weak_external_for_gotpcrel, _weak_external_fn
        \\.weak_definition _weak_external, _weak_external_for_gotpcrel, _weak_external_fn, _weak_internal, _weak_internal_for_gotpcrel, _weak_internal_fn
        \\
        \\_main:
        \\  mov _weak_dysym_for_gotpcrel@GOTPCREL(%rip), %rax
        \\  mov _weak_external_for_gotpcrel@GOTPCREL(%rip), %rax
        \\  mov _weak_internal_for_gotpcrel@GOTPCREL(%rip), %rax
        \\  mov _weak_tlv@TLVP(%rip), %rax
        \\  mov _weak_dysym_tlv@TLVP(%rip), %rax
        \\  mov _weak_internal_tlv@TLVP(%rip), %rax
        \\  callq _weak_dysym_fn
        \\  callq _weak_external_fn
        \\  callq _weak_internal_fn
        \\  mov $0, %rax
        \\  ret
        \\
        \\_weak_external:
        \\  .quad 0x1234
        \\
        \\_weak_external_for_gotpcrel:
        \\  .quad 0x1234
        \\
        \\_weak_external_fn:
        \\  ret
        \\
        \\_weak_internal:
        \\  .quad 0x1234
        \\
        \\_weak_internal_for_gotpcrel:
        \\  .quad 0x1234
        \\
        \\_weak_internal_fn:
        \\  ret
        \\
        \\.data
        \\  .quad _weak_dysym
        \\  .quad _weak_external + 2
        \\  .quad _weak_internal
        \\
        \\.tbss _weak_tlv$tlv$init, 4, 2
        \\.tbss _weak_internal_tlv$tlv$init, 4, 2
        \\
        \\.section __DATA,__thread_vars,thread_local_variables
        \\.globl _weak_tlv
        \\.weak_definition  _weak_tlv, _weak_internal_tlv
        \\
        \\_weak_tlv:
        \\  .quad __tlv_bootstrap
        \\  .quad 0
        \\  .quad _weak_tlv$tlv$init
        \\
        \\_weak_internal_tlv:
        \\  .quad __tlv_bootstrap
        \\  .quad 0
        \\  .quad _weak_internal_tlv$tlv$init
    );
    exe.addFileSource(lib.getFile());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", lib.getDir());

    {
        const check = exe.check();

        check.checkInExports();
        check.checkExtract("[WEAK] {vmaddr1} _weak_external");
        check.checkExtract("[WEAK] {vmaddr2} _weak_external_for_gotpcrel");
        check.checkExtract("[WEAK] {vmaddr3} _weak_external_fn");
        check.checkExtract("[THREAD_LOCAL, WEAK] {vmaddr4} _weak_tlv");

        check.checkInDyldBind();
        check.checkContains("(libfoo.dylib) _weak_dysym_for_gotpcrel");
        check.checkContains("(libfoo.dylib) _weak_dysym_fn");
        check.checkContains("(libfoo.dylib) _weak_dysym");
        check.checkContains("(libfoo.dylib) _weak_dysym_tlv");

        check.checkInDyldWeakBind();
        check.checkContains("_weak_external_for_gotpcrel");
        check.checkContains("_weak_dysym_for_gotpcrel");
        check.checkContains("_weak_external_fn");
        check.checkContains("_weak_dysym_fn");
        check.checkContains("_weak_dysym");
        check.checkContains("_weak_external");
        check.checkContains("_weak_tlv");
        check.checkContains("_weak_dysym_tlv");

        test_step.dependOn(&check.step);
    }

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testWeakFramework(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-weak-framework", "");

    const exe = cc(b, "a.out", opts);
    exe.addEmptyMain();
    exe.addArgs(&.{ "-weak_framework", "Cocoa" });

    const run = exe.run();
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("cmd LOAD_WEAK_DYLIB");
    check.checkContains("Cocoa");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testWeakLibrary(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-weak-library", "");

    const dylib = cc(b, "liba.dylib", opts);
    dylib.addCSource(
        \\#include<stdio.h>
        \\int a = 42;
        \\const char* asStr() {
        \\  static char str[3];
        \\  sprintf(str, "%d", 42);
        \\  return str;
        \\}
    );
    dylib.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/liba.dylib" });

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\#include<stdio.h>
        \\extern int a;
        \\extern const char* asStr();
        \\int main() {
        \\  printf("%d %s", a, asStr());
        \\  return 0;
        \\}
    );
    exe.addArg("-weak-la");
    exe.addPrefixedDirectorySource("-L", dylib.getDir());
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib.getDir());

    const check = exe.check();
    check.checkInHeaders();
    check.checkExact("cmd LOAD_WEAK_DYLIB");
    check.checkContains("liba.dylib");
    check.checkInSymtab();
    check.checkExact("(undefined) weakref external _a (from liba)");
    check.checkInSymtab();
    check.checkExact("(undefined) weakref external _asStr (from liba)");
    test_step.dependOn(&check.step);

    const run = exe.run();
    run.expectStdOutEqual("42 42");
    test_step.dependOn(run.step());

    return test_step;
}

fn testWeakRef(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-weak-ref", "");

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\#include<stdio.h>
        \\__attribute__((weak)) int foo();
        \\int main() {
        \\  printf("%d", foo ? foo() : -1);
        \\  return 0;
        \\}
    );
    exe.addArgs(&.{ "-Wl,-flat_namespace", "-Wl,-undefined,suppress" });

    const check = exe.check();
    check.checkInSymtab();
    check.checkExact("(undefined) weakref external _foo (from flat lookup)");
    test_step.dependOn(&check.step);

    const run = exe.run();
    run.expectStdOutEqual("-1");
    test_step.dependOn(run.step());

    return test_step;
}

fn testWeakRef2(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-weak-ref2", "");

    const exe = cc(b, "a.out", opts);
    exe.addCSource(
        \\#include <stdio.h>
        \\#include <sys/_types/_fd_def.h>
        \\int main(int argc, char** argv) {
        \\    printf("__darwin_check_fd_set_overflow: %p\n", __darwin_check_fd_set_overflow);
        \\}
    );
    exe.addArgs(&.{ "-mmacos-version-min=10.13", "-arch", "x86_64" });

    const check = exe.check();
    check.checkInSymtab();
    check.checkExact("(undefined) weakref external ___darwin_check_fd_set_overflow (from libSystem.B)");
    test_step.dependOn(&check.step);

    return test_step;
}

const Options = struct {
    zld: LazyPath,
    has_zig: bool,
    has_objc_msgsend_stubs: bool,
    macos_sdk: []const u8,
    ios_sdk: ?[]const u8,
    cc_override: ?[]const u8,
};

fn cc(b: *Build, name: []const u8, opts: Options) SysCmd {
    const cmd = Run.create(b, "cc");
    cmd.addArgs(&.{ opts.cc_override orelse "cc", "-fno-lto" });
    cmd.addArg("-o");
    const out = cmd.addOutputFileArg(name);
    cmd.addPrefixedDirectorySourceArg("-B", opts.zld.dirname());
    return .{ .cmd = cmd, .out = out };
}

fn zig(b: *Build, name: []const u8) SysCmd {
    const cmd = Run.create(b, "zig");
    cmd.addArgs(&.{ "zig", "build-obj" });
    const out = cmd.addPrefixedOutputFileArg("-femit-bin=", name);
    return .{ .cmd = cmd, .out = out };
}

fn ar(b: *Build, name: []const u8) SysCmd {
    const cmd = Run.create(b, "ar");
    cmd.addArgs(&.{ "ar", "rcs" });
    const out = cmd.addOutputFileArg(name);
    return .{ .cmd = cmd, .out = out };
}

fn lipo(b: *Build, name: []const u8) SysCmd {
    const cmd = Run.create(b, "lipo");
    cmd.addArgs(&.{ "lipo", "-create", "-output" });
    const out = cmd.addOutputFileArg(name);
    return .{ .cmd = cmd, .out = out };
}

fn ld(b: *Build, name: []const u8, opts: Options) SysCmd {
    const cmd = Run.create(b, "ld");
    cmd.addFileArg(opts.zld);
    cmd.addArg("-dynamic");
    cmd.addArg("-o");
    const out = cmd.addOutputFileArg(name);
    cmd.addArgs(&.{ "-lSystem", "-lc" });
    return .{ .cmd = cmd, .out = out };
}

const std = @import("std");
const builtin = @import("builtin");
const common = @import("test.zig");
const saveBytesToFile = common.saveBytesToFile;
const skipTestStep = common.skipTestStep;

const Build = std.Build;
const Compile = Step.Compile;
const LazyPath = Build.LazyPath;
const Run = Step.Run;
const Step = Build.Step;
const SysCmd = common.SysCmd;
const WriteFile = Step.WriteFile;
