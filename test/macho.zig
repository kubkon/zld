pub fn addMachOTests(b: *Build, options: common.Options) *Step {
    const macho_step = b.step("test-macho", "Run MachO tests");

    if (builtin.target.os.tag != .macos) return skipTestStep(macho_step);

    var opts = Options{
        .zld = options.zld,
        .has_zig = options.has_zig,
        .macos_sdk = undefined,
        .ios_sdk = null,
        .cc_override = options.cc_override,
    };
    opts.macos_sdk = std.zig.system.darwin.getSdk(b.allocator, builtin.target) orelse @panic("no macOS SDK found");
    opts.ios_sdk = blk: {
        const target_info = std.zig.system.NativeTargetInfo.detect(.{
            .cpu_arch = .aarch64,
            .os_tag = .ios,
        }) catch break :blk null;
        break :blk std.zig.system.darwin.getSdk(b.allocator, target_info.target);
    };

    macho_step.dependOn(testAllLoad(b, opts));
    macho_step.dependOn(testBuildVersionMacOS(b, opts));
    // macho_step.dependOn(testBuildVersionIOS(b, opts)); // TODO arm64 support
    macho_step.dependOn(testDeadStrip(b, opts));
    macho_step.dependOn(testDeadStripDylibs(b, opts));
    macho_step.dependOn(testDylib(b, opts));
    macho_step.dependOn(testDylibReexport(b, opts));
    macho_step.dependOn(testDylibReexportDeep(b, opts));
    macho_step.dependOn(testEmptyObject(b, opts));
    macho_step.dependOn(testEntryPoint(b, opts));
    macho_step.dependOn(testEntryPointArchive(b, opts));
    macho_step.dependOn(testEntryPointDylib(b, opts));
    macho_step.dependOn(testFatArchive(b, opts));
    // macho_step.dependOn(testFatDylib(b, opts)); // TODO arm64 support
    macho_step.dependOn(testFlatNamespace(b, opts));
    macho_step.dependOn(testFlatNamespaceExe(b, opts));
    macho_step.dependOn(testFlatNamespaceWeak(b, opts));
    macho_step.dependOn(testHeaderpad(b, opts));
    macho_step.dependOn(testHeaderWeakFlags(b, opts));
    macho_step.dependOn(testHelloC(b, opts));
    macho_step.dependOn(testHelloZig(b, opts));
    macho_step.dependOn(testLayout(b, opts));
    macho_step.dependOn(testLargeBss(b, opts));
    macho_step.dependOn(testLinkOrder(b, opts));
    macho_step.dependOn(testLoadHidden(b, opts));
    macho_step.dependOn(testMhExecuteHeader(b, opts));
    macho_step.dependOn(testNeededFramework(b, opts));
    macho_step.dependOn(testNeededLibrary(b, opts));
    macho_step.dependOn(testNoDeadStrip(b, opts));
    macho_step.dependOn(testNoExportsDylib(b, opts));
    macho_step.dependOn(testObjC(b, opts));
    macho_step.dependOn(testPagezeroSize(b, opts));
    macho_step.dependOn(testReexportsZig(b, opts));
    macho_step.dependOn(testSearchStrategy(b, opts));
    macho_step.dependOn(testSectionBoundarySymbols(b, opts));
    macho_step.dependOn(testSegmentBoundarySymbols(b, opts));
    macho_step.dependOn(testStackSize(b, opts));
    macho_step.dependOn(testSymbolStabs(b, opts));
    macho_step.dependOn(testTbdv3(b, opts));
    macho_step.dependOn(testTentative(b, opts));
    macho_step.dependOn(testTls(b, opts));
    macho_step.dependOn(testTlsLargeTbss(b, opts));
    macho_step.dependOn(testTwoLevelNamespace(b, opts));
    macho_step.dependOn(testUndefinedFlag(b, opts));
    macho_step.dependOn(testUnwindInfo(b, opts));
    macho_step.dependOn(testUnwindInfoNoSubsectionsArm64(b, opts));
    macho_step.dependOn(testUnwindInfoNoSubsectionsX64(b, opts));
    macho_step.dependOn(testWeakBind(b, opts));
    macho_step.dependOn(testWeakFramework(b, opts));
    macho_step.dependOn(testWeakLibrary(b, opts));
    macho_step.dependOn(testWeakRef(b, opts));

    return macho_step;
}

fn testAllLoad(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-all-load", "");

    const obj1 = cc(b, opts);
    obj1.addCSource("int foo = 1;");
    obj1.addArg("-c");

    const obj2 = cc(b, opts);
    obj2.addCSource("int bar = 42;");
    obj2.addArg("-c");

    const lib = ar(b);
    lib.addFileSource(obj1.out);
    lib.addFileSource(obj2.out);
    const lib_out = lib.saveOutputAs("liba.a");

    const main_o = cc(b, opts);
    main_o.addCSource(
        \\extern int foo;
        \\int main() {
        \\  return foo;
        \\}
    );
    main_o.addArg("-c");

    {
        const exe = cc(b, opts);
        exe.addFileSource(lib_out.file);
        exe.addFileSource(main_o.out);

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
        const exe = cc(b, opts);
        exe.addFileSource(lib_out.file);
        exe.addFileSource(main_o.out);
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
        const obj = cc(b, opts);
        obj.addEmptyMain();
        obj.addArg("-c");

        const exe = ld(b, opts);
        exe.addFileSource(obj.out);
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

    {
        const obj = cc(b, opts);
        obj.addEmptyMain();
        obj.addArgs(&.{ "-c", "-mmacos-version-min=10.13" });

        const exe = ld(b, opts);
        exe.addFileSource(obj.out);
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
        const obj = cc(b, opts);
        obj.addEmptyMain();
        obj.addArgs(&.{ "-c", "-isysroot", ios_sdk, "--target=arm64-ios16.4" });

        const exe = ld(b, opts);
        exe.addFileSource(obj.out);
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
        const obj = cc(b, opts);
        obj.addEmptyMain();
        obj.addArgs(&.{ "-c", "-isysroot", ios_sdk, "--target=arm64-ios11" });

        const exe = ld(b, opts);
        exe.addFileSource(obj.out);
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
    obj.addArg("-c");
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
        exe.addArg("-Wl,-dead_strip");

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
        const exe = cc(b, opts);
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
        const exe = cc(b, opts);
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

    const dylib = cc(b, opts);
    dylib.addArg("-shared");
    dylib.addCSource(
        \\#include<stdio.h>
        \\char world[] = "world";
        \\char* hello() {
        \\  return "Hello";
        \\}
    );

    const check = dylib.check();
    check.checkInHeaders();
    check.checkExact("header");
    check.checkNotPresent("PIE");
    test_step.dependOn(&check.step);

    const exe = cc(b, opts);
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
    exe.addPrefixedDirectorySource("-L", dylib.saveOutputAs("liba.dylib").dir);

    const run = exe.run();
    run.expectStdOutEqual("Hello world");
    test_step.dependOn(run.step());

    return test_step;
}

fn testDylibReexport(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-dylib-reexport", "");

    const a_o = cc(b, opts);
    a_o.addCSource(
        \\int foo = 42;
        \\int getFoo() {
        \\  return foo;
        \\}
    );
    a_o.addArg("-c");

    const b_o = cc(b, opts);
    b_o.addCSource(
        \\int getFoo();
        \\int getBar() {
        \\  return getFoo();
        \\}
    );
    b_o.addArg("-c");

    const main_o = cc(b, opts);
    main_o.addCSource(
        \\int getFoo();
        \\int getBar();
        \\int main() {
        \\  return getBar() - getFoo();
        \\}
    );
    main_o.addArg("-c");

    const liba = cc(b, opts);
    liba.addFileSource(a_o.out);
    liba.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/liba.dylib" });
    const liba_out = liba.saveOutputAs("liba.dylib");

    const libb = cc(b, opts);
    libb.addFileSource(b_o.out);
    libb.addPrefixedDirectorySource("-L", liba_out.dir);
    libb.addPrefixedDirectorySource("-Wl,-rpath,", liba_out.dir);
    libb.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libb.dylib", "-Wl,-reexport-la" });
    const libb_out = libb.saveOutputAs("libb.dylib");

    {
        const check = libb.check();
        check.checkInHeaders();
        check.checkExact("cmd REEXPORT_DYLIB");
        check.checkExact("name @rpath/liba.dylib");
        check.checkInSymtab();
        check.checkExact("(undefined) external _getFoo (from liba)");
        test_step.dependOn(&check.step);
    }

    const libc = cc(b, opts);
    libc.addFileSource(a_o.out);
    libc.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libc.dylib" });
    const libc_out = libc.saveOutputAs("libc.dylib");

    {
        const exe = cc(b, opts);
        exe.addFileSource(main_o.out);
        exe.addPrefixedDirectorySource("-L", libb_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libb_out.dir);
        exe.addPrefixedDirectorySource("-L", libc_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libc_out.dir);
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
        const exe = cc(b, opts);
        exe.addFileSource(main_o.out);
        exe.addPrefixedDirectorySource("-L", libb_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libb_out.dir);
        exe.addPrefixedDirectorySource("-L", libc_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libc_out.dir);
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

    const liba = cc(b, opts);
    liba.addCSource(
        \\int foo = 42;
        \\int getFoo() {
        \\  return foo;
        \\}
    );
    liba.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/liba.dylib" });
    const liba_out = liba.saveOutputAs("liba.dylib");

    const libb = cc(b, opts);
    libb.addCSource(
        \\int bar = 21;
        \\int getFoo();
        \\int getBar() {
        \\  return getFoo() - bar;
        \\}
    );
    libb.addPrefixedDirectorySource("-L", liba_out.dir);
    libb.addPrefixedDirectorySource("-Wl,-rpath,", liba_out.dir);
    libb.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libb.dylib", "-Wl,-reexport-la" });
    const libb_out = libb.saveOutputAs("libb.dylib");

    const libc = cc(b, opts);
    libc.addCSource(
        \\int foobar = 21;
        \\int getFoo();
        \\int getBar();
        \\int getFoobar() {
        \\  return getFoo() - getBar() - foobar;
        \\}
    );
    libc.addPrefixedDirectorySource("-L", libb_out.dir);
    libc.addPrefixedDirectorySource("-Wl,-rpath,", libb_out.dir);
    libc.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libc.dylib", "-Wl,-reexport-lb" });
    const libc_out = libc.saveOutputAs("libc.dylib");

    const exe = cc(b, opts);
    exe.addCSource(
        \\int getFoobar();
        \\int main() {
        \\  return getFoobar();
        \\}
    );
    exe.addPrefixedDirectorySource("-L", libc_out.dir);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", libc_out.dir);
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

fn testEmptyObject(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-empty-object", "");

    const exe = cc(b, opts);
    exe.addHelloWorldMain();
    exe.addCSource("");

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    return test_step;
}

fn testEntryPoint(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-entry-point", "");

    const exe = cc(b, opts);
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

    const obj = cc(b, opts);
    obj.addArg("-c");
    obj.addEmptyMain();

    const lib = ar(b);
    lib.addFileSource(obj.out);

    {
        const exe = cc(b, opts);
        exe.addArg("-lmain");
        exe.addPrefixedDirectorySource("-L", lib.saveOutputAs("libmain.a").dir);

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, opts);
        exe.addArgs(&.{ "-lmain", "-Wl,-dead_strip" });
        exe.addPrefixedDirectorySource("-L", lib.saveOutputAs("libmain.a").dir);

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testEntryPointDylib(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-entry-point-dylib", "");

    const dylib = cc(b, opts);
    dylib.addArgs(&.{ "-shared", "-Wl,-undefined,dynamic_lookup" });
    dylib.addCSource(
        \\extern int my_main();
        \\int bootstrap() {
        \\  return my_main();
        \\}
    );

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include<stdio.h>
        \\int my_main() {
        \\  fprintf(stdout, "Hello!\n");
        \\  return 0;
        \\}
    );
    exe.addArgs(&.{ "-Wl,-e,_bootstrap", "-Wl,-u,_my_main", "-lbootstrap" });
    exe.addPrefixedDirectorySource("-L", dylib.saveOutputAs("libbootstrap.dylib").dir);

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
        const obj = cc(b, opts);
        obj.addCSource(a_c);
        obj.addArgs(&.{ "-c", "-arch", "arm64" });
        const obj_out = obj.saveOutputAs("a.o");

        const lib = ar(b);
        lib.addFileSource(obj_out.file);
        break :blk lib.saveOutputAs("liba.a").file;
    };

    const lib_x64 = blk: {
        const obj = cc(b, opts);
        obj.addCSource(a_c);
        obj.addArgs(&.{ "-c", "-arch", "x86_64" });
        const obj_out = obj.saveOutputAs("a.o");

        const lib = ar(b);
        lib.addFileSource(obj_out.file);
        break :blk lib.saveOutputAs("liba.a").file;
    };

    const fat_lib = lipo(b);
    fat_lib.addFileSource(lib_arm64);
    fat_lib.addFileSource(lib_x64);
    const fat_lib_out = fat_lib.saveOutputAs("liba.a");

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include<stdio.h>
        \\extern int foo;
        \\int main() {
        \\  printf("%d\n", foo);
        \\  return 0;
        \\}
    );
    exe.addFileSource(fat_lib_out.file);

    const run = exe.run();
    run.expectStdOutEqual("42\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testFatDylib(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-fat-dylib", "");

    const a_c = "int foo = 42;";

    const dylib_arm64 = cc(b, opts);
    dylib_arm64.addCSource(a_c);
    dylib_arm64.addArgs(&.{ "-shared", "-arch", "arm64" });
    const dylib_arm64_out = dylib_arm64.saveOutputAs("liba.dylib");

    const dylib_x64 = cc(b, opts);
    dylib_x64.addCSource(a_c);
    dylib_x64.addArgs(&.{ "-shared", "-arch", "x86_64" });
    const dylib_x64_out = dylib_x64.saveOutputAs("liba.dylib");

    const fat_lib = lipo(b);
    fat_lib.addFileSource(dylib_arm64_out.file);
    fat_lib.addFileSource(dylib_x64_out.file);
    const fat_lib_out = fat_lib.saveOutputAs("liba.dylib");

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include<stdio.h>
        \\extern int foo;
        \\int main() {
        \\  printf("%d\n", foo);
        \\  return 0;
        \\}
    );
    exe.addFileSource(fat_lib_out.file);

    const run = exe.run();
    run.expectStdOutEqual("42\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testFlatNamespace(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-flat-namespace", "");

    const liba = cc(b, opts);
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
    const liba_out = liba.saveOutputAs("liba.dylib");

    {
        const check = liba.check();
        check.checkInDyldLazyBind();
        check.checkContains("(flat lookup) _getFoo");
        check.checkInIndirectSymtab();
        check.checkContains("_getFoo");
        test_step.dependOn(&check.step);
    }

    const libb = cc(b, opts);
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
    const libb_out = libb.saveOutputAs("libb.dylib");

    {
        const check = liba.check();
        check.checkInDyldLazyBind();
        check.checkContains("(flat lookup) _getFoo");
        check.checkInIndirectSymtab();
        check.checkContains("_getFoo");
        test_step.dependOn(&check.step);
    }

    const main_o = cc(b, opts);
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
        const exe = cc(b, opts);
        exe.addFileSource(main_o.out);
        exe.addPrefixedDirectorySource("-L", liba_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", liba_out.dir);
        exe.addPrefixedDirectorySource("-L", libb_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libb_out.dir);
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
        const exe = cc(b, opts);
        exe.addFileSource(main_o.out);
        exe.addPrefixedDirectorySource("-L", liba_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", liba_out.dir);
        exe.addPrefixedDirectorySource("-L", libb_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libb_out.dir);
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

    const exe = cc(b, opts);
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

    const liba = cc(b, opts);
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
    const liba_out = liba.saveOutputAs("liba.dylib");

    {
        const check = liba.check();
        check.checkInDyldLazyBind();
        check.checkContains("(flat lookup) _getFoo");
        test_step.dependOn(&check.step);
    }

    const libb = cc(b, opts);
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
    const libb_out = libb.saveOutputAs("libb.dylib");

    {
        const check = libb.check();
        check.checkInDyldWeakBind();
        check.checkContains("(self) _getFoo");
        check.checkInDyldLazyBind();
        check.checkNotPresent("_getFoo");
        test_step.dependOn(&check.step);
    }

    const main_o = cc(b, opts);
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
        const exe = cc(b, opts);
        exe.addFileSource(main_o.out);
        exe.addPrefixedDirectorySource("-L", liba_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", liba_out.dir);
        exe.addPrefixedDirectorySource("-L", libb_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libb_out.dir);
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
        const exe = cc(b, opts);
        exe.addFileSource(main_o.out);
        exe.addPrefixedDirectorySource("-L", liba_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", liba_out.dir);
        exe.addPrefixedDirectorySource("-L", libb_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libb_out.dir);
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
            \\main=2
            \\liba=2
            \\libb=2
            \\
        );
        test_step.dependOn(run.step());
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
        const exe = cc(b, opts);
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
        const exe = cc(b, opts);
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
        const exe = cc(b, opts);
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
        const exe = cc(b, opts);
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

    const obj1 = cc(b, opts);
    obj1.addAsmSource(
        \\.globl _x
        \\.weak_definition _x
        \\_x:
        \\ ret
    );
    obj1.addArg("-c");

    const lib = cc(b, opts);
    lib.addFileSource(obj1.out);
    lib.addArg("-shared");

    {
        const exe = cc(b, opts);
        exe.addFileSource(obj1.out);
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
        const exe = cc(b, opts);
        exe.addFileSource(lib.out);
        exe.addAsmSource(
            \\.globl _main
            \\_main:
            \\  callq _x
            \\  ret
        );

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
        const exe = cc(b, opts);
        exe.addFileSource(lib.out);
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

    const exe = cc(b, opts);
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

    const obj = zig(b);
    obj.addZigSource(
        \\const std = @import("std");
        \\pub fn main() void {
        \\    std.io.getStdOut().writer().print("Hello world!\n", .{}) catch unreachable;
        \\}
    );
    obj.addArg("-fno-stack-check"); // TODO find a way to include Zig's crt

    const exe = cc(b, opts);
    exe.addFileSource(obj.out);

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    return test_step;
}

fn testLayout(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-layout", "");

    const exe = cc(b, opts);
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

    const exe = cc(b, opts);
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
    const test_step = b.step("test-macho-link-order", "");

    const a_o = cc(b, opts);
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

    const c_o = cc(b, opts);
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

    const main_o = cc(b, opts);
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

    const liba = ar(b);
    liba.addFileSource(a_o.out);

    const libc = cc(b, opts);
    libc.addFileSource(c_o.out);
    libc.addArg("-shared");

    {
        const exe = cc(b, opts);
        exe.addFileSource(libc.out);
        exe.addFileSource(liba.out);
        exe.addFileSource(main_o.out);

        const run = exe.run();
        run.expectStdOutEqual("-1 42 42");
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, opts);
        exe.addFileSource(liba.out);
        exe.addFileSource(libc.out);
        exe.addFileSource(main_o.out);

        const run = exe.run();
        run.expectStdOutEqual("42 0 -2");
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testLoadHidden(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-load-hidden", "");

    const obj = cc(b, opts);
    obj.addCSource(
        \\int foo = 42;
        \\int getFoo() { return foo; }
    );
    obj.addArg("-c");

    const lib = ar(b);
    lib.addFileSource(obj.out);
    const lib_out = lib.saveOutputAs("liba.a");

    const main_o = cc(b, opts);
    main_o.addCSource(
        \\int actuallyGetFoo();
        \\int main() {
        \\  return actuallyGetFoo();
        \\}
    );
    main_o.addArg("-c");

    const dylib_o = cc(b, opts);
    dylib_o.addCSource(
        \\extern int foo;
        \\int getFoo();
        \\int actuallyGetFoo() { return foo; };
    );
    dylib_o.addArg("-c");

    {
        const dylib = cc(b, opts);
        dylib.addFileSource(dylib_o.out);
        dylib.addPrefixedDirectorySource("-L", lib_out.dir);
        dylib.addArgs(&.{ "-shared", "-Wl,-hidden-la", "-Wl,-install_name,@rpath/libb.dylib" });
        const dylib_out = dylib.saveOutputAs("libb.dylib");

        const check = dylib.check();
        check.checkInSymtab();
        check.checkContains("external _actuallyGetFoo");
        check.checkNotPresent("external _foo");
        check.checkNotPresent("external _getFoo");
        test_step.dependOn(&check.step);

        const exe = cc(b, opts);
        exe.addFileSource(main_o.out);
        exe.addPrefixedDirectorySource("-L", dylib_out.dir);
        exe.addArg("-lb");
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib_out.dir);

        const run = exe.run();
        run.expectExitCode(42);
        test_step.dependOn(run.step());
    }

    {
        const dylib = cc(b, opts);
        dylib.addFileSource(dylib_o.out);
        dylib.addArg("-load_hidden");
        dylib.addFileSource(lib.out);
        dylib.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libb.dylib" });
        const dylib_out = dylib.saveOutputAs("libb.dylib");

        const check = dylib.check();
        check.checkInSymtab();
        check.checkContains("external _actuallyGetFoo");
        check.checkNotPresent("external _foo");
        check.checkNotPresent("external _getFoo");
        test_step.dependOn(&check.step);

        const exe = cc(b, opts);
        exe.addFileSource(main_o.out);
        exe.addPrefixedDirectorySource("-L", dylib_out.dir);
        exe.addArg("-lb");
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib_out.dir);

        const run = exe.run();
        run.expectExitCode(42);
        test_step.dependOn(run.step());
    }

    {
        const dylib = cc(b, opts);
        dylib.addFileSource(dylib_o.out);
        dylib.addFileSource(lib.out);
        dylib.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/libb.dylib" });
        const dylib_out = dylib.saveOutputAs("libb.dylib");

        const check = dylib.check();
        check.checkInSymtab();
        check.checkContains("external _actuallyGetFoo");
        check.checkContains("external _foo");
        check.checkContains("external _getFoo");
        test_step.dependOn(&check.step);

        const exe = cc(b, opts);
        exe.addFileSource(main_o.out);
        exe.addPrefixedDirectorySource("-L", dylib_out.dir);
        exe.addArg("-lb");
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib_out.dir);

        const run = exe.run();
        run.expectExitCode(42);
        test_step.dependOn(run.step());
    }

    return test_step;
}

fn testMhExecuteHeader(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-mh-execute-header", "");

    const exe = cc(b, opts);
    exe.addEmptyMain();

    const check = exe.check();
    check.checkInSymtab();
    check.checkContains("[referenced dynamically] external __mh_execute_header");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testNeededFramework(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-needed-framework", "");

    const exe = cc(b, opts);
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

    const dylib = cc(b, opts);
    dylib.addCSource("int a = 42;");
    dylib.addArgs(&.{ "-shared", "-Wl,-install_name,@rpath/liba.dylib" });
    const dylib_out = dylib.saveOutputAs("liba.dylib");

    const exe = cc(b, opts);
    exe.addEmptyMain();
    exe.addArgs(&.{ "-Wl,-needed-la", "-Wl,-dead_strip_dylibs" });
    exe.addPrefixedDirectorySource("-L", dylib_out.dir);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib_out.dir);

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

    const exe = cc(b, opts);
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

    const dylib = cc(b, opts);
    dylib.addCSource("static void abc() {}");
    dylib.addArg("-shared");

    const check = dylib.check();
    check.checkInSymtab();
    check.checkNotPresent("external _abc");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testObjC(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-objc", "");

    const a_o = cc(b, opts);
    a_o.addObjCSource(
        \\#import <Foundation/Foundation.h>
        \\@interface Foo : NSObject
        \\@end
        \\@implementation Foo
        \\@end
    );
    a_o.addArg("-c");

    const liba = ar(b);
    liba.addFileSource(a_o.out);
    const liba_out = liba.saveOutputAs("liba.a");

    {
        const exe = cc(b, opts);
        exe.addEmptyMain();
        exe.addPrefixedDirectorySource("-L", liba_out.dir);
        exe.addArg("-la");

        const check = exe.check();
        check.checkInSymtab();
        check.checkNotPresent("_OBJC_");
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, opts);
        exe.addEmptyMain();
        exe.addPrefixedDirectorySource("-L", liba_out.dir);
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

fn testPagezeroSize(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-pagezero-size", "");

    {
        const exe = cc(b, opts);
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
        const exe = cc(b, opts);
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

    const obj = zig(b);
    obj.addZigSource(
        \\const x: i32 = 42;
        \\export fn foo() i32 {
        \\    return x;
        \\}
        \\comptime {
        \\    @export(foo, .{ .name = "bar", .linkage = .Strong });
        \\}
    );

    const lib = ar(b);
    lib.addFileSource(obj.out);
    const lib_out = lib.saveOutputAs("liba.a");

    const exe = cc(b, opts);
    exe.addCSource(
        \\extern int foo();
        \\extern int bar();
        \\int main() {
        \\  return bar() - foo();
        \\}
    );
    exe.addFileSource(lib_out.file);

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testSearchStrategy(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-search-strategy", "");

    const obj = cc(b, opts);
    obj.addArg("-c");
    obj.addCSource(
        \\#include<stdio.h>
        \\char world[] = "world";
        \\char* hello() {
        \\  return "Hello";
        \\}
    );
    const obj_out = obj.saveOutputAs("a.o");

    const lib = ar(b);
    lib.addFileSource(obj_out.file);
    const lib_out = lib.saveOutputAs("liba.a");

    const dylib = ld(b, opts);
    dylib.addFileSource(obj_out.file);
    dylib.addArgs(&.{ "-syslibroot", opts.macos_sdk, "-dylib", "-install_name", "@rpath/liba.dylib" });
    const dylib_out = dylib.saveOutputAs("liba.dylib");

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
        const exe = cc(b, opts);
        exe.addCSource(main_c);
        exe.addArgs(&.{ "-Wl,-search_dylibs_first", "-la" });
        exe.addPrefixedDirectorySource("-L", lib_out.dir);
        exe.addPrefixedDirectorySource("-L", dylib_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib_out.dir);

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
        const exe = cc(b, opts);
        exe.addCSource(main_c);
        exe.addArgs(&.{ "-Wl,-search_paths_first", "-la" });
        exe.addPrefixedDirectorySource("-L", lib_out.dir);
        exe.addPrefixedDirectorySource("-L", dylib_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib_out.dir);

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

    const obj1 = cc(b, opts);
    obj1.addCppSource(
        \\constexpr const char* MESSAGE __attribute__((used, section("__DATA_CONST,__message_ptr"))) = "codebase";
    );
    obj1.addArgs(&.{ "-std=c++17", "-c" });

    const main_o = cc(b, opts);
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
        const obj2 = cc(b, opts);
        obj2.addCppSource(
            \\extern const char* message_pointer __asm("section$start$__DATA_CONST$__message_ptr");
            \\extern "C" const char* interop() {
            \\  return message_pointer;
            \\}
        );
        obj2.addArgs(&.{ "-std=c++17", "-c" });

        const exe = cc(b, opts);
        exe.addFileSource(obj1.out);
        exe.addFileSource(obj2.out);
        exe.addFileSource(main_o.out);

        const run = exe.run();
        run.expectStdOutEqual("All your codebase are belong to us.\n");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkNotPresent("external section$start$__DATA_CONST$__message_ptr");
        test_step.dependOn(&check.step);
    }

    {
        const obj2 = cc(b, opts);
        obj2.addCppSource(
            \\extern const char* message_pointer __asm("section$start$__DATA_CONST$__not_present");
            \\extern "C" const char* interop() {
            \\  return message_pointer;
            \\}
        );
        obj2.addArgs(&.{ "-std=c++17", "-c" });

        const exe = cc(b, opts);
        exe.addFileSource(obj1.out);
        exe.addFileSource(obj2.out);
        exe.addFileSource(main_o.out);

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

    const obj1 = cc(b, opts);
    obj1.addCppSource(
        \\constexpr const char* MESSAGE __attribute__((used, section("__DATA_CONST_1,__message_ptr"))) = "codebase";
    );
    obj1.addArgs(&.{ "-std=c++17", "-c" });

    const main_o = cc(b, opts);
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
        const obj2 = cc(b, opts);
        obj2.addCppSource(
            \\extern const char* message_pointer __asm("segment$start$__DATA_CONST_1");
            \\extern "C" const char* interop() {
            \\  return message_pointer;
            \\}
        );
        obj2.addArgs(&.{ "-std=c++17", "-c" });

        const exe = cc(b, opts);
        exe.addFileSource(obj1.out);
        exe.addFileSource(obj2.out);
        exe.addFileSource(main_o.out);

        const run = exe.run();
        run.expectStdOutEqual("All your codebase are belong to us.\n");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkNotPresent("external segment$start$__DATA_CONST_1");
        test_step.dependOn(&check.step);
    }

    {
        const obj2 = cc(b, opts);
        obj2.addCppSource(
            \\extern const char* message_pointer __asm("segment$start$__DATA_1");
            \\extern "C" const char* interop() {
            \\  return message_pointer;
            \\}
        );
        obj2.addArgs(&.{ "-std=c++17", "-c" });

        const exe = cc(b, opts);
        exe.addFileSource(obj1.out);
        exe.addFileSource(obj2.out);
        exe.addFileSource(main_o.out);

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

    const exe = cc(b, opts);
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

    const a_o = cc(b, opts);
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

    const b_o = cc(b, opts);
    b_o.addAsmSource(
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
    );
    b_o.addArgs(&.{ "-c", "-g" });

    const exe = cc(b, opts);
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
    exe.addFileSource(a_o.out);
    exe.addFileSource(b_o.out);
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

    return test_step;
}

fn testTbdv3(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-tbdv3", "");

    const dylib = cc(b, opts);
    dylib.addArg("-shared");
    dylib.addCSource("int getFoo() { return 42; }");
    const dylib_out = dylib.saveOutputAs("liba.dylib");

    const tbd = scr: {
        const wf = WriteFile.create(b);
        break :scr wf.add("liba.tbd",
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
    };

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include <stdio.h>
        \\int getFoo();
        \\int main() {
        \\  return getFoo() - 42;
        \\}
    );
    exe.addFileSource(tbd);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib_out.dir);

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testTentative(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-tentative", "");

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

fn testTls(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-tls", "");

    const dylib = cc(b, opts);
    dylib.addArg("-shared");
    dylib.addCSource(
        \\_Thread_local int a;
        \\int getA() {
        \\  return a;
        \\}
    );

    const exe = cc(b, opts);
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
    exe.addPrefixedDirectorySource("-L", dylib.saveOutputAs("liba.dylib").dir);

    const run = exe.run();
    run.expectStdOutEqual("2 2 2");
    test_step.dependOn(run.step());

    return test_step;
}

fn testTwoLevelNamespace(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-two-level-namespace", "");

    const liba = cc(b, opts);
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
    const liba_out = liba.saveOutputAs("liba.dylib");

    {
        const check = liba.check();
        check.checkInDyldLazyBind();
        check.checkNotPresent("(flat lookup) _getFoo");
        check.checkInIndirectSymtab();
        check.checkNotPresent("_getFoo");
        test_step.dependOn(&check.step);
    }

    const libb = cc(b, opts);
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
    const libb_out = libb.saveOutputAs("libb.dylib");

    {
        const check = liba.check();
        check.checkInDyldLazyBind();
        check.checkNotPresent("(flat lookup) _getFoo");
        check.checkInIndirectSymtab();
        check.checkNotPresent("_getFoo");
        test_step.dependOn(&check.step);
    }

    const main_o = cc(b, opts);
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
        const exe = cc(b, opts);
        exe.addFileSource(main_o.out);
        exe.addPrefixedDirectorySource("-L", liba_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", liba_out.dir);
        exe.addPrefixedDirectorySource("-L", libb_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libb_out.dir);
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
        const exe = cc(b, opts);
        exe.addFileSource(main_o.out);
        exe.addPrefixedDirectorySource("-L", liba_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", liba_out.dir);
        exe.addPrefixedDirectorySource("-L", libb_out.dir);
        exe.addPrefixedDirectorySource("-Wl,-rpath,", libb_out.dir);
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

    const exe = cc(b, opts);
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

fn testUndefinedFlag(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-undefined-flag", "");

    const obj = cc(b, opts);
    obj.addCSource("int foo = 42;");
    obj.addArg("-c");

    const lib = ar(b);
    lib.addFileSource(obj.out);

    {
        const exe = cc(b, opts);
        exe.addEmptyMain();
        exe.addArgs(&.{ "-Wl,-u,_foo", "-la" });
        exe.addPrefixedDirectorySource("-L", lib.saveOutputAs("liba.a").dir);

        const run = exe.run();
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkContains("_foo");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, opts);
        exe.addEmptyMain();
        exe.addArgs(&.{ "-Wl,-u,_foo", "-la", "-Wl,-dead_strip" });
        exe.addPrefixedDirectorySource("-L", lib.saveOutputAs("liba.a").dir);

        const run = exe.run();
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkContains("_foo");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, opts);
        exe.addEmptyMain();
        exe.addFileSource(obj.out);

        const run = exe.run();
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkInSymtab();
        check.checkContains("_foo");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, opts);
        exe.addEmptyMain();
        exe.addFileSource(obj.out);
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

    const all_h = FileSourceWithDir.fromBytes(b,
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
    , "all.h");

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
    const obj = cc(b, opts);
    obj.addCppSource(main_c);
    obj.addPrefixedDirectorySource("-I", all_h.dir);
    obj.addArgs(flags);

    const obj1 = cc(b, opts);
    obj1.addCppSource(simple_string_c);
    obj1.addPrefixedDirectorySource("-I", all_h.dir);
    obj1.addArgs(flags);

    const obj2 = cc(b, opts);
    obj2.addCppSource(simple_string_owner_c);
    obj2.addPrefixedDirectorySource("-I", all_h.dir);
    obj2.addArgs(flags);

    const exe = ld(b, opts);
    exe.addArgs(&.{ "-syslibroot", opts.macos_sdk, "-lc++" });
    exe.addFileSource(obj.saveOutputAs("main.o").file);
    exe.addFileSource(obj1.saveOutputAs("simple_string.o").file);
    exe.addFileSource(obj2.saveOutputAs("simple_string_owner.o").file);

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

    const a_o = cc(b, opts);
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
    const a_o_out = a_o.saveOutputAs("a.o");

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include <stdio.h>
        \\int foo();
        \\int main() {
        \\  printf("%d\n", foo());
        \\  return 0;
        \\}
    );
    exe.addFileSource(a_o_out.file);

    const run = exe.run();
    run.expectStdOutEqual("4\n");
    test_step.dependOn(run.step());

    return test_step;
}

fn testUnwindInfoNoSubsectionsX64(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-unwind-info-no-subsections-x64", "");

    if (builtin.target.cpu.arch != .x86_64) return skipTestStep(test_step);

    const a_o = cc(b, opts);
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
    const a_o_out = a_o.saveOutputAs("a.o");

    const exe = cc(b, opts);
    exe.addCSource(
        \\#include <stdio.h>
        \\int foo();
        \\int main() {
        \\  printf("%d\n", foo());
        \\  return 0;
        \\}
    );
    exe.addFileSource(a_o_out.file);

    const run = exe.run();
    run.expectStdOutEqual("4\n");
    test_step.dependOn(run.step());

    return test_step;
}

// Adapted from https://github.com/llvm/llvm-project/blob/main/lld/test/MachO/weak-binding.s
fn testWeakBind(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-weak-bind", "");

    const lib = cc(b, opts);
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
    const lib_out = lib.saveOutputAs("libfoo.dylib");

    {
        const check = lib.check();
        check.checkInExports();
        check.checkExtract("[WEAK] {vmaddr1} _weak_dysym");
        check.checkExtract("[WEAK] {vmaddr2} _weak_dysym_for_gotpcrel");
        check.checkExtract("[WEAK] {vmaddr3} _weak_dysym_fn");
        check.checkExtract("[THREAD_LOCAL, WEAK] {vmaddr4} _weak_dysym_tlv");
        test_step.dependOn(&check.step);
    }

    const exe = cc(b, opts);
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
    exe.addFileSource(lib_out.file);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", lib_out.dir);

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

    const exe = cc(b, opts);
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

    const dylib = cc(b, opts);
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
    const dylib_out = dylib.saveOutputAs("liba.dylib");

    const exe = cc(b, opts);
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
    exe.addPrefixedDirectorySource("-L", dylib_out.dir);
    exe.addPrefixedDirectorySource("-Wl,-rpath,", dylib_out.dir);

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

    const exe = cc(b, opts);
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

const Options = struct {
    zld: FileSourceWithDir,
    has_zig: bool,
    macos_sdk: []const u8,
    ios_sdk: ?[]const u8,
    cc_override: ?[]const u8,
};

fn cc(b: *Build, opts: Options) SysCmd {
    const cmd = Run.create(b, "cc");
    cmd.addArgs(&.{ opts.cc_override orelse "cc", "-fno-lto" });
    cmd.addArg("-o");
    const out = cmd.addOutputFileArg("a.out");
    cmd.addPrefixedDirectorySourceArg("-B", opts.zld.dir);
    return .{ .cmd = cmd, .out = out };
}

fn zig(b: *Build) SysCmd {
    const cmd = Run.create(b, "zig");
    cmd.addArgs(&.{ "zig", "build-obj" });
    const out = cmd.addPrefixedOutputFileArg("-femit-bin=", "a.o");
    return .{ .cmd = cmd, .out = out };
}

fn ar(b: *Build) SysCmd {
    const cmd = Run.create(b, "ar");
    cmd.addArgs(&.{ "ar", "rcs" });
    const out = cmd.addOutputFileArg("a.a");
    return .{ .cmd = cmd, .out = out };
}

fn lipo(b: *Build) SysCmd {
    const cmd = Run.create(b, "lipo");
    cmd.addArgs(&.{ "lipo", "-create", "-output" });
    const out = cmd.addOutputFileArg("a.out");
    return .{ .cmd = cmd, .out = out };
}

fn ld(b: *Build, opts: Options) SysCmd {
    const cmd = Run.create(b, "ld");
    cmd.addFileSourceArg(opts.zld.file);
    cmd.addArg("-dynamic");
    cmd.addArg("-o");
    const out = cmd.addOutputFileArg("a.out");
    cmd.addArgs(&.{ "-lSystem", "-lc" });
    return .{ .cmd = cmd, .out = out };
}

const std = @import("std");
const builtin = @import("builtin");
const common = @import("test.zig");
const skipTestStep = common.skipTestStep;

const Build = std.Build;
const Compile = Step.Compile;
const FileSourceWithDir = common.FileSourceWithDir;
const Run = Step.Run;
const Step = Build.Step;
const SysCmd = common.SysCmd;
const WriteFile = Step.WriteFile;
