pub fn addMachOTests(b: *Build, opts: Options) *Step {
    const macho_step = b.step("test-macho", "Run MachO tests");

    if (builtin.target.ofmt == .macho) {
        macho_step.dependOn(testDeadStrip(b, opts));
        macho_step.dependOn(testDeadStripDylibs(b, opts));
        macho_step.dependOn(testDylib(b, opts));
        macho_step.dependOn(testEmptyObject(b, opts));
        macho_step.dependOn(testEntryPoint(b, opts));
        macho_step.dependOn(testEntryPointArchive(b, opts));
        macho_step.dependOn(testEntryPointDylib(b, opts));
        macho_step.dependOn(testHeaderpad(b, opts));
        macho_step.dependOn(testHello(b, opts));
        macho_step.dependOn(testLayout(b, opts));
        macho_step.dependOn(testNeededFramework(b, opts));
        macho_step.dependOn(testNeededLibrary(b, opts));
        macho_step.dependOn(testPagezeroSize(b, opts));
        macho_step.dependOn(testSearchStrategy(b, opts));
        macho_step.dependOn(testStackSize(b, opts));
        macho_step.dependOn(testTls(b, opts));
        macho_step.dependOn(testUnwindInfo(b, opts));
        macho_step.dependOn(testWeakFramework(b, opts));
        macho_step.dependOn(testWeakLibrary(b, opts));
    }

    return macho_step;
}

fn testDeadStrip(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-dead-strip", "");

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\#include <stdio.h>
        \\void printMe() {
        \\  printf("Hello!\n");
        \\}
        \\int main() {
        \\  printMe();
        \\  return 0;
        \\}
        \\void iAmUnused() {
        \\  printf("YOU SHALL NOT PASS!\n");
        \\}
    , "main.c");
    exe.addArg("-dead_strip");

    const run = exe.run();
    run.expectStdOutEqual("Hello!\n");
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkInSymtab();
    check.checkNotPresent("{*} (__TEXT,__text) external _iAmUnused");
    test_step.dependOn(&check.step);

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
        const exe = cc(b, null, opts);
        exe.addSourceBytes(main_c, "main.c");
        exe.addArgs(&.{ "-framework", "Cocoa" });

        const check = exe.check();
        check.checkStart("cmd LOAD_DYLIB");
        check.checkNext("name {*}Cocoa");
        check.checkStart("cmd LOAD_DYLIB");
        check.checkNext("name {*}libobjc{*}.dylib");
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, null, opts);
        exe.addSourceBytes(main_c, "main.c");
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
    dylib.addArg("-shared");
    dylib.addSourceBytes(
        \\#include<stdio.h>
        \\char world[] = "world";
        \\char* hello() {
        \\  return "Hello";
        \\}
    , "a.c");

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\#include<stdio.h>
        \\char* hello();
        \\extern char world[];
        \\int main() {
        \\  printf("%s %s", hello(), world);
        \\  return 0;
        \\}
    , "main.c");
    exe.addArg("-la");
    exe.addPrefixedDirectorySource("-L", dylib.saveOutputAs("liba.dylib").dir);

    const run = exe.run();
    run.expectStdOutEqual("Hello world");
    test_step.dependOn(run.step());

    return test_step;
}

fn testEmptyObject(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-empty-object", "");

    const exe = cc(b, null, opts);
    exe.addHelloWorldMain();
    exe.addSourceBytes("", "empty.c");

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    return test_step;
}

fn testEntryPoint(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-entry-point", "");

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\#include<stdio.h>
        \\int non_main() {
        \\  printf("%d", 42);
        \\  return 0;
        \\}
    , "main.c");
    exe.addArg("-Wl,-e,_non_main");

    const run = exe.run();
    run.expectStdOutEqual("42");
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkStart("segname __TEXT");
    check.checkNext("vmaddr {vmaddr}");
    check.checkStart("cmd MAIN");
    check.checkNext("entryoff {entryoff}");
    check.checkInSymtab();
    check.checkNext("{n_value} (__TEXT,__text) external _non_main");
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
    lib.addFileSource(obj.out);

    const exe = cc(b, null, opts);
    exe.addArg("-lmain");
    exe.addPrefixedDirectorySource("-L", lib.saveOutputAs("libmain.a").dir);

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testEntryPointDylib(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-entry-point-dylib", "");

    const dylib = cc(b, "libbootstrap.dylib", opts);
    dylib.addArgs(&.{ "-shared", "-Wl,-undefined,dynamic_lookup" });
    dylib.addSourceBytes(
        \\extern int my_main();
        \\int bootstrap() {
        \\  return my_main();
        \\}
    , "bootstrap.c");

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\#include<stdio.h>
        \\int my_main() {
        \\  fprintf(stdout, "Hello!\n");
        \\  return 0;
        \\}
    , "main.c");
    exe.addArgs(&.{ "-Wl,-e,_bootstrap", "-Wl,-u,_my_main", "-lbootstrap" });
    exe.addPrefixedDirectorySource("-L", dylib.saveOutputAs("libbootstrap.dylib").dir);

    const check = exe.check();
    check.checkStart("segname __TEXT");
    check.checkNext("vmaddr {text_vmaddr}");
    check.checkStart("sectname __stubs");
    check.checkNext("addr {stubs_vmaddr}");
    check.checkStart("cmd MAIN");
    check.checkNext("entryoff {entryoff}");
    check.checkComputeCompare("text_vmaddr entryoff +", .{
        .op = .eq,
        .value = .{ .variable = "stubs_vmaddr" }, // The entrypoint should be a synthetic stub
    });
    test_step.dependOn(&check.step);

    const run = exe.run();
    run.expectStdOutEqual("Hello!\n");
    test_step.dependOn(run.step());

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
        const exe = cc(b, null, opts);
        exe.addArgs(flags);
        exe.addArg("-Wl,-headerpad_max_install_names");
        exe.addEmptyMain();

        const check = exe.check();
        check.checkStart("sectname __text");
        check.checkNext("offset {offset}");
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
        const exe = cc(b, null, opts);
        exe.addArgs(flags);
        exe.addArg("-Wl,-headerpad,0x10000");
        exe.addEmptyMain();

        const check = exe.check();
        check.checkStart("sectname __text");
        check.checkNext("offset {offset}");
        check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x10000 } });
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, null, opts);
        exe.addArgs(flags);
        exe.addArg("-Wl,-headerpad,0x10000");
        exe.addArg("-Wl,-headerpad_max_install_names");
        exe.addEmptyMain();

        const check = exe.check();
        check.checkStart("sectname __text");
        check.checkNext("offset {offset}");
        check.checkComputeCompare("offset", .{ .op = .gte, .value = .{ .literal = 0x10000 } });
        test_step.dependOn(&check.step);

        const run = exe.run();
        test_step.dependOn(run.step());
    }

    {
        const exe = cc(b, null, opts);
        exe.addArgs(flags);
        exe.addArg("-Wl,-headerpad,0x1000");
        exe.addArg("-Wl,-headerpad_max_install_names");
        exe.addEmptyMain();

        const check = exe.check();
        check.checkStart("sectname __text");
        check.checkNext("offset {offset}");
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

fn testHello(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-hello", "");

    const exe = cc(b, null, opts);
    exe.addHelloWorldMain();

    const run = exe.run();
    run.expectHelloWorld();
    test_step.dependOn(run.step());

    return test_step;
}

fn testLayout(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-layout", "");

    const exe = cc(b, null, opts);
    exe.addHelloWorldMain();

    const check = exe.check();
    check.checkStart("cmd SEGMENT_64");
    check.checkNext("segname __LINKEDIT");
    check.checkNext("fileoff {fileoff}");
    check.checkNext("filesz {filesz}");
    check.checkStart("cmd DYLD_INFO_ONLY");
    check.checkNext("rebaseoff {rebaseoff}");
    check.checkNext("rebasesize {rebasesize}");
    check.checkNext("bindoff {bindoff}");
    check.checkNext("bindsize {bindsize}");
    check.checkNext("lazybindoff {lazybindoff}");
    check.checkNext("lazybindsize {lazybindsize}");
    check.checkNext("exportoff {exportoff}");
    check.checkNext("exportsize {exportsize}");
    check.checkStart("cmd FUNCTION_STARTS");
    check.checkNext("dataoff {fstartoff}");
    check.checkNext("datasize {fstartsize}");
    check.checkStart("cmd DATA_IN_CODE");
    check.checkNext("dataoff {diceoff}");
    check.checkNext("datasize {dicesize}");
    check.checkStart("cmd SYMTAB");
    check.checkNext("symoff {symoff}");
    check.checkNext("nsyms {symnsyms}");
    check.checkNext("stroff {stroff}");
    check.checkNext("strsize {strsize}");
    check.checkStart("cmd DYSYMTAB");
    check.checkNext("indirectsymoff {dysymoff}");
    check.checkNext("nindirectsyms {dysymnsyms}");

    switch (builtin.cpu.arch) {
        .aarch64 => {
            check.checkStart("cmd CODE_SIGNATURE");
            check.checkNext("dataoff {codesigoff}");
            check.checkNext("datasize {codesigsize}");
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

fn testNeededFramework(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-needed-framework", "");

    const exe = cc(b, null, opts);
    exe.addArgs(&.{ "-Wl,-needed_framework,Cocoa", "-Wl,-dead_strip_dylibs" });
    exe.addEmptyMain();

    const check = exe.check();
    check.checkStart("cmd LOAD_DYLIB");
    check.checkNext("name {*}Cocoa");
    test_step.dependOn(&check.step);

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testNeededLibrary(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-needed-library", "");

    const dylib = cc(b, "liba.dylib", opts);
    dylib.addArg("-shared");
    dylib.addSourceBytes("int a = 42;", "a.c");

    const exe = cc(b, null, opts);
    exe.addEmptyMain();
    exe.addArgs(&.{ "-Wl,-needed-la", "-Wl,-dead_strip_dylibs" });
    exe.addPrefixedDirectorySource("-L", dylib.saveOutputAs("liba.dylib").dir);

    const check = exe.check();
    check.checkStart("cmd LOAD_DYLIB");
    check.checkNext("name {*}liba.dylib");
    test_step.dependOn(&check.step);

    const run = exe.run();
    test_step.dependOn(run.step());

    return test_step;
}

fn testPagezeroSize(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-pagezero-size", "");

    {
        const exe = cc(b, null, opts);
        exe.addArg("-Wl,-pagezero_size,0x4000");
        exe.addEmptyMain();

        const check = exe.check();
        check.checkStart("LC 0");
        check.checkNext("segname __PAGEZERO");
        check.checkNext("vmaddr 0");
        check.checkNext("vmsize 4000");
        check.checkStart("segname __TEXT");
        check.checkNext("vmaddr 4000");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, null, opts);
        exe.addArg("-Wl,-pagezero_size,0");
        exe.addEmptyMain();

        const check = exe.check();
        check.checkStart("LC 0");
        check.checkNext("segname __TEXT");
        check.checkNext("vmaddr 0");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testSearchStrategy(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-search-strategy", "");

    const obj = cc(b, "a.o", opts);
    obj.addArg("-c");
    obj.addSourceBytes(
        \\#include<stdio.h>
        \\char world[] = "world";
        \\char* hello() {
        \\  return "Hello";
        \\}
    , "a.c");

    const lib = ar(b, "liba.a");
    lib.addFileSource(obj.out);

    const dylib = ld(b, "liba.dylib", opts);
    dylib.addArg("-dylib");
    dylib.addFileSource(obj.out);

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
        const exe = cc(b, null, opts);
        exe.addSourceBytes(main_c, "main.c");
        exe.addArgs(&.{ "-Wl,-search_dylibs_first", "-la" });
        exe.addPrefixedDirectorySource("-L", lib.saveOutputAs("liba.a").dir);
        exe.addPrefixedDirectorySource("-L", dylib.saveOutputAs("liba.dylib").dir);

        const run = exe.run();
        run.expectStdOutEqual("Hello world");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkStart("cmd LOAD_DYLIB");
        check.checkNext("name {*}liba.dylib");
        test_step.dependOn(&check.step);
    }

    {
        const exe = cc(b, null, opts);
        exe.addSourceBytes(main_c, "main.c");
        exe.addArgs(&.{ "-Wl,-search_paths_first", "-la" });
        exe.addPrefixedDirectorySource("-L", lib.saveOutputAs("liba.a").dir);
        exe.addPrefixedDirectorySource("-L", dylib.saveOutputAs("liba.dylib").dir);

        const run = exe.run();
        run.expectStdOutEqual("Hello world");
        test_step.dependOn(run.step());

        const check = exe.check();
        check.checkStart("cmd LOAD_DYLIB");
        check.checkNotPresent("name {*}liba.dylib");
        test_step.dependOn(&check.step);
    }

    return test_step;
}

fn testStackSize(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-stack-size", "");

    const exe = cc(b, null, opts);
    exe.addEmptyMain();
    exe.addArg("-Wl,-stack_size,0x100000000");

    const run = exe.run();
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkStart("cmd MAIN");
    check.checkNext("stacksize 100000000");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testTls(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-tls", "");

    const dylib = cc(b, "liba.dylib", opts);
    dylib.addArg("-shared");
    dylib.addSourceBytes(
        \\_Thread_local int a;
        \\int getA() {
        \\  return a;
        \\}
    , "a.c");

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
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
    , "main.c");
    exe.addArg("-la");
    exe.addPrefixedDirectorySource("-L", dylib.saveOutputAs("liba.dylib").dir);

    const run = exe.run();
    run.expectStdOutEqual("2 2 2");
    test_step.dependOn(run.step());

    return test_step;
}

fn testUnwindInfo(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-unwind-info", "");

    const flags: []const []const u8 = &.{ "-std=c++17", "-c" };
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

    const exe = ld(b, null, opts);
    exe.addArg("-lc++");

    {
        const obj = cc(b, "main.o", opts);
        obj.addSourceBytes(
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
        , "main.cpp");
        obj.addPrefixedDirectorySource("-I", all_h.dir);
        obj.addArgs(flags);
        exe.addFileSource(obj.saveOutputAs("main.o").file);
    }

    {
        const obj = cc(b, "simple_string.o", opts);
        obj.addSourceBytes(
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
        , "simple_string.cpp");
        obj.addPrefixedDirectorySource("-I", all_h.dir);
        obj.addArgs(flags);
        exe.addFileSource(obj.saveOutputAs("simple_string.o").file);
    }

    {
        const obj = cc(b, "simple_string_owner.o", opts);
        obj.addSourceBytes(
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
        , "simple_string_owner.cpp");
        obj.addPrefixedDirectorySource("-I", all_h.dir);
        obj.addArgs(flags);
        exe.addFileSource(obj.saveOutputAs("simple_string_owner.o").file);
    }

    const run = exe.run();
    run.expectStdOutEqual(
        \\Constructed: a
        \\Constructed: b
        \\About to destroy: b
        \\About to destroy: a
        \\Error: Not enough memory!
        \\
    );
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkInSymtab();
    check.checkNext("{*} external ___gxx_personality_v0");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testWeakFramework(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-weak-framework", "");

    const exe = cc(b, null, opts);
    exe.addEmptyMain();
    exe.addArgs(&.{ "-weak_framework", "Cocoa" });

    const run = exe.run();
    test_step.dependOn(run.step());

    const check = exe.check();
    check.checkStart("cmd LOAD_WEAK_DYLIB");
    check.checkNext("name {*}Cocoa");
    test_step.dependOn(&check.step);

    return test_step;
}

fn testWeakLibrary(b: *Build, opts: Options) *Step {
    const test_step = b.step("test-macho-weak-library", "");

    const dylib = cc(b, "liba.dylib", opts);
    dylib.addArg("-shared");
    dylib.addSourceBytes(
        \\#include<stdio.h>
        \\int a = 42;
        \\const char* asStr() {
        \\  static char str[3];
        \\  sprintf(str, "%d", 42);
        \\  return str;
        \\}
    , "a.c");

    const exe = cc(b, null, opts);
    exe.addSourceBytes(
        \\#include<stdio.h>
        \\extern int a;
        \\extern const char* asStr();
        \\int main() {
        \\  printf("%d %s", a, asStr());
        \\  return 0;
        \\}
    , "main.c");
    exe.addArg("-weak-la");
    exe.addPrefixedDirectorySource("-L", dylib.saveOutputAs("liba.dylib").dir);

    const check = exe.check();
    check.checkStart("cmd LOAD_WEAK_DYLIB");
    check.checkNext("name {*}liba.dylib");
    check.checkInSymtab();
    check.checkNext("(undefined) weak external _a (from liba)");
    check.checkInSymtab();
    check.checkNext("(undefined) weak external _asStr (from liba)");
    test_step.dependOn(&check.step);

    const run = exe.run();
    run.expectStdOutEqual("42 42");
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
    cmd.addArg("-dynamic");
    cmd.addArg("-o");
    const out = cmd.addOutputFileArg(name orelse "a.out");
    cmd.addArgs(&.{ "-lSystem", "-lc" });
    if (opts.sdk_path) |sdk| {
        cmd.addArgs(&.{ "-syslibroot", sdk.path });
    }
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
