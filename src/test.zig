const std = @import("std");
const build_options = @import("build_options");
const builtin = std.builtin;
const mem = std.mem;
const testing = std.testing;
const process = std.process;
const log = std.log.scoped(.tests);

const Allocator = mem.Allocator;
const ChildProcess = std.ChildProcess;
const Target = std.Target;
const CrossTarget = std.zig.CrossTarget;
const tmpDir = testing.tmpDir;
const ThreadPool = @import("ThreadPool.zig");
const Zld = @import("Zld.zig");

const gpa = testing.allocator;

test "unit" {
    _ = @import("Zld.zig");
}

test "end-to-end" {
    var ctx = TestContext.init();
    defer ctx.deinit();

    try @import("end_to_end_tests").addCases(&ctx);
    try ctx.run();
}

pub const TestContext = struct {
    cases: std.ArrayList(Case),

    pub const Case = struct {
        name: []const u8,
        target: CrossTarget,
        input_files: std.ArrayList(InputFile),
        expected_out: ExpectedOutput = .{},

        const ExpectedOutput = struct {
            stdout: ?[]const u8 = null,
            stderr: ?[]const u8 = null,
        };

        const InputFile = struct {
            const FileType = enum {
                Header,
                C,
                Cpp,
                Zig,
            };

            filetype: FileType,
            basename: []const u8,
            contents: []const u8,

            /// Caller own the memory.
            fn getFilename(self: InputFile, allocator: Allocator) ![]u8 {
                const ext = switch (self.filetype) {
                    .Header => ".h",
                    .C => ".c",
                    .Cpp => ".cpp",
                    .Zig => ".zig",
                };
                return std.fmt.allocPrint(allocator, "{s}{s}", .{ self.basename, ext });
            }
        };

        pub fn init(allocator: Allocator, name: []const u8, target: CrossTarget) Case {
            var input_files = std.ArrayList(InputFile).init(allocator);
            return .{
                .name = name,
                .target = target,
                .input_files = input_files,
            };
        }

        pub fn deinit(self: *Case) void {
            self.input_files.deinit();
        }

        pub fn addInput(self: *Case, filename: []const u8, contents: []const u8) !void {
            const ext = std.fs.path.extension(filename);
            const filetype: InputFile.FileType = blk: {
                if (mem.eql(u8, ".h", ext)) {
                    break :blk .Header;
                } else if (mem.eql(u8, ".c", ext)) {
                    break :blk .C;
                } else if (mem.eql(u8, ".cpp", ext)) {
                    break :blk .Cpp;
                } else if (mem.eql(u8, ".zig", ext)) {
                    break :blk .Zig;
                } else {
                    log.warn("skipping file; unknown filetype detected with extension '{s}'", .{ext});
                    return;
                }
            };
            const index = mem.lastIndexOf(u8, filename, ext).?;
            const basename = filename[0..index];
            try self.input_files.append(.{
                .filetype = filetype,
                .basename = basename,
                .contents = contents,
            });
        }

        pub fn expectedStdout(self: *Case, expected_stdout: []const u8) void {
            self.expected_out.stdout = expected_stdout;
        }

        pub fn expectedStderr(self: *Case, expected_stderr: []const u8) void {
            self.expected_out.stderr = expected_stderr;
        }
    };

    pub fn init() TestContext {
        var cases = std.ArrayList(Case).init(gpa);
        return .{ .cases = cases };
    }

    pub fn deinit(self: *TestContext) void {
        for (self.cases.items) |*case| {
            case.deinit();
        }
        self.cases.deinit();
    }

    pub fn addCase(self: *TestContext, name: []const u8, target: CrossTarget) !*Case {
        const idx = self.cases.items.len;
        try self.cases.append(Case.init(gpa, name, target));
        return &self.cases.items[idx];
    }

    pub fn run(self: *TestContext) !void {
        var arena_allocator = std.heap.ArenaAllocator.init(gpa);
        defer arena_allocator.deinit();
        const arena = arena_allocator.allocator();

        for (self.cases.items) |case| {
            var tmp = tmpDir(.{});
            defer tmp.cleanup();

            const cwd = try std.fs.path.join(arena, &[_][]const u8{
                "zig-cache", "tmp", &tmp.sub_path,
            });

            var objects = std.ArrayList(Zld.LinkObject).init(arena);

            const target_triple = try std.fmt.allocPrint(arena, "{s}-{s}-{s}", .{
                @tagName(case.target.cpu_arch.?),
                @tagName(case.target.os_tag.?),
                @tagName(case.target.abi.?),
            });

            var requires_crts: bool = true;

            for (case.input_files.items) |input_file| {
                const input_filename = try input_file.getFilename(arena);
                try tmp.dir.writeFile(input_filename, input_file.contents);

                var argv = std.ArrayList([]const u8).init(arena);
                try argv.append("zig");

                switch (input_file.filetype) {
                    .C => {
                        try argv.append("cc");
                        try argv.append("-c");
                    },
                    .Cpp => {
                        try argv.append("c++");
                        try argv.append("-c");
                    },
                    .Zig => {
                        try argv.append("build-obj");
                        requires_crts = false;
                    },
                    .Header => continue,
                }

                try argv.append("-target");
                try argv.append(target_triple);

                try argv.append(input_filename);

                const output_filename = try std.fmt.allocPrint(arena, "{s}.o", .{input_file.basename});

                if (input_file.filetype != .Zig) {
                    try argv.append("-o");
                    try argv.append(output_filename);
                }

                const output_file_path = try std.fs.path.join(arena, &[_][]const u8{
                    cwd, output_filename,
                });
                try objects.append(.{ .path = output_file_path, .must_link = false });

                const result = try std.ChildProcess.exec(.{
                    .allocator = arena,
                    .argv = argv.items,
                    .cwd = cwd,
                });
                if (result.stdout.len != 0) {
                    log.warn("unexpected compiler stdout: {s}", .{result.stdout});
                }
                if (result.stderr.len != 0) {
                    log.warn("unexpected compiler stderr: {s}", .{result.stderr});
                }
                if (result.term != .Exited or result.term.Exited != 0) {
                    log.err("{s}", .{result.stderr});
                    try printInvocation(argv.items);
                    return error.CompileError;
                }
            }

            // compiler_rt
            const compiler_rt_path = try std.fs.path.join(arena, &[_][]const u8{
                "test", "assets", target_triple, "libcompiler_rt.a",
            });
            try objects.append(.{ .path = compiler_rt_path, .must_link = false });

            if (case.target.getAbi() == .musl) {
                if (requires_crts) {
                    // crt1
                    const crt1_path = try std.fs.path.join(arena, &[_][]const u8{
                        "test", "assets", target_triple, "crt1.o",
                    });
                    try objects.append(.{ .path = crt1_path, .must_link = true });
                    // crti
                    const crti_path = try std.fs.path.join(arena, &[_][]const u8{
                        "test", "assets", target_triple, "crti.o",
                    });
                    try objects.append(.{ .path = crti_path, .must_link = true });
                    // crtn
                    const crtn_path = try std.fs.path.join(arena, &[_][]const u8{
                        "test", "assets", target_triple, "crtn.o",
                    });
                    try objects.append(.{ .path = crtn_path, .must_link = true });
                }
                // libc
                const libc_path = try std.fs.path.join(arena, &[_][]const u8{
                    "test", "assets", target_triple, "libc.a",
                });
                try objects.append(.{ .path = libc_path, .must_link = false });
            }

            const output_path = try std.fs.path.join(arena, &[_][]const u8{
                "zig-cache", "tmp", &tmp.sub_path, "a.out",
            });

            var libs = std.StringArrayHashMap(Zld.SystemLib).init(arena);
            var lib_dirs = std.ArrayList([]const u8).init(arena);
            var frameworks = std.StringArrayHashMap(Zld.SystemLib).init(arena);
            var framework_dirs = std.ArrayList([]const u8).init(arena);

            const host = try std.zig.system.NativeTargetInfo.detect(.{});
            const target_info = try std.zig.system.NativeTargetInfo.detect(case.target);
            var syslibroot: ?[]const u8 = null;

            if (case.target.isDarwin()) {
                try libs.put("System", .{});
                try lib_dirs.append("/usr/lib");
                try framework_dirs.append("/System/Library/Frameworks");

                if (std.zig.system.darwin.isDarwinSDKInstalled(arena)) {
                    if (std.zig.system.darwin.getDarwinSDK(arena, host.target)) |sdk| {
                        syslibroot = sdk.path;
                    }
                }
            }

            const tag: Zld.Tag = switch (case.target.os_tag.?) {
                .macos,
                .ios,
                .watchos,
                .tvos,
                => .macho,
                .linux => .elf,
                .windows => .coff,
                else => unreachable,
            };
            var opts: Zld.Options = switch (tag) {
                .macho => .{ .macho = .{
                    .emit = .{
                        .directory = std.fs.cwd(),
                        .sub_path = output_path,
                    },
                    .dynamic = true,
                    .target = case.target,
                    .platform_version = target_info.target.os.version_range.semver.min,
                    .sdk_version = target_info.target.os.version_range.semver.min,
                    .output_mode = .exe,
                    .syslibroot = syslibroot,
                    .positionals = objects.items,
                    .libs = libs,
                    .frameworks = frameworks,
                    .lib_dirs = lib_dirs.items,
                    .framework_dirs = framework_dirs.items,
                    .rpath_list = &[0][]const u8{},
                    .dead_strip = true,
                } },
                .elf => .{ .elf = .{
                    .emit = .{
                        .directory = std.fs.cwd(),
                        .sub_path = output_path,
                    },
                    .target = case.target,
                    .output_mode = .exe,
                    .positionals = objects.items,
                    .libs = libs,
                    .lib_dirs = lib_dirs.items,
                    .rpath_list = &[0][]const u8{},
                    .gc_sections = true,
                } },
                .coff => .{ .coff = .{
                    .emit = .{
                        .directory = std.fs.cwd(),
                        .sub_path = output_path,
                    },
                    .target = case.target,
                    .output_mode = .exe,
                    .positionals = objects.items,
                    .libs = libs,
                    .lib_dirs = &[0][]const u8{},
                } },
                .wasm => @panic("TODO"),
            };

            var thread_pool: ThreadPool = undefined;
            try thread_pool.init(gpa);
            defer thread_pool.deinit();

            const zld = try Zld.openPath(gpa, tag, opts, &thread_pool);
            defer zld.deinit();

            var argv = std.ArrayList([]const u8).init(arena);
            outer: {
                switch (host.getExternalExecutor(target_info, .{})) {
                    .native => {
                        try zld.flush();
                        try argv.append("./a.out");
                    },
                    .qemu => |qemu_bin_name| if (build_options.enable_qemu) {
                        try zld.flush();
                        try argv.append(qemu_bin_name);
                        try argv.append("./a.out");
                    } else {
                        break :outer;
                    },
                    else => {
                        // TODO simply pass the test
                        break :outer;
                    },
                }

                const result = try std.ChildProcess.exec(.{
                    .allocator = arena,
                    .argv = argv.items,
                    .cwd = cwd,
                });

                if (case.expected_out.stdout != null or case.expected_out.stderr != null) {
                    if (case.expected_out.stderr) |err| {
                        const pass = mem.eql(u8, result.stderr, err);
                        if (!pass)
                            log.err("STDERR: Test '{s}' failed\nExpected: '{s}'\nGot: '{s}'", .{ case.name, err, result.stderr });
                        try testing.expect(pass);
                    }
                    if (case.expected_out.stdout) |out| {
                        const pass = mem.eql(u8, result.stdout, out);
                        if (!pass)
                            log.err("STDOUT: Test '{s}' failed\nExpected: '{s}'\nGot: '{s}'", .{ case.name, out, result.stdout });
                        try testing.expect(pass);
                    }
                    continue;
                }
                if (result.stderr.len != 0) {
                    log.warn("unexpected exe stderr: {s}", .{result.stderr});
                }
                if (result.term != .Exited or result.term.Exited != 0) {
                    log.err("{s}", .{result.stderr});
                    try printInvocation(argv.items);
                    return error.ExeError;
                }
                log.warn("exe was run, but no expected output was provided", .{});
            }
        }
    }
};

fn printInvocation(argv: []const []const u8) !void {
    const full_inv = try std.mem.join(gpa, " ", argv);
    defer gpa.free(full_inv);
    log.err("The following command failed:\n{s}", .{full_inv});
}
