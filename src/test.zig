const std = @import("std");
const build_options = @import("build_options");
const builtin = std.builtin;
const mem = std.mem;
const testing = std.testing;
const process = std.process;
const log = std.log.scoped(.tests);

const ChildProcess = std.ChildProcess;
const Target = std.Target;
const CrossTarget = std.zig.CrossTarget;
const tmpDir = testing.tmpDir;
const Zld = @import("Zld.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();
// TODO fix memory leaks in std.dwarf
// const allocator = testing.allocator();

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
            fn getFilename(self: InputFile) ![]u8 {
                const ext = switch (self.filetype) {
                    .Header => ".h",
                    .C => ".c",
                    .Cpp => ".cpp",
                    .Zig => ".zig",
                };
                return std.fmt.allocPrint(allocator, "{s}{s}", .{ self.basename, ext });
            }
        };

        pub fn init(name: []const u8, target: CrossTarget) Case {
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
        var cases = std.ArrayList(Case).init(allocator);
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
        try self.cases.append(Case.init(name, target));
        return &self.cases.items[idx];
    }

    pub fn run(self: *TestContext) !void {
        for (self.cases.items) |case| {
            var tmp = tmpDir(.{});
            defer tmp.cleanup();

            const cwd = try std.fs.path.join(allocator, &[_][]const u8{
                "zig-cache", "tmp", &tmp.sub_path,
            });
            defer allocator.free(cwd);

            var filenames = std.ArrayList([]u8).init(allocator);
            defer {
                for (filenames.items) |f| {
                    allocator.free(f);
                }
                filenames.deinit();
            }

            const target_triple = try std.fmt.allocPrint(allocator, "{s}-{s}-{s}", .{
                @tagName(case.target.cpu_arch.?),
                @tagName(case.target.os_tag.?),
                @tagName(case.target.abi.?),
            });
            defer allocator.free(target_triple);

            var requires_crts: bool = true;

            for (case.input_files.items) |input_file| {
                const input_filename = try input_file.getFilename();
                defer allocator.free(input_filename);
                try tmp.dir.writeFile(input_filename, input_file.contents);

                var argv = std.ArrayList([]const u8).init(allocator);
                defer argv.deinit();

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

                const output_filename = try std.fmt.allocPrint(allocator, "{s}.o", .{input_file.basename});
                defer allocator.free(output_filename);

                if (input_file.filetype != .Zig) {
                    try argv.append("-o");
                    try argv.append(output_filename);
                }

                const output_file_path = try std.fs.path.join(allocator, &[_][]const u8{
                    cwd, output_filename,
                });
                try filenames.append(output_file_path);

                const result = try std.ChildProcess.exec(.{
                    .allocator = allocator,
                    .argv = argv.items,
                    .cwd = cwd,
                });
                defer {
                    allocator.free(result.stdout);
                    allocator.free(result.stderr);
                }
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
            const compiler_rt_path = try std.fs.path.join(allocator, &[_][]const u8{
                "test", "assets", target_triple, "libcompiler_rt.a",
            });
            try filenames.append(compiler_rt_path);

            if (case.target.getAbi() == .musl) {
                if (requires_crts) {
                    // crt1
                    const crt1_path = try std.fs.path.join(allocator, &[_][]const u8{
                        "test", "assets", target_triple, "crt1.o",
                    });
                    try filenames.append(crt1_path);
                    // crti
                    const crti_path = try std.fs.path.join(allocator, &[_][]const u8{
                        "test", "assets", target_triple, "crti.o",
                    });
                    try filenames.append(crti_path);
                    // crtn
                    const crtn_path = try std.fs.path.join(allocator, &[_][]const u8{
                        "test", "assets", target_triple, "crtn.o",
                    });
                    try filenames.append(crtn_path);
                }
                // libc
                const libc_path = try std.fs.path.join(allocator, &[_][]const u8{
                    "test", "assets", target_triple, "libc.a",
                });
                try filenames.append(libc_path);
            }

            const output_path = try std.fs.path.join(allocator, &[_][]const u8{
                "zig-cache", "tmp", &tmp.sub_path, "a.out",
            });
            defer allocator.free(output_path);

            const host = try std.zig.system.NativeTargetInfo.detect(allocator, .{});
            const target_info = try std.zig.system.NativeTargetInfo.detect(allocator, case.target);
            const syslibroot = blk: {
                if (case.target.getOsTag() == .macos and host.target.os.tag == .macos) {
                    if (!std.zig.system.darwin.isDarwinSDKInstalled(allocator)) break :blk null;
                    const sdk = std.zig.system.darwin.getDarwinSDK(allocator, host.target) orelse
                        break :blk null;
                    break :blk sdk.path;
                }
                break :blk null;
            };
            var zld = try Zld.openPath(allocator, .{
                .emit = .{
                    .directory = std.fs.cwd(),
                    .sub_path = output_path,
                },
                .dynamic = true,
                .target = case.target.toTarget(),
                .output_mode = .exe,
                .syslibroot = syslibroot,
                .positionals = filenames.items,
                .libs = &[0][]const u8{},
                .frameworks = &[0][]const u8{},
                .lib_dirs = &[0][]const u8{},
                .framework_dirs = &[0][]const u8{},
                .rpath_list = &[0][]const u8{},
                .gc_sections = false,
            });
            defer zld.deinit();

            var argv = std.ArrayList([]const u8).init(allocator);
            defer argv.deinit();

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
                    .allocator = allocator,
                    .argv = argv.items,
                    .cwd = cwd,
                });
                defer {
                    allocator.free(result.stdout);
                    allocator.free(result.stderr);
                }

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
    const full_inv = try std.mem.join(allocator, " ", argv);
    defer allocator.free(full_inv);
    log.err("The following command failed:\n{s}", .{full_inv});
}
