const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const process = std.process;
const log = std.log.scoped(.tests);

const ChildProcess = std.ChildProcess;
const Target = std.Target;
const CrossTarget = std.zig.CrossTarget;
const tmpDir = testing.tmpDir;
const Zld = @import("Zld.zig");

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
        expected_out: ?[]const u8 = null,

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
                return std.fmt.allocPrint(testing.allocator, "{s}{s}", .{ self.basename, ext });
            }
        };

        pub fn init(name: []const u8, target: CrossTarget) Case {
            var input_files = std.ArrayList(InputFile).init(testing.allocator);
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

        pub fn expectedOutput(self: *Case, expected_out: []const u8) void {
            self.expected_out = expected_out;
        }
    };

    pub fn init() TestContext {
        var cases = std.ArrayList(Case).init(testing.allocator);
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

            var filenames = std.ArrayList([]u8).init(testing.allocator);
            defer {
                for (filenames.items) |f| {
                    testing.allocator.free(f);
                }
                filenames.deinit();
            }

            const target_triple = try std.fmt.allocPrint(testing.allocator, "{s}-{s}-{s}", .{
                @tagName(case.target.cpu_arch.?),
                @tagName(case.target.os_tag.?),
                @tagName(case.target.abi.?),
            });
            defer testing.allocator.free(target_triple);

            for (case.input_files.items) |input_file| {
                const input_filename = try input_file.getFilename();
                defer testing.allocator.free(input_filename);
                try tmp.dir.writeFile(input_filename, input_file.contents);

                var argv = std.ArrayList([]const u8).init(testing.allocator);
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
                    },
                    .Header => continue,
                }

                try argv.append("-target");
                try argv.append(target_triple);

                const input_file_path = try std.fs.path.join(testing.allocator, &[_][]const u8{
                    "zig-cache", "tmp", &tmp.sub_path, input_filename,
                });
                defer testing.allocator.free(input_file_path);

                try argv.append(input_file_path);
                try argv.append("-o");

                const output_filename = try std.fmt.allocPrint(testing.allocator, "{s}.o", .{input_file.basename});
                defer testing.allocator.free(output_filename);

                const output_file_path = try std.fs.path.join(testing.allocator, &[_][]const u8{
                    "zig-cache", "tmp", &tmp.sub_path, output_filename,
                });
                try argv.append(output_file_path);
                try filenames.append(output_file_path);

                const result = try std.ChildProcess.exec(.{
                    .allocator = testing.allocator,
                    .argv = argv.items,
                });
                defer {
                    testing.allocator.free(result.stdout);
                    testing.allocator.free(result.stderr);
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

            const output_path = try std.fs.path.join(testing.allocator, &[_][]const u8{
                "zig-cache", "tmp", &tmp.sub_path, "a.out",
            });
            defer testing.allocator.free(output_path);

            var zld = Zld.init(testing.allocator);
            defer zld.deinit();
            try zld.link(filenames.items, output_path);

            var argv = std.ArrayList([]const u8).init(testing.allocator);
            defer argv.deinit();

            outer: {
                switch (case.target.getExternalExecutor()) {
                    .native => try argv.append(output_path),
                    else => {
                        // TODO simply pass the test
                        break :outer;
                    },
                }

                const result = try std.ChildProcess.exec(.{
                    .allocator = testing.allocator,
                    .argv = argv.items,
                });
                defer {
                    testing.allocator.free(result.stdout);
                    testing.allocator.free(result.stderr);
                }
                if (result.stderr.len != 0) {
                    log.warn("unexpected exe stderr: {s}", .{result.stderr});
                }
                if (result.term != .Exited or result.term.Exited != 0) {
                    log.err("{s}", .{result.stderr});
                    try printInvocation(argv.items);
                    return error.ExeError;
                }

                if (case.expected_out) |exp| {
                    const pass = mem.eql(u8, result.stdout, exp);
                    if (!pass) {
                        log.err("Test '{s}' failed\nExpected: '{s}'\nGot: '{s}'", .{ case.name, exp, result.stdout });
                    }
                    testing.expect(pass);
                } else {
                    log.warn("exe was run, but no expected output was provided", .{});
                }
            }
        }
    }
};

fn printInvocation(argv: []const []const u8) !void {
    const full_inv = try std.mem.join(testing.allocator, " ", argv);
    defer testing.allocator.free(full_inv);
    log.err("The following command failed:\n{s}", .{full_inv});
}
