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

pub const SourceType = enum {
    C,
    Cpp,
    Zig,
};

pub const TestContext = struct {
    cases: std.ArrayList(Case),

    pub const Case = struct {
        target: CrossTarget,
        sources: std.ArrayList(Source),
        expected_out: ?[]const u8 = null,

        const Source = struct {
            src: []const u8,
            tt: SourceType,
        };

        pub fn init(target: CrossTarget) Case {
            var sources = std.ArrayList(Source).init(testing.allocator);
            return .{
                .target = target,
                .sources = sources,
            };
        }

        pub fn deinit(self: *Case) void {
            self.sources.deinit();
        }

        pub fn addSource(self: *Case, src: []const u8, tt: SourceType) !void {
            try self.sources.append(.{
                .src = src,
                .tt = tt,
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
        try self.cases.append(Case.init(target));
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
            try filenames.ensureCapacity(case.sources.items.len);

            for (case.sources.items) |src, i| {
                const ext = switch (src.tt) {
                    .C => ".c",
                    .Cpp => ".cpp",
                    .Zig => ".zig",
                };
                const input_src = try std.fmt.allocPrint(testing.allocator, "src_{}{s}", .{ i, ext });
                defer testing.allocator.free(input_src);

                try tmp.dir.writeFile(input_src, src.src);

                var argv = std.ArrayList([]const u8).init(testing.allocator);
                defer argv.deinit();

                try argv.append("zig");

                switch (src.tt) {
                    .C, .Cpp => {
                        try argv.append("cc");
                        try argv.append("-c");
                    },
                    .Zig => {
                        try argv.append("build-obj");
                    },
                }

                const input_src_path = try std.fs.path.join(testing.allocator, &[_][]const u8{
                    "zig-cache", "tmp", &tmp.sub_path, input_src,
                });
                defer testing.allocator.free(input_src_path);

                try argv.append(input_src_path);
                try argv.append("-o");

                const output_src = try std.fmt.allocPrint(testing.allocator, "obj_{}.o", .{i});
                defer testing.allocator.free(output_src);

                const output_src_path = try std.fs.path.join(testing.allocator, &[_][]const u8{
                    "zig-cache", "tmp", &tmp.sub_path, output_src,
                });
                try argv.append(output_src_path);
                filenames.appendAssumeCapacity(output_src_path);

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
                    return error.ExeError;
                }

                testing.expect(mem.eql(u8, result.stdout, case.expected_out.?));
            }
        }
    }
};
