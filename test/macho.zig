pub const Case = struct {
    build_root: []const u8,
    import: type,
};

pub const cases = [_]Case{
    .{
        .build_root = "test/macho/dead-strip",
        .import = @import("macho/dead-strip/build.zig"),
    },
    .{
        .build_root = "test/macho/dylib",
        .import = @import("macho/dylib/build.zig"),
    },
    .{
        .build_root = "test/macho/hello-dynamic",
        .import = @import("macho/hello-dynamic/build.zig"),
    },
};
