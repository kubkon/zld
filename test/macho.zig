pub const Case = struct {
    build_root: []const u8,
    import: type,
};

pub const cases = [_]Case{
    .{
        .build_root = "test/macho/hello-dynamic",
        .import = @import("macho/hello-dynamic/build.zig"),
    },
};
