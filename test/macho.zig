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
        .build_root = "test/macho/dead-strip-dylibs",
        .import = @import("macho/dead-strip-dylibs/build.zig"),
    },
    .{
        .build_root = "test/macho/dylib",
        .import = @import("macho/dylib/build.zig"),
    },
    .{
        .build_root = "test/macho/empty-object",
        .import = @import("macho/empty-object/build.zig"),
    },
    .{
        .build_root = "test/macho/entry-point",
        .import = @import("macho/entry-point/build.zig"),
    },
    .{
        .build_root = "test/macho/entry-point-archive",
        .import = @import("macho/entry-point-archive/build.zig"),
    },
    .{
        .build_root = "test/macho/entry-point-dylib",
        .import = @import("macho/entry-point-dylib/build.zig"),
    },
    .{
        .build_root = "test/macho/headerpad",
        .import = @import("macho/headerpad/build.zig"),
    },
    .{
        .build_root = "test/macho/hello-dynamic",
        .import = @import("macho/hello-dynamic/build.zig"),
    },
    .{
        .build_root = "test/macho/needed-framework",
        .import = @import("macho/needed-framework//build.zig"),
    },
    .{
        .build_root = "test/macho/needed-library",
        .import = @import("macho/needed-library//build.zig"),
    },
    .{
        .build_root = "test/macho/pagezero-size",
        .import = @import("macho/pagezero-size/build.zig"),
    },
    .{
        .build_root = "test/macho/search-dylibs-first",
        .import = @import("macho/search-dylibs-first/build.zig"),
    },
    .{
        .build_root = "test/macho/search-paths-first",
        .import = @import("macho/search-paths-first/build.zig"),
    },
    .{
        .build_root = "test/macho/stack-size",
        .import = @import("macho/stack-size/build.zig"),
    },
    .{
        .build_root = "test/macho/unwind-info",
        .import = @import("macho/unwind-info/build.zig"),
    },
};
