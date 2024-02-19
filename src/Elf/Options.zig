emit: Zld.Emit,
shared: bool = false,
relocatable: bool = false,
positionals: []const Elf.LinkObject,
search_dirs: []const []const u8,
rpath_list: []const []const u8,
strip_debug: bool = false,
strip_all: bool = false,
entry: ?[]const u8 = null,
gc_sections: bool = false,
print_gc_sections: bool = false,
allow_multiple_definition: bool = false,
cpu_arch: ?std.Target.Cpu.Arch = null,
os_tag: ?std.Target.Os.Tag = null,
dynamic_linker: ?[]const u8 = null,
eh_frame_hdr: bool = true,
static: bool = false,
relax: bool = true,
export_dynamic: bool = false,
image_base: u64 = 0x200000,
page_size: ?u16 = null,
pie: bool = false,
pic: bool = false,
warn_common: bool = false,
build_id: ?BuildId = null,
hash_style: ?HashStyle = null,
apply_dynamic_relocs: bool = true,
soname: ?[]const u8 = null,
/// -z flags
/// Overrides default stack size.
z_stack_size: ?u64 = null,
/// Marks the writeable segments as executable.
z_execstack: bool = false,
/// Marks the writeable segments as executable only if requested by an input object file
/// via sh_flags of the input .note.GNU-stack section.
z_execstack_if_needed: bool = false,
/// Disables lazy function resolution.
z_now: bool = false,
/// Do not create copy relocations.
z_nocopyreloc: bool = false,
/// Mark DSO not available for dlopen.
z_nodlopen: bool = false,
/// Do not allow relocations against read-only segments.
z_text: bool = false,
/// Make some sections read-only after dynamic relocations.
/// TODO make this default to true.
z_relro: bool = false,

pub fn parse(arena: Allocator, args: []const []const u8, ctx: anytype) !Options {
    if (args.len == 0) ctx.fatal(usage ++ "\n", .{cmd});

    var positionals = std.ArrayList(Positional).init(arena);
    var search_dirs = std.StringArrayHashMap(void).init(arena);
    var rpath_list = std.StringArrayHashMap(void).init(arena);
    var verbose = false;
    var print_version = false;
    var print_target_info = false;
    var opts: Options = .{
        .emit = .{
            .directory = std.fs.cwd(),
            .sub_path = "a.out",
        },
        .positionals = undefined,
        .search_dirs = undefined,
        .rpath_list = undefined,
    };

    var it = Zld.Options.ArgsIterator{ .args = args };
    var p = Zld.ArgParser(@TypeOf(ctx)){ .it = &it, .ctx = ctx };
    while (p.hasMore()) {
        if (p.flag2("help")) {
            ctx.fatal(usage ++ "\n", .{cmd});
        } else if (p.arg2("debug-log")) |scope| {
            try ctx.log_scopes.append(scope);
        } else if (p.arg1("l")) |lib| {
            try positionals.append(.{ .tag = .path, .path = try std.fmt.allocPrint(arena, "-l{s}", .{lib}) });
        } else if (p.arg1("L")) |dir| {
            try search_dirs.put(dir, {});
        } else if (p.arg1("o")) |path| {
            opts.emit.sub_path = path;
        } else if (p.flag1("r") or p.flagAny("relocatable")) {
            opts.relocatable = true;
        } else if (p.argAny("image-base")) |value| {
            opts.image_base = std.fmt.parseInt(u64, value, 0) catch
                ctx.fatal("Could not parse value '{s}' into integer\n", .{value});
        } else if (p.flagAny("gc-sections")) {
            opts.gc_sections = true;
        } else if (p.flagAny("no-gc-sections")) {
            opts.gc_sections = false;
        } else if (p.flagAny("print-gc-sections")) {
            opts.print_gc_sections = true;
        } else if (p.flagAny("shared")) {
            opts.shared = true;
        } else if (p.argAny("rpath")) |path| {
            try rpath_list.put(path, {});
        } else if (p.arg1("R")) |path| {
            try rpath_list.put(path, {});
        } else if (p.flagAny("export-dynamic") or p.flag1("E")) {
            opts.export_dynamic = true;
        } else if (p.flagAny("no-export-dynamic")) {
            opts.export_dynamic = false;
        } else if (p.flagAny("pie") or p.flagAny("pic-executable")) {
            opts.pic = true;
            opts.pie = true;
        } else if (p.flagAny("no-pie") or p.flagAny("no-pic-executable")) {
            opts.pic = false;
            opts.pie = false;
        } else if (p.argAny("entry")) |name| {
            opts.entry = name;
        } else if (p.arg1("e")) |name| {
            opts.entry = name;
        } else if (p.arg1("m")) |target| {
            if (cpuArchFromElfEmulation(target)) |cpu_arch| {
                opts.cpu_arch = cpu_arch;
            } else {
                ctx.fatal("unknown target emulation '{s}'\n", .{target});
            }
        } else if (p.flagAny("allow-multiple-definition")) {
            opts.allow_multiple_definition = true;
        } else if (p.flagAny("warn-common")) {
            opts.warn_common = true;
        } else if (p.flagAny("static")) {
            opts.static = true;
            try positionals.append(.{ .tag = .static });
        } else if (p.flagAny("dynamic")) {
            opts.static = false;
            try positionals.append(.{ .tag = .dynamic });
        } else if (p.argAny("B")) |b_arg| {
            if (mem.eql(u8, b_arg, "static")) {
                opts.static = true;
                try positionals.append(.{ .tag = .static });
            } else if (mem.eql(u8, b_arg, "dynamic")) {
                opts.static = false;
                try positionals.append(.{ .tag = .dynamic });
            } else {
                ctx.fatal("unknown argument '--B{s}'\n", .{b_arg});
            }
        } else if (p.flagAny("start-group") or p.flagAny("end-group")) {
            // Ignored
        } else if (p.flagAny("strip-debug") or p.flag1("S")) {
            opts.strip_debug = true;
        } else if (p.flagAny("strip-all") or p.flag1("s")) {
            opts.strip_all = true;
        } else if (p.flagAny("as-needed")) {
            try positionals.append(.{ .tag = .as_needed });
        } else if (p.flagAny("no-as-needed")) {
            try positionals.append(.{ .tag = .no_as_needed });
        } else if (p.flagAny("push-state")) {
            try positionals.append(.{ .tag = .push_state });
        } else if (p.flagAny("pop-state")) {
            try positionals.append(.{ .tag = .pop_state });
        } else if (p.argAny("dynamic-linker")) |path| {
            opts.dynamic_linker = path;
        } else if (p.flagAny("no-dynamic-linker")) {
            opts.dynamic_linker = null;
        } else if (p.arg1("I")) |path| {
            opts.dynamic_linker = path;
        } else if (p.flagAny("eh-frame-hdr")) {
            opts.eh_frame_hdr = true;
        } else if (p.flagAny("no-eh-frame-hdr")) {
            opts.eh_frame_hdr = false;
        } else if (p.flagAny("relax")) {
            opts.relax = true;
        } else if (p.flagAny("no-relax")) {
            opts.relax = false;
        } else if (p.flagAny("verbose")) {
            verbose = true;
        } else if (p.argAny("build-id")) |value| {
            if (std.mem.eql(u8, "none", value)) {
                opts.build_id = .none;
            } else if (std.mem.eql(u8, "md5", value)) {
                opts.build_id = .md5;
            } else if (std.mem.eql(u8, "sha1", value)) {
                opts.build_id = .sha1;
            } else if (std.mem.eql(u8, "sha256", value)) {
                opts.build_id = .sha256;
            } else if (std.mem.eql(u8, "uuid", value)) {
                opts.build_id = .uuid;
            } else {
                ctx.fatal("invalid build-id value '--build-id={s}'\n", .{value});
            }
        } else if (p.flagAny("build-id")) {
            opts.build_id = .none;
        } else if (p.flagAny("no-build-id")) {
            opts.build_id = .none;
        } else if (p.argAny("hash-style")) |value| {
            if (std.mem.eql(u8, "none", value)) {
                opts.hash_style = .none;
            } else if (std.mem.eql(u8, "gnu", value)) {
                opts.hash_style = .gnu;
            } else if (std.mem.eql(u8, "sysv", value)) {
                opts.hash_style = .sysv;
            } else if (std.mem.eql(u8, "both", value)) {
                opts.hash_style = .both;
            } else {
                ctx.fatal("invalid hash-style value '--hash-style={s}'\n", .{value});
            }
        } else if (p.flagAny("apply-dynamic-relocs")) {
            opts.apply_dynamic_relocs = true;
        } else if (p.flagAny("no-apply-dynamic-relocs")) {
            opts.apply_dynamic_relocs = false;
        } else if (p.flagAny("nostdlib")) {
            // ignore
        } else if (p.flag1("v") or p.flagAny("version")) {
            print_version = true;
        } else if (p.flag1("V")) {
            print_version = true;
            print_target_info = true;
        } else if (p.argAny("soname")) |value| {
            opts.soname = value;
        } else if (p.arg1("h")) |value| {
            opts.soname = value;
        } else if (p.argZ("stack-size")) |value| {
            opts.z_stack_size = std.fmt.parseInt(u64, value, 0) catch
                ctx.fatal("Could not parse value '{s}' into integer\n", .{value});
        } else if (p.flagZ("execstack")) {
            opts.z_execstack = true;
        } else if (p.flagZ("noexecstack")) {
            opts.z_execstack = false;
        } else if (p.flagZ("execstack-if-needed")) {
            opts.z_execstack_if_needed = true;
        } else if (p.flagZ("now")) {
            opts.z_now = true;
        } else if (p.flagZ("lazy")) {
            opts.z_now = false;
        } else if (p.flagZ("nocopyreloc")) {
            opts.z_nocopyreloc = true;
        } else if (p.flagZ("nodlopen")) {
            opts.z_nodlopen = true;
        } else if (p.flagZ("text")) {
            opts.z_text = true;
        } else if (p.flagZ("notext")) {
            opts.z_text = false;
        } else if (p.flagZ("relro")) {
            opts.z_relro = true;
        } else if (p.flagZ("norelro")) {
            opts.z_relro = false;
        } else if (p.flagZ("muldefs")) {
            opts.allow_multiple_definition = true;
        } else {
            try positionals.append(.{ .tag = .path, .path = p.arg });
        }
    }

    if (verbose) {
        ctx.print("{s} ", .{cmd});
        for (args[0 .. args.len - 1]) |arg| {
            ctx.print("{s} ", .{arg});
        }
        ctx.print("{s}\n", .{args[args.len - 1]});
    }

    if (print_version) {
        ctx.print("{s}\n", .{version});
    }
    if (print_target_info) {
        const nemuls = supported_emulations.len;
        ctx.print(" Supported emulations:\n", .{});
        inline for (supported_emulations[0 .. nemuls - 1]) |emulation| {
            ctx.print("  {s}\n", .{cpuArchToElfEmulation(emulation[0])});
        }
        ctx.print("  {s}\n", .{cpuArchToElfEmulation(supported_emulations[nemuls - 1][0])});
    }

    if (positionals.items.len == 0) ctx.fatal("Expected at least one positional argument\n", .{});
    if (opts.shared) opts.pic = true;
    if (opts.pic) opts.image_base = 0;
    if (opts.cpu_arch) |cpu_arch| {
        const page_size = defaultPageSize(cpu_arch).?;
        if (opts.image_base % page_size != 0) {
            ctx.fatal("specified --image-base=0x{x} is not a multiple of page size of 0x{x}\n", .{
                opts.image_base,
                page_size,
            });
        }
        opts.page_size = page_size;
    }

    opts.positionals = try unpackPositionals(arena, .{
        .static = opts.static,
        .unprocessed = positionals.items,
    }, ctx);
    opts.search_dirs = search_dirs.keys();
    opts.rpath_list = rpath_list.keys();

    return opts;
}

const Positional = struct {
    tag: Tag,
    path: []const u8 = "",

    pub const Tag = enum {
        path,
        static,
        dynamic,
        as_needed,
        no_as_needed,
        push_state,
        pop_state,
    };
};

const UnpackArgs = struct {
    static: bool,
    unprocessed: []const Positional,
};

fn unpackPositionals(arena: Allocator, args: UnpackArgs, ctx: anytype) ![]const Elf.LinkObject {
    const State = struct {
        needed: bool,
        static: bool,
    };

    var positionals = std.ArrayList(Elf.LinkObject).init(arena);
    try positionals.ensureTotalCapacity(args.unprocessed.len);

    var stack = std.ArrayList(State).init(arena);
    var state = State{ .needed = true, .static = args.static };

    for (args.unprocessed) |arg| switch (arg.tag) {
        .path => positionals.appendAssumeCapacity(.{
            .path = arg.path,
            .needed = state.needed,
            .static = state.static,
        }),
        .static => state.static = true,
        .dynamic => state.static = false,
        .as_needed => state.needed = false,
        .no_as_needed => state.needed = true,
        .push_state => try stack.append(state),
        .pop_state => state = stack.popOrNull() orelse return ctx.fatal("no state pushed before pop\n", .{}),
    };

    return positionals.toOwnedSlice();
}

const usage =
    \\Usage: {s} [files...]
    \\
    \\General Options:
    \\--allow-multiple-definition   Allow multiple definitions
    \\--apply-dynamic-relocs        Apply link-time values for dynamic relocations (default)
    \\  --no-apply-dynamic-relocs
    \\--as-needed                   Only set DT_NEEDED for shared libraries if used
    \\  --no-as-needed
    \\--Bstatic, --static           Do not link against shared libraries
    \\--Bdynamic                    Link against shared libraries (default)
    \\--build-id=[none,md5,sha1,sha256,uuid,HEXSTRING]
    \\                              Generate build ID
    \\  --no-build-id
    \\--debug-log [value]           Turn on debugging logs for [value] (requires zld compiled with -Dlog)
    \\--dynamic                     Alias for --Bdynamic
    \\--dynamic-linker=[value], -I [value]      
    \\                              Set the dynamic linker to use
    \\  --no-dynamic-linker
    \\--eh-frame-hdr                Create .eh_frame_hdr section (default)
    \\  --no-eh-frame-hdr
    \\--end-group                   Ignored for compatibility with GNU
    \\--entry=[value], -e [value]   Set name of the entry point symbol
    \\--export-dynamic, -E          Export all dynamic symbols
    \\  --no-export-dynamic
    \\--gc-sections                 Remove unused sections
    \\  --no-gc-sections
    \\--hash-style=[none,sysv,gnu,both]
    \\                              Set hash style
    \\--help                        Print this help and exit
    \\--image-base=[value]          Set the base address
    \\-l[value]                     Specify library to link against
    \\-L[value]                     Specify library search dir
    \\-m [value]                    Set target emulation
    \\-o [value]                    Specify output path for the final artifact
    \\--pie, --pic-executable       Create a position independent executable
    \\  --no-pie, --no-pic-executable
    \\--pop-state                   Restore the states saved by --push-state
    \\--print-gc-sections           List removed unused sections to stderr
    \\--push-state                  Save the current state of --as-needed, -static and --whole-archive
    \\-r                            Create a relocatable object file
    \\  --relocatable
    \\--relax                       Optimize instructions (default)
    \\  --no-relax
    \\--rpath=[value], -R [value]   Specify runtime path
    \\--shared                      Create dynamic library
    \\--soname=[value], -h [value]  Set shared library name
    \\--start-group                 Ignored for compatibility with GNU
    \\--strip-all, -s               Strip all symbols. Implies --strip-debug
    \\--strip-debug, -S             Strip .debug_ sections
    \\--warn-common                 Warn about duplicate common symbols
    \\-z                            Set linker extension flags
    \\  execstack                   Require executable stack
    \\    noexecstack               
    \\  execstack-if-needed         Make the stack executable if the input file explicitly requests it
    \\  lazy                        Enable lazy function resolution (default)
    \\  muldefs                     Allow multiple definitions
    \\  nocopyreloc                 Do not create copy relocations
    \\  nodlopen                    Mark DSO not available to dlopen
    \\  now                         Disable lazy function resolution
    \\  stack-size=[value]          Override default stack size
    \\  text                        Do not allow relocations against read-only segments
    \\    notext                    
    \\  relro                       Make some sections read-only after dynamic relocations
    \\    norelro                   
    \\--verbose                     Print full linker invocation to stderr
    \\-v, --version                 Print version
    \\-V                            Print version and target information
    \\
    \\ld.zld: supported target: elf64-x86-64, elf64-littleaarch64, elf64-littleriscv
    \\ld.zld: supported emulations: elf64_x86_64, aarch64linux, aarch64elf, elf64lriscv
;

const version =
    \\ld.zld 0.0.4 (compatible with GNU ld)
;

fn cpuArchToElfEmulation(cpu_arch: std.Target.Cpu.Arch) []const u8 {
    return switch (cpu_arch) {
        .x86_64 => "elf_x86_64",
        .aarch64 => "aarch64linux",
        .riscv64 => "elf64lriscv",
        else => unreachable,
    };
}

const supported_emulations = [_]struct { std.Target.Cpu.Arch, u16 }{
    .{ .x86_64, 0x1000 },
    .{ .aarch64, 0x1000 },
    .{ .riscv64, 0x1000 },
};

fn cpuArchFromElfEmulation(value: []const u8) ?std.Target.Cpu.Arch {
    inline for (supported_emulations) |emulation| {
        if (mem.eql(u8, cpuArchToElfEmulation(emulation[0]), value)) {
            return emulation[0];
        }
    }
    return null;
}

pub fn defaultPageSize(cpu_arch: std.Target.Cpu.Arch) ?u16 {
    inline for (supported_emulations) |emulation| {
        if (cpu_arch == emulation[0]) return emulation[1];
    }
    return null;
}

const cmd = "ld.zld";

pub const BuildId = enum {
    none,
    md5,
    sha1,
    sha256,
    uuid,
    hex,
};

pub const HashStyle = enum {
    none,
    sysv,
    gnu,
    both,
};

const std = @import("std");
const builtin = @import("builtin");
const io = std.io;
const mem = std.mem;
const process = std.process;

const Allocator = mem.Allocator;
const Elf = @import("../Elf.zig");
const Options = @This();
const Zld = @import("../Zld.zig");
