pub const RelocSection = struct {
    entries: std.ArrayListUnmanaged(Entry) = .{},
    pages: std.ArrayListUnmanaged(Page) = .{},

    pub fn deinit(rel: *RelocSection, allocator: Allocator) void {
        rel.entries.deinit(allocator);
        for (rel.pages.items) |*page| {
            page.deinit(allocator);
        }
        rel.pages.deinit(allocator);
    }

    pub fn updateSize(rel: *RelocSection, coff_file: *Coff) !u32 {
        // Sort entries by output section and offset.
        rel.sort(coff_file);

        // Bin relocations in pages.
        const gpa = coff_file.base.allocator;
        var rel_index: usize = 0;
        var last_page: ?*Page = null;
        while (rel_index < rel.entries.items.len) {
            const entry = rel.entries.items[rel_index];
            const addr = entry.getAddress(coff_file);
            const page = mem.alignBackward(u32, addr, Page.page_size);
            const off = std.math.cast(u12, addr - page) orelse return error.Overflow;
            const last = if (last_page) |last| blk: {
                if (last.getAddress(coff_file) != page) {
                    const next = try rel.pages.addOne(gpa);
                    next.* = .{ .atom = entry.atom };
                    last_page = next;
                    break :blk next;
                }
                break :blk last;
            } else blk: {
                const last = try rel.pages.addOne(gpa);
                last.* = .{ .atom = entry.atom };
                last_page = last;
                break :blk last;
            };
            try last.relocs.append(gpa, .{
                .offset = off,
                .type = .DIR64, // TODO handle more types
            });
            rel_index += 1;
        }

        // Pad to required 4-byte alignment.
        for (rel.pages.items) |*page| {
            const size = page.relocs.items.len * @sizeOf(coff.BaseRelocation);
            if (!mem.isAlignedGeneric(usize, size, @sizeOf(u32))) {
                try page.relocs.append(gpa, .{
                    .offset = 0,
                    .type = .ABSOLUTE,
                });
            }
        }

        var size: u32 = @intCast(rel.pages.items.len * @sizeOf(coff.BaseRelocationDirectoryEntry));
        for (rel.pages.items) |page| {
            size += page.size();
        }

        return size;
    }

    pub fn write(rel: RelocSection, coff_file: *Coff, writer: anytype) !void {
        for (rel.pages.items) |page| {
            const dir_entry = coff.BaseRelocationDirectoryEntry{
                .page_rva = page.getAddress(coff_file),
                .block_size = page.size() + @sizeOf(coff.BaseRelocationDirectoryEntry),
            };
            try writer.writeAll(mem.asBytes(&dir_entry));
            try writer.writeAll(mem.sliceAsBytes(page.relocs.items));
        }
    }

    fn sort(rel: *RelocSection, coff_file: *Coff) void {
        const sortFn = struct {
            fn sortFn(ctx: *Coff, lhs: Entry, rhs: Entry) bool {
                const lhs_atom = ctx.getAtom(lhs.atom).?;
                const rhs_atom = ctx.getAtom(rhs.atom).?;
                if (lhs_atom.out_section_number == rhs_atom.out_section_number) {
                    return lhs.getAddress(ctx) < rhs.getAddress(ctx);
                }
                return lhs_atom.out_section_number < rhs_atom.out_section_number;
            }
        }.sortFn;
        mem.sort(Entry, rel.entries.items, coff_file, sortFn);
    }

    const Entry = struct {
        atom: Atom.Index,
        offset: u32,

        fn getAtom(entry: Entry, coff_file: *Coff) *Atom {
            return coff_file.getAtom(entry.atom).?;
        }

        fn getAddress(entry: Entry, coff_file: *Coff) u32 {
            return entry.getAtom(coff_file).getAddress(coff_file) + entry.offset;
        }
    };

    const Page = struct {
        atom: Atom.Index,
        relocs: std.ArrayListUnmanaged(coff.BaseRelocation) = .{},

        fn deinit(page: *Page, allocator: Allocator) void {
            page.relocs.deinit(allocator);
        }

        fn getAddress(page: Page, coff_file: *Coff) u32 {
            const addr = coff_file.getAtom(page.atom).?.getAddress(coff_file);
            return mem.alignBackward(u32, addr, Page.page_size);
        }

        fn size(page: Page) u32 {
            return @intCast(page.relocs.items.len * @sizeOf(coff.BaseRelocation));
        }

        const page_size = 0x1000;
    };
};

const coff = std.coff;
const mem = std.mem;
const std = @import("std");

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const Coff = @import("../Coff.zig");
const Symbol = @import("Symbol.zig");
