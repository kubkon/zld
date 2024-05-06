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
        rel.sort(coff_file);
        for (rel.entries.items) |entry| {
            std.debug.print("{d} : {x}\n", .{
                entry.getAtom(coff_file).out_section_number,
                entry.getAddress(coff_file),
            });
        }
        return 0;
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
        value: u32,
        relocs: std.ArrayListUnmanaged(coff.BaseRelocation) = .{},

        fn deinit(page: *Page, allocator: Allocator) void {
            page.relocs.deinit(allocator);
        }
    };
};

const coff = std.coff;
const mem = std.mem;
const std = @import("std");

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const Coff = @import("../Coff.zig");
const Symbol = @import("Symbol.zig");
