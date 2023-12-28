pub fn flush(macho_file: *MachO) !void {
    claimUnresolved(macho_file);

    state_log.debug("{}", .{macho_file.dumpState()});

    macho_file.base.fatal("-r mode unimplemented", .{});
    return error.Unimplemented;
}

fn claimUnresolved(macho_file: *MachO) void {
    for (macho_file.objects.items) |index| {
        const object = macho_file.getFile(index).?.object;

        for (object.symbols.items, 0..) |sym_index, i| {
            const nlist_idx = @as(Symbol.Index, @intCast(i));
            const nlist = object.symtab.items(.nlist)[nlist_idx];
            if (!nlist.ext()) continue;
            if (!nlist.undf()) continue;

            const sym = macho_file.getSymbol(sym_index);
            if (sym.getFile(macho_file) != null) continue;

            sym.value = 0;
            sym.atom = 0;
            sym.nlist_idx = nlist_idx;
            sym.file = index;
            sym.flags.weak_ref = nlist.weakRef();
            sym.flags.import = true;
        }
    }
}

const state_log = std.log.scoped(.state);
const std = @import("std");

const MachO = @import("../MachO.zig");
const Symbol = @import("Symbol.zig");
