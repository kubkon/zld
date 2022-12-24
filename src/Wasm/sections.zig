//! Contains the definiton and logic for all the
//! output sections required to build the final file.
const std = @import("std");
const Symbol = @import("Symbol.zig");
const Object = @import("Object.zig");
const types = @import("types.zig");
const Wasm = @import("../Wasm.zig");
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.wasm);

/// Output function section, holding a list of all
/// function with indexes to their type
pub const Functions = struct {
    /// Holds the list of function type indexes.
    /// The list is built from merging all defined functions into this single list.
    /// Once appended, it becomes immutable and should not be mutated outside this list.
    items: std.ArrayListUnmanaged(std.wasm.Func) = .{},

    /// Adds a new function to the section while also setting the function index
    /// of the `Func` itself.
    pub fn append(self: *Functions, gpa: Allocator, offset: u32, func: std.wasm.Func) !u32 {
        const index = offset + self.count();
        try self.items.append(gpa, func);
        return index;
    }

    /// Returns the count of entires within the function section
    pub fn count(self: *Functions) u32 {
        return @intCast(u32, self.items.items.len);
    }

    pub fn deinit(self: *Functions, gpa: Allocator) void {
        self.items.deinit(gpa);
        self.* = undefined;
    }
};

/// Output import section, containing all the various import types
pub const Imports = struct {
    /// Table where the key is represented by an import.
    /// Each entry represents and imported function where the value contains the index of the function
    /// as well as the index of the type.
    imported_functions: std.ArrayHashMapUnmanaged(
        ImportKey,
        struct { index: u32, type: u32 },
        ImportKey.Ctx,
        true,
    ) = .{},
    /// Table where the key is represented by an import.
    /// Each entry represents an imported global from the host environment and maps to the index
    /// within this map.
    imported_globals: std.ArrayHashMapUnmanaged(
        ImportKey,
        struct { index: u32, global: std.wasm.GlobalType },
        ImportKey.Ctx,
        true,
    ) = .{},
    /// Table where the key is represented by an import.
    /// Each entry represents an imported table from the host environment and maps to the index
    /// within this map.
    imported_tables: std.ArrayHashMapUnmanaged(
        ImportKey,
        struct { index: u32, table: std.wasm.Table },
        ImportKey.Ctx,
        true,
    ) = .{},
    /// A list of symbols representing objects that have been imported.
    imported_symbols: std.ArrayListUnmanaged(Wasm.SymbolWithLoc) = .{},

    const ImportKey = struct {
        module_name: []const u8,
        name: []const u8,

        const Ctx = struct {
            pub fn hash(ctx: Ctx, key: ImportKey) u32 {
                _ = ctx;
                const hashFunc = std.hash.autoHash;
                var hasher = std.hash.Wyhash.init(0);
                hashFunc(&hasher, key.module_name.len);
                hashFunc(&hasher, key.module_name.ptr);
                hashFunc(&hasher, key.name.len);
                hashFunc(&hasher, key.name.ptr);
                return @truncate(u32, hasher.final());
            }

            pub fn eql(ctx: Ctx, lhs: ImportKey, rhs: ImportKey, index: usize) bool {
                _ = ctx;
                _ = index;
                return std.mem.eql(u8, lhs.name, rhs.name) and
                    std.mem.eql(u8, lhs.module_name, rhs.module_name);
            }
        };
    };

    const max_load = std.hash_map.default_max_load_percentage;

    /// Appends an import symbol into the list of imports. Based on the type, also appends it
    /// to their respective import list (such as imported_functions)
    ///
    /// NOTE: The given symbol must reside within the given `Object`.
    pub fn appendSymbol(
        self: *Imports,
        gpa: Allocator,
        wasm: *const Wasm,
        sym_with_loc: Wasm.SymbolWithLoc,
    ) !void {
        const object: *Object = &wasm.objects.items[sym_with_loc.file.?];
        const symbol = &object.symtable[sym_with_loc.sym_index];
        const import = object.findImport(symbol.tag.externalType(), symbol.index);
        const module_name = object.string_table.get(import.module_name);
        const import_name = object.string_table.get(import.name);

        switch (symbol.tag) {
            .function => {
                const ret = try self.imported_functions.getOrPut(gpa, .{
                    .module_name = module_name,
                    .name = import_name,
                });
                if (!ret.found_existing) {
                    try self.imported_symbols.append(gpa, sym_with_loc);
                    ret.value_ptr.* = .{
                        .index = self.functionCount() - 1,
                        .type = import.kind.function,
                    };
                }
                symbol.index = ret.value_ptr.*.index;
                log.debug("Imported function '{s}' at index ({d})", .{ import_name, symbol.index });
            },
            .global => {
                const ret = try self.imported_globals.getOrPut(gpa, .{
                    .module_name = module_name,
                    .name = import_name,
                });
                if (!ret.found_existing) {
                    try self.imported_symbols.append(gpa, sym_with_loc);
                    ret.value_ptr.* = .{
                        .index = self.globalCount() - 1,
                        .global = import.kind.global,
                    };
                }
                symbol.index = ret.value_ptr.*.index;
                log.debug("Imported global '{s}' at index ({d})", .{ import_name, symbol.index });
            },
            .table => {
                const ret = try self.imported_tables.getOrPut(gpa, .{
                    .module_name = module_name,
                    .name = import_name,
                });
                if (!ret.found_existing) {
                    try self.imported_symbols.append(gpa, sym_with_loc);
                    ret.value_ptr.* = .{
                        .index = self.tableCount() - 1,
                        .table = import.kind.table,
                    };
                }
                symbol.index = ret.value_ptr.*.index;
                log.debug("Imported table '{s}' at index ({d})", .{ import_name, symbol.index });
            },
            else => unreachable, // programmer error: Given symbol cannot be imported
        }
    }

    /// Returns the count of functions that have been imported (so far)
    pub fn functionCount(self: Imports) u32 {
        return @intCast(u32, self.imported_functions.count());
    }

    /// Returns the count of tables that have been imported (so far)
    pub fn tableCount(self: Imports) u32 {
        return @intCast(u32, self.imported_tables.count());
    }

    /// Returns the count of globals that have been imported (so far)
    pub fn globalCount(self: Imports) u32 {
        return @intCast(u32, self.imported_globals.count());
    }

    pub fn deinit(self: *Imports, gpa: Allocator) void {
        self.imported_functions.deinit(gpa);
        self.imported_globals.deinit(gpa);
        self.imported_tables.deinit(gpa);
        self.imported_symbols.deinit(gpa);
        self.* = undefined;
    }

    /// Returns a slice to pointers to symbols that have been imported
    pub fn symbols(self: Imports) []const Wasm.SymbolWithLoc {
        return self.imported_symbols.items;
    }

    /// Returns the count of symbols which have been imported
    pub fn symbolCount(self: Imports) u32 {
        return @intCast(u32, self.imported_symbols.items.len);
    }
};

/// Represents the output global section, containing a list of globals
pub const Globals = struct {
    /// A list of `wasm.Global`s
    /// Once appended to this list, they should no longer be mutated
    items: std.ArrayListUnmanaged(std.wasm.Global) = .{},
    /// List of internal GOT symbols
    got_symbols: std.ArrayListUnmanaged(*Symbol) = .{},

    /// Appends a new global and sets the `global_idx` on the global based on the
    /// current count of globals and the given `offset`.
    pub fn append(self: *Globals, gpa: Allocator, offset: u32, global: std.wasm.Global) !u32 {
        const index = offset + @intCast(u32, self.items.items.len);
        try self.items.append(gpa, global);
        return index;
    }

    /// Appends a new entry to the internal GOT
    pub fn addGOTEntry(self: *Globals, gpa: Allocator, symbol: *Symbol, wasm_bin: *Wasm) !void {
        if (symbol.kind == .function) {
            try wasm_bin.tables.createIndirectFunctionTable(gpa, wasm_bin);
            // try wasm_bin.elements.appendSymbol(gpa, symbol);
            @panic("TODO: Implement GOT entries");
        }

        try self.got_symbols.append(gpa, symbol);
    }

    /// Returns the total amount of globals of the global section
    pub fn count(self: Globals) u32 {
        return @intCast(u32, self.items.items.len);
    }

    /// Creates a new linker-defined global with the given mutability and value type.
    /// Also appends the new global to the output global section and returns a pointer
    /// to the newly created global.
    ///
    /// This will automatically set `init` to `null` and can manually be updated at a later point using
    /// the returned pointer.
    pub fn create(self: *Globals, gpa: Allocator, mutability: enum { mutable, immutable }, valtype: types.ValueType) !*types.Global {
        const index = self.count();
        try self.items.append(gpa, .{
            .valtype = valtype,
            .mutable = mutability == .mutable,
            .init = null,
            .global_idx = index,
        });
        return &self.items.items[index];
    }

    pub fn deinit(self: *Globals, gpa: Allocator) void {
        self.items.deinit(gpa);
        self.got_symbols.deinit(gpa);
        self.* = undefined;
    }
};

/// Represents the type section, containing a list of
/// wasm signature types.
pub const Types = struct {
    /// A list of `wasm.FuncType`, when appending to
    /// this list, duplicates will be removed.
    items: std.ArrayListUnmanaged(std.wasm.Type) = .{},

    /// Checks if a given type is already present within the list of types.
    /// If not, the given type will be appended to the list.
    /// In all cases, this will return the index within the list of types.
    pub fn append(self: *Types, gpa: Allocator, func_type: std.wasm.Type) !u32 {
        return self.find(func_type) orelse {
            const index = self.count();
            try self.items.append(gpa, func_type);
            return index;
        };
    }

    /// Returns a pointer to the function type at given `index`
    /// Asserts the index is within bounds.
    pub fn get(self: Types, index: u32) *std.wasm.Type {
        return &self.items.items[index];
    }

    /// Checks if any type (read: function signature) already exists within
    /// the type section. When it does exist, it will return its index
    /// otherwise, returns `null`.
    pub fn find(self: Types, func_type: std.wasm.Type) ?u32 {
        return for (self.items.items) |ty, index| {
            if (std.mem.eql(std.wasm.Valtype, ty.params, func_type.params) and
                std.mem.eql(std.wasm.Valtype, ty.returns, func_type.returns))
            {
                return @intCast(u32, index);
            }
        } else null;
    }

    /// Returns the amount of entries in the type section
    pub fn count(self: Types) u32 {
        return @intCast(u32, self.items.items.len);
    }

    pub fn deinit(self: *Types, gpa: Allocator) void {
        self.items.deinit(gpa);
        self.* = undefined;
    }
};

/// Represents the table section, containing a list
/// of tables, as well as the definition of linker-defined
/// tables such as the indirect function table
pub const Tables = struct {
    /// The list of tables that have been merged from all
    /// object files. This does not include any linker-defined
    /// tables. Once inserted in this list, the object becomes immutable.
    items: std.ArrayListUnmanaged(std.wasm.Table) = .{},

    /// Appends a new table to the list of tables and sets its index to
    /// the position within the list of tables.
    pub fn append(self: *Tables, gpa: Allocator, offset: u32, table: std.wasm.Table) !u32 {
        const index = offset + self.count();
        try self.items.append(gpa, table);
        return index;
    }

    /// Returns the amount of entries in the table section
    pub fn count(self: Tables) u32 {
        return @intCast(u32, self.items.items.len);
    }

    pub fn deinit(self: *Tables, gpa: Allocator) void {
        self.items.deinit(gpa);
        self.* = undefined;
    }
};

/// Represents the exports section, built from explicit exports
/// from all object files, as well as global defined symbols that are
/// non-hidden.
pub const Exports = struct {
    /// List of exports, containing both merged exports
    /// as linker-defined exports such as __stack_pointer.
    items: std.ArrayListUnmanaged(std.wasm.Export) = .{},

    /// Appends a given `wasm.Export` to the list of output exports.
    pub fn append(self: *Exports, gpa: Allocator, exp: std.wasm.Export) !void {
        try self.items.append(gpa, exp);
    }

    /// Returns the amount of entries in the export section
    pub fn count(self: Exports) u32 {
        return @intCast(u32, self.items.items.len);
    }

    pub fn deinit(self: *Exports, gpa: Allocator) void {
        self.items.deinit(gpa);
        self.* = undefined;
    }
};

pub const Elements = struct {
    /// A list of symbols for indirect function calls where the key
    /// represents the symbol location, and the value represents the index into the table.
    indirect_functions: std.AutoArrayHashMapUnmanaged(Wasm.SymbolWithLoc, u32) = .{},

    /// Appends a function symbol to the list of indirect function calls.
    /// The table index will be set on the symbol, based on the length
    ///
    /// Asserts symbol represents a function.
    pub fn appendSymbol(self: *Elements, gpa: Allocator, symbol_loc: Wasm.SymbolWithLoc) !void {
        const gop = try self.indirect_functions.getOrPut(gpa, symbol_loc);
        if (gop.found_existing) return;
        // start at index 1 so the index '0' is an invalid function pointer
        gop.value_ptr.* = self.functionCount() + 1;
    }

    pub fn functionCount(self: Elements) u32 {
        return @intCast(u32, self.indirect_functions.count());
    }

    pub fn deinit(self: *Elements, gpa: Allocator) void {
        self.indirect_functions.deinit(gpa);
        self.* = undefined;
    }
};
