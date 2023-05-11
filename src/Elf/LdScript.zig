pub fn parse(scr: *LdScript, data: []const u8, elf_file: *Elf) !void {
    _ = elf_file;
    _ = data;
    _ = scr;
}

const Token = struct {
    id: Id,
    start: usize,
    end: usize,

    const Id = enum {
        // zig fmt: off
        eof,
        invalid,

        new_line,
        lparen,    // (
        rparen,    // )
        lbrace,    // {
        rbrace,    // }

        comment,   // /* */

        command,   // literal with special meaning, see Command
        literal,
        // zig fmt: on
    };

    const Index = usize;
};

const Command = enum {
    output_format,
    group,
    as_needed,
};

const Tokenizer = struct {
    buffer: []const u8,
    index: usize = 0,

    fn matchesPattern(comptime pattern: []const u8, slice: []const u8) bool {
        comptime var count: usize = 0;
        inline while (count < pattern.len) : (count += 1) {
            if (count >= slice.len) return false;
            const c = slice[count];
            if (pattern[count] != c) return false;
        }
        return true;
    }

    fn matches(tok: Tokenizer, comptime pattern: []const u8) bool {
        return matchesPattern(pattern, tok.buffer[tok.index..]);
    }

    fn isCommand(tok: Tokenizer, start: usize, end: usize) bool {
        const candidate = tok.buffer[start..end];
        inline for (@typeInfo(Command).Enum.fields) |field| {
            comptime var buf: [field.name.len]u8 = undefined;
            inline for (field.name, 0..) |c, i| {
                buf[i] = comptime std.ascii.toUpper(c);
            }
            if (std.mem.eql(u8, &buf, candidate)) return true;
        }
        return false;
    }

    fn next(tok: *Tokenizer) Token {
        var result = Token{
            .id = .eof,
            .start = tok.index,
            .end = undefined,
        };

        var state: enum {
            start,
            comment,
            literal,
        } = .start;

        while (tok.index < tok.buffer.len) : (tok.index += 1) {
            const c = tok.buffer[tok.index];
            switch (state) {
                .start => switch (c) {
                    ' ', '\t' => result.start += 1,

                    '\n' => {
                        result.id = .new_line;
                        tok.index += 1;
                        break;
                    },

                    '\r' => {
                        if (tok.matches("\r\n")) {
                            result.id = .new_line;
                            tok.index += "\r\n".len;
                        } else {
                            result.id = .invalid;
                            tok.index += 1;
                        }
                        break;
                    },

                    '/' => if (tok.matches("/*")) {
                        state = .comment;
                        tok.index += "/*".len;
                    } else {
                        state = .literal;
                    },

                    '(' => {
                        result.id = .lparen;
                        tok.index += 1;
                        break;
                    },

                    ')' => {
                        result.id = .rparen;
                        tok.index += 1;
                        break;
                    },

                    '{' => {
                        result.id = .lbrace;
                        tok.index += 1;
                        break;
                    },

                    '}' => {
                        result.id = .rbrace;
                        tok.index += 1;
                        break;
                    },

                    else => state = .literal,
                },

                .comment => switch (c) {
                    '*' => if (tok.matches("*/")) {
                        result.id = .comment;
                        tok.index += "*/".len;
                        break;
                    },
                    else => {},
                },

                .literal => switch (c) {
                    ' ', '(', '\n' => {
                        if (tok.isCommand(result.start, tok.index)) {
                            result.id = .command;
                        } else {
                            result.id = .literal;
                        }
                        break;
                    },

                    ')' => {
                        result.id = .literal;
                        break;
                    },

                    '\r' => {
                        if (tok.matches("\r\n")) {
                            if (tok.isCommand(result.start, tok.index)) {
                                result.id = .command;
                            } else {
                                result.id = .literal;
                            }
                        } else {
                            result.id = .invalid;
                            tok.index += 1;
                        }
                        break;
                    },

                    else => {},
                },
            }
        }

        result.end = tok.index;
        return result;
    }

    inline fn get(tok: Tokenizer, token: Token) []const u8 {
        return tok.buffer[token.start..token.end];
    }
};

const testing = std.testing;

fn testExpectedTokens(input: []const u8, expected: []const Token.Id) !void {
    var given = std.ArrayList(Token.Id).init(testing.allocator);
    defer given.deinit();

    var tokenizer = Tokenizer{ .buffer = input };
    while (true) {
        const tok = tokenizer.next();
        if (tok.id == .invalid) {
            std.debug.print("  {s} => '{s}'\n", .{ @tagName(tok.id), tokenizer.get(tok) });
        }
        try given.append(tok.id);
        if (tok.id == .eof) break;
    }

    try testing.expectEqualSlices(Token.Id, expected, given.items);
}

test "Tokenizer - just comments" {
    try testExpectedTokens(
        \\/* GNU ld script
        \\   Use the shared library, but some functions are only in
        \\   the static library, so try that secondarily.  */
    , &.{ .comment, .eof });
}

test "Tokenizer - comments with a simple command" {
    try testExpectedTokens(
        \\/* GNU ld script
        \\   Use the shared library, but some functions are only in
        \\   the static library, so try that secondarily.  */
        \\OUTPUT_FORMAT(elf64-x86-64)
    , &.{ .comment, .new_line, .command, .lparen, .literal, .rparen, .eof });
}

test "Tokenizer - libc.so" {
    try testExpectedTokens(
        \\/* GNU ld script
        \\   Use the shared library, but some functions are only in
        \\   the static library, so try that secondarily.  */
        \\OUTPUT_FORMAT(elf64-x86-64)
        \\GROUP ( /glibc-2.34-210/lib/libc.so.6 /glibc-2.34-210/lib/libc_nonshared.a  AS_NEEDED ( /glibc-2.34-210/lib/ld-linux-x86-64.so.2 ) )
    , &.{
        .comment, .new_line, // GNU comment
        .command, .lparen, .literal, .rparen, .new_line, // output format
        .command, .lparen, .literal, .literal, // group start
        .command, .lparen, .literal, .rparen, // as needed
        .rparen, // group end
        .eof,
    });
}

const LdScript = @This();

const std = @import("std");
const Elf = @import("../Elf.zig");
