pub fn parse(scr: *LdScript, data: []const u8, elf_file: *Elf) !void {
    _ = elf_file;
    _ = data;
    _ = scr;
}

const Command = enum {
    output_format,
    group,
    as_needed,

    fn fromString(s: []const u8) ?Command {
        inline for (@typeInfo(Command).Enum.fields) |field| {
            comptime var buf: [field.name.len]u8 = undefined;
            inline for (field.name, 0..) |c, i| {
                buf[i] = comptime std.ascii.toUpper(c);
            }
            if (std.mem.eql(u8, &buf, s)) return @field(Command, field.name);
        }
        return null;
    }
};

const Parser = struct {
    source: []const u8,
    it: *TokenIterator,

    fn outputFormat(p: *Parser) !std.Target.Cpu.Arch {
        const cmd_tok_id = try p.require(.command);
        const cmd = p.getCommand(cmd_tok_id);
        assert(cmd == .output_format);
        const value = value: {
            if (p.skip(&.{.lparen})) {
                const value_id = try p.require(.literal);
                const value = p.it.tokens[value_id];
                _ = try p.require(.rparen);
                break :value value.get(p.source);
            } else if (p.skip(&.{ .new_line, .lbrace })) {
                const value_id = try p.require(.literal);
                const value = p.it.tokens[value_id];
                _ = p.skip(&.{.new_line});
                _ = try p.require(.rbrace);
                break :value value.get(p.source);
            } else return error.UnexpectedToken;
        };
        if (std.mem.eql(u8, value, "elf64-x86-64")) return .x86_64;
        return error.UnknownCpuArch;
    }

    fn skip(p: *Parser, comptime ids: []const Token.Id) bool {
        const pos = p.it.pos;
        inline for (ids) |id| {
            const tok = p.it.next() orelse return false;
            if (tok.id != id) {
                p.it.seekTo(pos);
                return false;
            }
        }
        return true;
    }

    fn require(p: *Parser, comptime id: Token.Id) !Token.Index {
        const pos = p.it.pos;
        const tok = p.it.next() orelse return error.UnexpectedToken;
        if (tok.id == id) return pos;
        p.it.seekBy(-1);
        return error.UnexpectedToken;
    }

    fn getCommand(p: *Parser, index: Token.Index) Command {
        const tok = p.it.tokens[index];
        assert(tok.id == .command);
        return Command.fromString(tok.get(p.source)).?;
    }
};

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

    inline fn get(tok: Token, source: []const u8) []const u8 {
        return source[tok.start..tok.end];
    }
};

const Tokenizer = struct {
    source: []const u8,
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
        return matchesPattern(pattern, tok.source[tok.index..]);
    }

    fn isCommand(tok: Tokenizer, start: usize, end: usize) bool {
        return if (Command.fromString(tok.source[start..end]) == null) false else true;
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

        while (tok.index < tok.source.len) : (tok.index += 1) {
            const c = tok.source[tok.index];
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
};

const TokenIterator = struct {
    tokens: []const Token,
    pos: Token.Index = 0,

    fn next(it: *TokenIterator) ?Token {
        const token = it.peek() orelse return null;
        it.pos += 1;
        return token;
    }

    fn peek(it: TokenIterator) ?Token {
        if (it.pos >= it.tokens.len) return null;
        return it.tokens[it.pos];
    }

    inline fn reset(it: *TokenIterator) void {
        it.pos = 0;
    }

    inline fn seekTo(it: *TokenIterator, pos: Token.Index) void {
        it.pos = pos;
    }

    fn seekBy(it: *TokenIterator, offset: isize) void {
        const new_pos = @bitCast(isize, it.pos) + offset;
        if (new_pos < 0) {
            it.pos = 0;
        } else {
            it.pos = @intCast(usize, new_pos);
        }
    }
};

const testing = std.testing;

fn testExpectedTokens(input: []const u8, expected: []const Token.Id) !void {
    var given = std.ArrayList(Token.Id).init(testing.allocator);
    defer given.deinit();

    var tokenizer = Tokenizer{ .source = input };
    while (true) {
        const tok = tokenizer.next();
        if (tok.id == .invalid) {
            std.debug.print("  {s} => '{s}'\n", .{ @tagName(tok.id), tok.get(input) });
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

test "Parser - output format" {
    const source =
        \\OUTPUT_FORMAT(elf64-x86-64)
    ;
    var tokenizer = Tokenizer{ .source = source };
    var tokens = std.ArrayList(Token).init(testing.allocator);
    defer tokens.deinit();
    while (true) {
        const tok = tokenizer.next();
        try testing.expect(tok.id != .invalid);
        try tokens.append(tok);
        if (tok.id == .eof) break;
    }
    var it = TokenIterator{ .tokens = tokens.items };
    var parser = Parser{ .source = source, .it = &it };
    const cpu_arch = try parser.outputFormat();
    try testing.expectEqual(cpu_arch, .x86_64);
}

const LdScript = @This();

const std = @import("std");
const assert = std.debug.assert;
const Elf = @import("../Elf.zig");
