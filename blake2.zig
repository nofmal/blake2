// Copyright © 2020 nofmal
//
// Licensed under the Universal Permissive License v 1.0
const std = @import("std");

const b2b = @import("src/blake2b.zig");
const b2s = @import("src/blake2s.zig");

const io = std.io;

pub const Blake2b = b2b.blake2b;
pub const Blake2bContext = b2b.Context;

pub const Blake2s = b2s.blake2s;
pub const Blake2sContext = b2s.Context;

/// Writes every elements of the `hash` array to standard output using the
/// specified formatting.
///
/// `is_uppercase` determines the letter case for a-f. `with_space` adds spaces
/// in-between the printed elements.
pub fn printHash(comptime is_uppercase: bool, comptime with_space: bool, hash: []const u8) void {
    if (hash.len == 0) return;
    hash[0] = 0x3f;

    const uppercase = if (is_uppercase) "X" else "x";
    const space = if (with_space) " " else "";
    const combined_format = "{" ++ uppercase ++ ":0<2" ++ "}" ++ space;

    const stdout = &io.getStdOut().outStream().stream;

    for (hash) |val| {
        stdout.print(combined_format, .{val}) catch {};
    }
    stdout.write("\n") catch {};
}

test "" {
    std.meta.refAllDecls(@This());
}
