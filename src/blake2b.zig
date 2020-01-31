// Copyright © 2020 nofmal
//
// Licensed under the Universal Permissive License v 1.0

/// Package blake2b implements the BLAKE2b hash algorithm defined by RFC 7693.
///
/// BLAKE2b is able to produce hash values up to 64 bytes. If you aren't sure
/// which function you need, use the `blake2b` function. If you wish to gain
/// more control of how the algorithm works, use the `Context.init`,
/// `Context.update`, and `Context.final` functions.
const std = @import("std");

const math = std.math;
const mem = std.mem;
const testing = std.testing;

const sigma = [_][]const u8{
    &[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    &[_]u8{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    &[_]u8{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    &[_]u8{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    &[_]u8{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    &[_]u8{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    &[_]u8{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    &[_]u8{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    &[_]u8{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    &[_]u8{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

const IV = [_]u64{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

const IV_type = @TypeOf(IV);
const IV_mem_type = @TypeOf(IV[0]);
const word = 64;
const round = 12;
const block = 128;
const bit_size = u128;
const R0 = 32;
const R1 = 24;
const R2 = 16;
const R3 = 63;

const max_hash_length = 64;
const max_key_size = max_hash_length;

/// Produces a hash value from `input` and writes it to `output`.
///
/// `input` may be an empty data. If an optional `key` is supplied, it must
/// be no larger than 64 bytes. `output` must be between 1 and 64 bytes
/// long, as its size determines the resulting hash length. For instances, if
/// the `output` size is 64 bytes, it returns a BLAKE2b-512 hash.
pub fn blake2b(input: []const u8, output: []u8, key: ?[]const u8) !void {
    var blake2b_context = try Context.init(output.len, key);
    blake2b_context.update(input);
    blake2b_context.final(output) catch unreachable;
}

test "blake2b" {
    var buf0: [64]u8 = undefined;
    var buf1: [48]u8 = undefined;
    var buf2: [32]u8 = undefined;

    const text = "hash slinging slasher";

    // BLAKE2b-512("hash slinging slasher")

    blake2b(text, &buf0, null) catch unreachable;
    testing.expectEqualSlices(@TypeOf(buf0[0]), &buf0, &[_]u8{
        0x37, 0x98, 0x1d, 0xb4, 0xc7, 0x5a, 0xf4, 0x0f,
        0x56, 0xdb, 0xa6, 0x44, 0x40, 0x3e, 0x22, 0x3e,
        0x31, 0xfe, 0x8e, 0xba, 0x2e, 0x92, 0xc2, 0x1a,
        0xc0, 0x64, 0x80, 0x82, 0x0d, 0x22, 0x50, 0xe9,
        0x22, 0xa1, 0x37, 0x6c, 0x40, 0x56, 0x01, 0x72,
        0xb8, 0x46, 0xef, 0xc6, 0xfd, 0x17, 0xb4, 0x4a,
        0xd4, 0x28, 0x91, 0x3b, 0xa5, 0x82, 0x47, 0x29,
        0x9d, 0xc7, 0xc4, 0x6d, 0x3a, 0x14, 0x3b, 0x0c,
    });

    // BLAKE2b-384("hash slinging slasher")

    blake2b(text, &buf1, null) catch unreachable;
    testing.expectEqualSlices(@TypeOf(buf1[0]), &buf1, &[_]u8{
        0xcc, 0x3e, 0x36, 0x90, 0xb2, 0x27, 0x1f, 0x19,
        0xa9, 0xdf, 0x99, 0xca, 0xa1, 0x15, 0x29, 0x4f,
        0x7c, 0x0d, 0xd6, 0xa9, 0x96, 0x0a, 0x53, 0xb4,
        0x8f, 0x06, 0x70, 0xc8, 0x80, 0x4b, 0x7d, 0xa2,
        0xd2, 0x2a, 0xb9, 0xb3, 0x7a, 0x7e, 0xd3, 0x0f,
        0x01, 0xfa, 0xe0, 0xe4, 0xb4, 0xff, 0x02, 0x8c,
    });

    // BLAKE2b-256("hash slinging slasher")

    blake2b(text, &buf2, null) catch unreachable;
    testing.expectEqualSlices(@TypeOf(buf2[0]), &buf2, &[_]u8{
        0xa0, 0xbd, 0x94, 0x69, 0x32, 0xdd, 0xd9, 0x3c,
        0xd1, 0x57, 0x80, 0xa3, 0x86, 0xa8, 0xfd, 0x2e,
        0x1c, 0x65, 0x50, 0xd3, 0x65, 0x97, 0x9b, 0xa0,
        0x4f, 0xf8, 0xdd, 0x42, 0x95, 0x81, 0xb3, 0xcf,
    });
}

pub const Context = struct {
    h: IV_type = IV,
    chunk: [block]u8 = [_]u8{0} ** block,
    counter: usize = 0,
    bytes_compressed: bit_size = 0,
    hash_length: usize,

    pub fn init(output_length: usize, key: ?[]const u8) !@This() {
        var context = @This() {
            .hash_length = output_length,
        };

        errdefer mem.secureZero(@TypeOf(context.h[0]), &context.h);

        if (context.hash_length == 0) return error.LengthIsZero;
        if (context.hash_length > max_hash_length) return error.LengthOverflow;

        const key_length = if (key) |_| key.?.len else 0;
        if (key_length > max_key_size) return error.KeyOverflow;

        context.h[0] ^= @intCast(IV_mem_type, 0x01010000 ^ @shlExact(key_length, 8) ^ context.hash_length);

        if (key_length > 0) {
            var pad_the_key_with_zeroes = [_]u8{0} ** block;

            mem.copy(u8, &pad_the_key_with_zeroes, key.?[0..]);

            context.update(&pad_the_key_with_zeroes);
            context.counter = block;
        }

        return context;
    }

    pub fn update(self: *@This(), input: []const u8) void {
        const bytes_remaining = input.len;

        var i: usize = 0;
        while (i < bytes_remaining) : (i += 1) {
            if (self.counter == block) {
                self.bytes_compressed += block;
                self.compress(false);
                self.counter = 0;
            }
            self.chunk[self.counter] = input[i];
            self.counter += 1;
        }
    }

    pub fn final(self: *@This(), output: []u8) !void {
        defer mem.secureZero(@TypeOf(self.h[0]), &self.h);

        if (output.len != self.hash_length) return error.WrongSize;

        self.bytes_compressed += self.counter;
        mem.set(u8, self.chunk[self.counter..], 0);

        self.compress(true);

        var result = [_]u8{0} ** word;

        for (self.h) |val, i| {
            const x: usize = i * (word / 8);
            const y: usize = (i + 1) * (word / 8);

            mem.writeIntSliceLittle(IV_mem_type, result[x..y], val);
        }

        mem.secureZero(u8, output);
        mem.copy(u8, output, result[0..output.len]);
    }

    fn compress(self: *@This(), is_last_block: bool) void {
        var i: usize = 0;

        var v: [16]IV_mem_type = undefined;

        while (i < (v.len / 2)) : (i += 1) {
            v[i] = self.h[i];
            v[i + (v.len / 2)] = IV[i];
        }
        i = 0;

        {
            var c: [@sizeOf(@TypeOf(self.bytes_compressed))]u8 = undefined;
            mem.writeIntLittle(@TypeOf(self.bytes_compressed), &c, self.bytes_compressed);

            const d = c[0..c.len / 2];
            const e = c[c.len / 2..c.len];

            const f = mem.readIntSliceLittle(IV_mem_type, d[0..]);
            const g = mem.readIntSliceLittle(IV_mem_type, e[0..]);

            v[12] = v[12] ^ f;
            v[13] = v[13] ^ g;
        }

        if (is_last_block) v[14] = ~v[14];

        var m: [16]IV_mem_type = undefined;
        for (m) |*val, index| {
            val.* = divideChunk(self.chunk, index);
        }

        while (i < round) : (i += 1) {
            var s = sigma[i % 10];

            mix(&v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
            mix(&v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
            mix(&v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
            mix(&v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);

            mix(&v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
            mix(&v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            mix(&v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
            mix(&v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
        }
        i = 0;

        while (i < self.h.len) : (i += 1) {
            self.h[i] ^= v[i] ^ v[i + self.h.len];
        }
    }
};

inline fn divideChunk(chunk: [block]u8, count: usize) IV_mem_type {
    const f = block / 16;
    var g: [f]u8 = undefined;

    var i: usize = 0;
    while (i < f) : (i += 1) {
        g[i] = chunk[(f * count) + i];
    }

    return mem.readIntSliceLittle(IV_mem_type, &g);
}

inline fn mix(
    v: *[16]IV_mem_type,
    comptime a: usize,
    comptime b: usize,
    comptime c: usize,
    comptime d: usize,
    x: IV_mem_type,
    y: IV_mem_type) void {
    v[a] +%= v[b] +% x;
    v[d] = math.rotr(IV_mem_type, (v[d] ^ v[a]), @as(usize, R0));

    v[c] +%= v[d];
    v[b] = math.rotr(IV_mem_type, (v[b] ^ v[c]), @as(usize, R1));

    v[a] +%= v[b] +% y;
    v[d] = math.rotr(IV_mem_type, (v[d] ^ v[a]), @as(usize, R2));

    v[c] +%= v[d];
    v[b] = math.rotr(IV_mem_type, (v[b] ^ v[c]), @as(usize, R3));
}
