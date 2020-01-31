BLAKE2.zig
==========

This is a BLAKE2 implementation written in `Zig`_.

Usage
-----

test.zig::

    const blake2 = @import("blake2");

    test "Simple API" {
        // Produce BLAKE2b-512 digest
        var buffer0: [64]u8 = undefined;
        try blake2.Blake2b("abc", &buffer0, null);

        // Produce BLAKE2s-256 digest
        var buffer1: [32]u8 = undefined;
        try blake2.Blake2s("abc", &buffer1, null);
    }

    test "Streaming API" {
        var buffer0: [64]u8 = undefined;
        var buffer1: [32]u8 = undefined;

        var blake2b_context = try blake2.Blake2bContext.init(buffer0.len, null);
        blake2b_context.update("abc");
        try blake2b_context.final(&buffer0);

        var blake2s_context = try blake2.Blake2sContext.init(buffer1.len, null);
        blake2s_context.update("abc");
        try blake2s_context.final(&buffer1);
    }

build.zig::

    const builtin = @import("builtin");
    const std = @import("std");

    pub fn build(b: *std.build.Builder) void {
        const run_test_step = b.step("test", "Run all tests in debug mode");
        {
            const tests = b.addTest("test.zig");
            tests.setBuildMode(builtin.Mode.Debug);

            // Assuming this library's folder is placed on the root directory...
            tests.addPackagePath("blake2", "blake2/blake2.zig");

            run_test_step.dependOn(&tests.step);
        }

        b.default_step.dependOn(run_test_step);
    }

.. _`Zig`: https://ziglang.org
