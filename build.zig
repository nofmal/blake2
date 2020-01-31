// Copyright © 2020 nofmal
//
// Licensed under the Universal Permissive License v 1.0
const builtin = @import("builtin");
const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const run_all_tests_step = b.step("test", "Run all tests in debug mode");
    {
        const tests = b.addTest("blake2.zig");
        tests.setBuildMode(builtin.Mode.Debug);

        run_all_tests_step.dependOn(&tests.step);
    }

    readme: {
        const pager = switch (builtin.os) {
            .linux => "less",
            .windows => "more",
            else => break :readme,
        };

        const readme_file = "README.rst";
        const license_file = "LICENSE";

        const readme_step = b.step("readme", "Read the " ++ readme_file ++ " file");
        const license_step = b.step("license", "Read the " ++ license_file ++ " file");

        const pager_readme = b.addSystemCommand(&[_][]const u8{pager, readme_file});
        const pager_license = b.addSystemCommand(&[_][]const u8{pager, license_file});

        readme_step.dependOn(&pager_readme.step);
        license_step.dependOn(&pager_license.step);
    }

    b.default_step.dependOn(run_all_tests_step);
}
