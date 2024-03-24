const std = @import("std");

const crypto = @import("crypto.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.skip();

    const commandStr = args.next();
    if (commandStr == null) {
        std.debug.print("USAGE : zocrypt [command]\n\tWhere command is decrypt or encrypt\n", .{});
        return;
    }

    var command: enum { unknown, encrypt, decrypt } = .unknown;
    if (std.mem.eql(u8, commandStr.?, "encrypt")) {
        command = .encrypt;
    } else if (std.mem.eql(u8, commandStr.?, "decrypt")) {
        command = .decrypt;
    }

    if (command == .unknown) {
        std.debug.print("USAGE : zocrypt [command]\n\tWhere command is decrypt or encrypt\n", .{});
        return;
    }

    var input = args.next();
    var output = args.next();

    if ((input == null) or (output == null)) {
        std.debug.print("USAGE : zocrypt [command]\n\tWhere command is decrypt or encrypt\n", .{});
        return;
    }

    const password = try getPassword(allocator);
    defer allocator.free(password);

    var key: [32]u8 = undefined;

    // 14 is log2(16384)
    try std.crypto.pwhash.scrypt.kdf(allocator, &key, password, &[_]u8{}, .{ .ln = 14, .r = 8, .p = 1 });

    var file_key: [32]u8 = undefined;
    std.crypto.kdf.hkdf.HkdfSha256.expand(&file_key, "Key used for file encryption", key);

    std.crypto.utils.secureZero(u8, key);

    if (command == .decrypt) {
        try crypto.decrypt(file_key, input.?, output.?);
    } else {
        try crypto.encrypt(file_key, input.?, output.?);
    }

    std.crypto.utils.secureZero(u8, file_key);
}

fn getPassword(allocator: std.mem.Allocator) anyerror![]const u8 {
    const have_password_var = try std.process.hasEnvVar(allocator, "PASSWORD");

    if (have_password_var) {
        return try std.process.getEnvVarOwned(allocator, "PASSWORD");
    } else {
        const termios = std.os.tcgetattr(std.os.STDOUT_FILENO) catch {
            return error.TcGetAttrFailed;
        };

        var t = termios;
        t.lflag &= ~(std.os.system.ECHO);
        t.lflag |= std.os.system.ECHONL;

        std.os.tcsetattr(std.os.STDOUT_FILENO, std.os.system.TCSA.NOW, t) catch {
            return error.TcSetAttrFailed;
        };

        try std.io.getStdOut().writeAll("password : ");

        var stdin = std.io.getStdIn();

        var password_array_list = std.ArrayList(u8).init(allocator);
        try stdin.reader().streamUntilDelimiter(password_array_list.writer(), '\n', null);

        std.os.tcsetattr(std.os.STDOUT_FILENO, std.os.system.TCSA.NOW, termios) catch {
            return error.TcSetAttrFailed;
        };

        return password_array_list.toOwnedSlice();
    }
}
