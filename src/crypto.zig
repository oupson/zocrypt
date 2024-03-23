const std = @import("std");

const InOutFile = @import("inout.zig");

const cipher = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub fn decrypt(key: [32]u8, input: [:0]const u8, output: [:0]const u8) anyerror!void {
    var cwd = std.fs.cwd();
    var input_file = try InOutFile.openOrCreate(&cwd, input, .input);
    defer _ = input_file.close();

    var output_file = try InOutFile.openOrCreate(&cwd, output, .output);
    defer _ = output_file.close();

    var input_reader = input_file.reader((cipher.nonce_length + 4096 + cipher.tag_length) * 5);
    var output_writer = output_file.writer(4096 * 5);

    var ad: [16 + 8]u8 = undefined;
    _ = try input_reader.read(ad[0..16]);

    var buffer: [cipher.nonce_length + 4096 + cipher.tag_length]u8 = undefined;

    var start = try std.time.Instant.now();
    var block_nbr: u64 = 0;
    while (true) {
        var size = try input_reader.read(&buffer);
        if (size == 0) {
            break;
        }

        var nonce: [cipher.nonce_length]u8 = buffer[0..cipher.nonce_length].*;
        var ciphertext = buffer[cipher.nonce_length .. size - cipher.tag_length];
        var tag: [cipher.tag_length]u8 = buffer[size - cipher.tag_length ..][0..cipher.tag_length].*;

        std.mem.writeIntLittle(u64, ad[16 .. 16 + 8], block_nbr);

        try cipher.decrypt(ciphertext, ciphertext, tag, &ad, nonce, key);

        _ = try output_writer.write(ciphertext);
        block_nbr += 1;
    }
    try output_writer.flush();

    var end = try std.time.Instant.now();
    var ellapsed = end.since(start);
    std.debug.print("ellapsed : {}\n", .{ellapsed});
}

pub fn encrypt(key: [32]u8, input: [:0]const u8, output: [:0]const u8) anyerror!void {
    var tag: [cipher.tag_length]u8 = undefined;
    var nonce: [cipher.nonce_length]u8 = undefined;

    var ad: [16 + 8]u8 = undefined;
    std.crypto.random.bytes(&ad);

    var cwd = std.fs.cwd();

    var input_file = try InOutFile.openOrCreate(&cwd, input, .input);
    defer _ = input_file.close();

    var output_file = try InOutFile.openOrCreate(&cwd, output, .output);
    defer _ = output_file.close();

    var input_reader = input_file.reader(4096 * 5);
    var output_writer = output_file.writer((cipher.nonce_length + 4096 + cipher.tag_length) * 5);

    _ = try output_writer.write(ad[0..16]);
    try output_writer.flush();

    var buffer: [4096]u8 = undefined;

    var start = try std.time.Instant.now();
    var block_nbr: u64 = 0;
    while (true) {
        var size = try input_reader.read(&buffer);
        if (size == 0) {
            break;
        }

        std.crypto.random.bytes(&nonce);
        var plaintext = buffer[0..size];

        std.mem.writeIntLittle(u64, ad[16 .. 16 + 8], block_nbr);

        cipher.encrypt(plaintext, &tag, plaintext, &ad, nonce, key);

        _ = try output_writer.write(&nonce);
        _ = try output_writer.write(plaintext);
        _ = try output_writer.write(&tag);
        block_nbr += 1;
    }
    try output_writer.flush();

    var end = try std.time.Instant.now();
    var ellapsed = end.since(start);
    std.debug.print("ellapsed : {}\n", .{ellapsed});
}
