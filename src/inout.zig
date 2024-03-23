const std = @import("std");

const Self = @This();

const Direction = enum { input, output };

handle: ?std.fs.File,

pub fn openOrCreate(cwd: *std.fs.Dir, name: []const u8, direction: Direction) std.fs.File.OpenError!Self {
    if (std.mem.eql(u8, name, "-")) {
        return Self{
            .handle = null,
        };
    } else {
        var file = try if (direction == .input) cwd.openFile(name, .{ .mode = .read_only }) else cwd.createFile(name, .{});
        return Self{
            .handle = file,
        };
    }
}

pub fn reader(self: *Self, comptime buf_size: usize) std.io.BufferedReader(buf_size, std.fs.File.Reader) {
    var handle = if (self.handle) |handle| handle else std.io.getStdIn();
    return std.io.bufferedReaderSize(buf_size, handle.reader());
}

pub fn writer(self: *Self, comptime buf_size: usize) std.io.BufferedWriter(buf_size, std.fs.File.Writer) {
    var handle = if (self.handle) |handle| handle else std.io.getStdOut();

    var handle_writer = handle.writer();
    return std.io.BufferedWriter(buf_size, @TypeOf(handle_writer)){ .unbuffered_writer = handle_writer };
}

pub fn close(self: *Self) void {
    if (self.handle) |handle| {
        handle.close();
        self.handle = null;
    }
}
