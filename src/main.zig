const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Io = std.Io;

const Server = @import("./transport/server.zig").Server;

const zmq = @import("zmq");

pub fn main() !void {
    var server = try Server.init();

    try server.start();
}
