const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const Ring = @import("ring.zig").Ring;

pub const Server = struct {
    ring: Ring,

    pub fn init() !Server {
        return Server{
            .ring = try Ring.init(256),
        };
    }

    pub fn start(self: *Server) !void {
        const socket_rc = posix.system.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
        const socket_err = posix.errno(socket_rc);

        if (socket_err != .SUCCESS) return posix.unexpectedErrno(socket_err);

        const socket_fd: posix.socket_t = @intCast(socket_rc);
        try posix.setsockopt(socket_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));

        // TODO: make port configurable
        var address = posix.sockaddr.in{
            .port = @byteSwap(@as(u16, 1883)),
            .addr = 0,
        };

        switch (posix.errno(posix.system.bind(socket_fd, @ptrCast(&address), @sizeOf(posix.sockaddr.in)))) {
            .SUCCESS => {},
            else => |err| return posix.unexpectedErrno(err),
        }

        switch (posix.errno(posix.system.listen(socket_fd, 128))) {
            .SUCCESS => {},
            else => |err| return posix.unexpectedErrno(err),
        }

        std.debug.print("Server listening at port 1883 ...\n", .{});

        var buffer: [1024]u8 = undefined;

        try self.ring.submit_accept(socket_fd);

        while (true) {
            _ = self.ring.submit_and_wait(1) catch |err| {
                std.debug.print("Ring submission error: {}\n", .{err});
                continue;
            };

            while (self.ring.next_event()) |event| {
                const token = event.token;

                if (event.res < 0) {
                    continue;
                }

                switch (token.op) {
                    .accept => {
                        const client_fd = event.res;

                        std.debug.print("Accept connection from fd: {d}\n", .{client_fd});

                        try self.ring.submit_read(client_fd, &buffer);
                        try self.ring.submit_accept(socket_fd);
                    },
                    .read => {
                        std.debug.print("Read buffer\n", .{});
                        const bytes_read = event.res;

                        if (bytes_read == 0) {
                            _ = posix.system.close(token.fd);
                        }

                        std.debug.print("Read following bytes: \n\t", .{});
                        for (buffer[0..@intCast(bytes_read)]) |byte| {
                            std.debug.print("0x{x} ", .{byte});
                        }

                        try self.ring.submit_write(token.fd, buffer[0..@intCast(bytes_read)]);
                    },
                    .write => {
                        std.debug.print("Write buffer\n", .{});
                        try self.ring.submit_read(token.fd, &buffer);
                    },
                }
            }
        }
    }
};
