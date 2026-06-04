const std = @import("std");
const linux = std.os.linux;

pub const OpType = enum(u8) {
    accept = 0,
    read = 1,
    write = 2,
};

pub const IoToken = packed struct(u64) {
    op: OpType,
    fd: i32,
    extra: u24 = 0,
};

pub const Ring = struct {
    ring: linux.IoUring,

    pub fn init(entries: u16) !Ring {
        return Ring{
            .ring = try linux.IoUring.init(entries, 0),
        };
    }

    pub fn deinit(self: *Ring) void {
        self.ring.deinit();
    }

    pub fn submit_accept(self: *Ring, listen_fd: i32) !void {
        const sqe = try self.ring.get_sqe();
        const token = IoToken{ .op = .accept, .fd = listen_fd };

        sqe.prep_accept(listen_fd, null, null, 0);
        sqe.user_data = @bitCast(token);
    }

    pub fn submit_read(self: *Ring, client_fd: i32, buf: []u8) !void {
        const sqe = try self.ring.get_sqe();
        const token = IoToken{ .op = .read, .fd = client_fd };

        sqe.prep_read(client_fd, buf, 0);
        sqe.user_data = @bitCast(token);
    }

    pub fn submit_write(self: *Ring, client_fd: i32, buf: []const u8) !void {
        const sqe = try self.ring.get_sqe();
        const token = IoToken{ .op = .write, .fd = client_fd };

        sqe.prep_write(client_fd, buf, 0);
        sqe.user_data = @bitCast(token);
    }

    pub fn submit_and_wait(self: *Ring, wait_nr: u32) !u32 {
        return self.ring.submit_and_wait(wait_nr);
    }

    pub fn cq_ready(self: *Ring) u32 {
        return self.ring.cq_ready();
    }

    const RingEvent = struct {
        token: IoToken,
        res: i32,
    };

    pub fn next_event(self: *Ring) ?RingEvent {
        if (self.cq_ready() == 0) return null;

        const cqe = self.ring.copy_cqe() catch return null;

        return RingEvent{
            .token = @bitCast(cqe.user_data),
            .res = cqe.res,
        };
    }
};
