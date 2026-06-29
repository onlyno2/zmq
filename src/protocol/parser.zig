const std = @import("std");

const packet_mod = @import("packet.zig");
const Packet = packet_mod.Packet;

const Parser = @This();

allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator) Parser {
    return Parser{
        .allocator = allocator,
    };
}

const ParserError = error{
    UnsupportedProtocolVersion,
    UnsupportedPacketType,
    InsufficientData,
    MalformedVariableByteInteger,
    OutOfMemory,
} || packet_mod.PacketError;

/// Parsing helper, used to track current parsing byte position
const Reader = struct {
    bytes: []const u8,
    offset: u64,

    pub fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes, .offset = 0 };
    }

    pub fn read_byte(self: *Reader) ParserError!u8 {
        if (self.offset >= self.bytes.len) return ParserError.MalformedPacket;

        const b = self.bytes[self.offset];
        self.offset += 1;

        return b;
    }

    pub fn read_u16(self: *Reader) ParserError!u16 {
        if (self.offset + 2 > self.bytes.len) return ParserError.MalformedPacket;

        const val = (@as(u16, self.bytes[self.offset]) << 8) | self.bytes[self.offset + 1];
        self.offset += 2;

        return val;
    }

    pub fn read_u32(self: *Reader) ParserError!u32 {
        if (self.offset + 4 > self.bytes.len) return ParserError.MalformedPacket;

        const val = (@as(u32, self.bytes[self.offset]) << 24) |
            (@as(u32, self.bytes[self.offset + 1]) << 16) |
            (@as(u32, self.bytes[self.offset + 2]) << 8) |
            self.bytes[self.offset + 3];
        self.offset += 4;

        return val;
    }

    pub fn read_var_int(self: *Reader) ParserError!u32 {
        var value: u32 = 0;
        var multiplier: u32 = 1;

        while (self.offset < self.bytes.len) {
            const byte = self.bytes[self.offset];
            value += @as(u32, byte & 0x7F) * multiplier;
            self.offset += 1;
            if ((byte & 0x80) == 0) {
                return value;
            }

            multiplier *= 128;
            if (multiplier > 128 * 128 * 128) {
                return ParserError.MalformedVariableByteInteger;
            }
        }

        return ParserError.InsufficientData;
    }

    pub fn read_slice(self: *Reader, len: u64) ![]const u8 {
        if (self.offset + len > self.bytes.len) return ParserError.MalformedPacket;

        const slice = self.bytes[self.offset .. self.offset + len];
        self.offset += len;

        return slice;
    }

    pub fn read_string(self: *Reader) ![]const u8 {
        const len = try self.read_u16();

        return self.read_slice(len);
    }
};

fn parse_fixed_header(reader: *Reader) ParserError!packet_mod.FixedHeader {
    if (reader.bytes.len < 2) return ParserError.InsufficientData;

    const first_byte = try reader.read_byte();
    var fixed_header = try packet_mod.FixedHeader.parse(first_byte);

    const remaining_length = try reader.read_var_int();
    fixed_header.remaining_length = remaining_length;

    return fixed_header;
}

pub fn parse(self: *Parser, bytes: []const u8) ParserError!Packet {
    var reader = Reader.init(bytes);

    const header = try parse_fixed_header(&reader);
    const total_packet_size = reader.offset + header.remaining_length;

    if (bytes.len < total_packet_size) {
        return ParserError.InsufficientData;
    }

    const packet = switch (header.packet_type) {
        .connect => Packet{ .connect = try self.parse_connect(&reader) },
        else => return ParserError.UnsupportedPacketType,
    };

    return packet;
}

fn parse_connect(self: *Parser, reader: *Reader) ParserError!packet_mod.ConnectPacket {
    _ = try reader.read_string();
    const protocol_version = try reader.read_byte();
    if (protocol_version != 5) return ParserError.UnsupportedProtocolVersion;

    const connection_flags = try reader.read_byte();

    if ((connection_flags & 0x01) != 0) return ParserError.MalformedPacket;

    const flags: packet_mod.ConnectPacket.Flags = @bitCast(connection_flags);
    if (flags.reserved != 0) return ParserError.ProtocolViolation;

    // Validate connection flags constraints:
    // 1. If username flag is 0, password flag MUST be 0
    if (flags.username_flag == 0 and flags.password_flag == 1) return ParserError.ProtocolViolation;
    // 2. If will flag is 0, will QoS and will retain MUST be 0
    if (flags.will_flag == 0 and (flags.will_qos != 0 or flags.will_retain != 0)) return ParserError.ProtocolViolation;

    const keep_alive = try reader.read_u16();

    // Parse properties
    var properties = packet_mod.ConnectPacket.Properties{};
    var user_props: std.ArrayList(packet_mod.KeyValue) = .empty;
    errdefer user_props.deinit(self.allocator);

    const properties_len = try reader.read_var_int();
    const properties_end = reader.offset + properties_len;
    if (properties_end > reader.bytes.len) return ParserError.MalformedPacket;

    while (reader.offset < properties_end) {
        const property_id_byte = try reader.read_byte();
        const property_id: packet_mod.PropertyId = @enumFromInt(property_id_byte);
        switch (property_id) {
            .session_expiry_interval => properties.session_expiry_interval = try reader.read_u32(),
            .receive_maximum => properties.receive_maximum = try reader.read_u16(),
            .maximum_packet_size => properties.maximum_packet_size = try reader.read_u32(),
            .topic_alias_maximum => properties.topic_alias_maximum = try reader.read_u16(),
            .request_response_information => properties.request_response_information = try reader.read_byte(),
            .request_problem_information => properties.request_problem_information = try reader.read_byte(),
            .authentication_method => properties.authentication_method = try reader.read_string(),
            .authentication_data => properties.authentication_data = try reader.read_string(),
            .user_property => {
                const key = try reader.read_string();
                const value = try reader.read_string();
                try user_props.append(self.allocator, .{
                    .name = key,
                    .value = value,
                });
            },
            else => return ParserError.ProtocolViolation,
        }
    }

    if (user_props.items.len > 0) {
        properties.user_properties = try user_props.toOwnedSlice(self.allocator);
    } else {
        user_props.deinit(self.allocator);
    }

    // Parse payload
    const client_id = try reader.read_string();

    var will_properties: ?packet_mod.ConnectPacket.WillProperties = null;
    var will_topic: ?[]const u8 = null;
    var will_message: ?[]const u8 = null;

    if (flags.will_flag == 1) {
        var will_props = packet_mod.ConnectPacket.WillProperties{};
        var will_user_properties: std.ArrayList(packet_mod.KeyValue) = .empty;
        errdefer will_user_properties.deinit(self.allocator);

        const will_property_len = try reader.read_var_int();
        const will_property_end = reader.offset + will_property_len;
        if (will_property_end > reader.bytes.len) return ParserError.MalformedPacket;

        while (reader.offset < will_property_end) {
            const property_id_byte = try reader.read_byte();
            const property_id: packet_mod.PropertyId = @enumFromInt(property_id_byte);
            switch (property_id) {
                .will_delay_interval => will_props.will_delay_interval = try reader.read_u32(),
                .payload_format_indicator => will_props.payload_format_indicator = try reader.read_byte(),
                .message_expiry_interval => will_props.message_expiry_interval = try reader.read_u32(),
                .content_type => will_props.content_type = try reader.read_string(),
                .response_topic => will_props.response_topic = try reader.read_string(),
                .correlation_data => will_props.correlation_data = try reader.read_string(),
                .user_property => {
                    const key = try reader.read_string();
                    const val = try reader.read_string();
                    try will_user_properties.append(self.allocator, .{ .name = key, .value = val });
                },
                else => return ParserError.ProtocolViolation,
            }
        }

        if (will_user_properties.items.len > 0) {
            will_props.user_properties = try will_user_properties.toOwnedSlice(self.allocator);
        } else {
            will_user_properties.deinit(self.allocator);
        }

        will_properties = will_props;
        will_topic = try reader.read_string();
        will_message = try reader.read_string();
    }

    const username: ?[]const u8 = if (flags.username_flag == 1) try reader.read_string() else null;
    const password: ?[]const u8 = if (flags.password_flag == 1) try reader.read_string() else null;

    if (reader.offset != reader.bytes.len) return ParserError.MalformedPacket;

    return packet_mod.ConnectPacket{
        .protocol_level = protocol_version,
        .flags = flags,
        .keep_alive = keep_alive,
        .properties = properties,
        .client_id = client_id,
        .username = username,
        .password = password,
        .will_properties = will_properties,
        .will_topic = will_topic,
        .will_message = will_message,
    };
}

test "parse_packet CONNECT basic" {
    const allocator = std.testing.allocator;

    // Connect packet layout:
    // Header byte: 0x10
    // Remaining length: 16 (0x10)
    // Protocol Name: length 4, "MQTT" (0x00, 0x04, 'M', 'Q', 'T', 'T')
    // Protocol Level: 5 (0x05)
    // Connect Flags: Clean Start = 1 (0x02)
    // Keep Alive: 60 (0x00, 0x3C)
    // Properties Length: 0 (0x00)
    // Client ID: length 3, "zmq" (0x00, 0x03, 'z', 'm', 'q')
    const connect_bytes = [_]u8{
        0x10, 16, // Fixed Header
        0x00, 0x04, 'M', 'Q', 'T', 'T', // Protocol Name
        0x05, // Protocol Level
        0x02, // Connect Flags
        0x00, 0x3C, // Keep Alive
        0x00, // Properties Length
        0x00, 0x03, 'z', 'm', 'q', // Client ID
    };

    var parser = init(allocator);
    const pkt = try parser.parse(&connect_bytes);

    try std.testing.expect(pkt == .connect);
    try std.testing.expectEqual(@as(u8, 5), pkt.connect.protocol_level);
    try std.testing.expectEqual(@as(u1, 1), pkt.connect.flags.clean_start);
    try std.testing.expectEqual(@as(u16, 60), pkt.connect.keep_alive);
    try std.testing.expectEqualStrings("zmq", pkt.connect.client_id);
    try std.testing.expect(pkt.connect.username == null);
}

test "parse_packet CONNECT full" {
    const allocator = std.testing.allocator;

    // Connect packet layout:
    // Header byte: 0x10
    // Remaining length: 137 (0x89, 0x01)
    // Protocol Name: length 4, "MQTT" (0x00, 0x04, 'M', 'Q', 'T', 'T')
    // Protocol Level: 5 (0x05)
    // Connect Flags:
    // - Clean Start = 1 (bit 1 -> 0x02)
    // - Will Flag = 1 (bit 2 -> 0x04)
    // - Will QoS = 1 (bits 3-4 -> 0x08)
    // - Will Retain = 1 (bit 5 -> 0x20)
    // - Password Flag = 1 (bit 6 -> 0x40)
    // - User Name Flag = 1 (bit 7 -> 0x80)
    // Total Flag Byte: 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80 = 0xEE
    // Keep Alive: 60 (0x00, 0x3C)
    //
    // CONNECT Properties: (Total length = 45 -> 0x2D)
    // - session_expiry_interval (0x11): 10 (0x00, 0x00, 0x00, 0x0A) -> 5 bytes
    // - receive_maximum (0x21): 100 (0x00, 0x64) -> 3 bytes
    // - maximum_packet_size (0x27): 1024 (0x00, 0x00, 0x04, 0x00) -> 5 bytes
    // - topic_alias_maximum (0x22): 10 (0x00, 0x0A) -> 3 bytes
    // - request_response_information (0x19): 1 (0x01) -> 2 bytes
    // - request_problem_information (0x17): 1 (0x01) -> 2 bytes
    // - authentication_method (0x15): "auth" (0x00, 0x04, 'a', 'u', 't', 'h') -> 7 bytes
    // - authentication_data (0x16): "data" (0x00, 0x04, 'd', 'a', 't', 'a') -> 7 bytes
    // - user_property (0x26): "key" -> "val" (0x00, 0x03, 'k', 'e', 'y', 0x00, 0x03, 'v', 'a', 'l') -> 11 bytes
    //
    // Payload:
    // - Client ID: "zmq" (0x00, 0x03, 'z', 'm', 'q') -> 5 bytes
    // - Will Properties: (Total length = 46 -> 0x2E)
    //   - will_delay_interval (0x18): 5 (0x00, 0x00, 0x00, 0x05) -> 5 bytes
    //   - payload_format_indicator (0x01): 1 (0x01) -> 2 bytes
    //   - message_expiry_interval (0x02): 60 (0x00, 0x00, 0x00, 0x3C) -> 5 bytes
    //   - content_type (0x03): "text" (0x00, 0x04, 't', 'e', 'x', 't') -> 7 bytes
    //   - response_topic (0x08): "resp" (0x00, 0x04, 'r', 'e', 's', 'p') -> 7 bytes
    //   - correlation_data (0x09): "corr" (0x00, 0x04, 'c', 'o', 'r', 'r') -> 7 bytes
    //   - user_property (0x26): "wkey" -> "wval" (0x00, 0x04, 'w', 'k', 'e', 'y', 0x00, 0x04, 'w', 'v', 'a', 'l') -> 13 bytes
    // - Will Topic: "status" (0x00, 0x06, 's', 't', 'a', 't', 'u', 's') -> 8 bytes
    // - Will Message: "offline" (0x00, 0x07, 'o', 'f', 'f', 'l', 'i', 'n', 'e') -> 9 bytes
    // - Username: "user" (0x00, 0x04, 'u', 's', 'e', 'r') -> 6 bytes
    // - Password: "pass" (0x00, 0x04, 'p', 'a', 's', 's') -> 6 bytes

    const connect_bytes = [_]u8{
        0x10, 0x89, 0x01, // Fixed Header (0x10, remaining length 137)
        0x00, 0x04, 'M', 'Q', 'T', 'T', // Protocol Name
        0x05, // Protocol Level
        0xEE, // Connect Flags
        0x00, 0x3C, // Keep Alive
        0x2D, // Properties Length (45)
        0x11, 0x00, 0x00, 0x00, 0x0A, // Session Expiry Interval (10)
        0x21, 0x00, 0x64, // Receive Maximum (100)
        0x27, 0x00, 0x00, 0x04, 0x00, // Maximum Packet Size (1024)
        0x22, 0x00, 0x0A, // Topic Alias Maximum (10)
        0x19, 0x01, // Request Response Information (1)
        0x17, 0x01, // Request Problem Information (1)
        0x15, 0x00, 0x04, 'a', 'u', 't', 'h', // Authentication Method
        0x16, 0x00, 0x04, 'd', 'a', 't', 'a', // Authentication Data
        0x26, 0x00, 0x03, 'k', 'e', 'y', 0x00, 0x03, 'v', 'a', 'l', // User Property ("key" -> "val")
        0x00, 0x03, 'z', 'm', 'q', // Client ID
        0x2E, // Will Properties Length (46)
        0x18, 0x00, 0x00, 0x00, 0x05, // Will Delay Interval (5)
        0x01, 0x01, // Payload Format Indicator (1)
        0x02, 0x00, 0x00, 0x00, 0x3C, // Message Expiry Interval (60)
        0x03, 0x00, 0x04, 't', 'e', 'x', 't', // Content Type
        0x08, 0x00, 0x04, 'r', 'e', 's', 'p', // Response Topic
        0x09, 0x00, 0x04, 'c', 'o', 'r', 'r', // Correlation Data
        0x26, 0x00, 0x04, 'w', 'k', 'e', 'y', 0x00, 0x04, 'w', 'v', 'a', 'l', // Will User Property ("wkey" -> "wval")
        0x00, 0x06, 's', 't', 'a', 't', 'u', 's', // Will Topic
        0x00, 0x07, 'o', 'f', 'f', 'l', 'i', 'n', 'e', // Will Message
        0x00, 0x04, 'u', 's', 'e', 'r', // Username
        0x00, 0x04, 'p', 'a', 's', 's', // Password
    };

    var parser = init(allocator);
    const pkt = try parser.parse(&connect_bytes);
    defer {
        if (pkt.connect.properties.user_properties) |up| {
            allocator.free(up);
        }
        if (pkt.connect.will_properties) |wp| {
            if (wp.user_properties) |wup| {
                allocator.free(wup);
            }
        }
    }

    try std.testing.expect(pkt == .connect);
    const conn = pkt.connect;
    try std.testing.expectEqual(@as(u8, 5), conn.protocol_level);
    try std.testing.expectEqual(@as(u1, 1), conn.flags.clean_start);
    try std.testing.expectEqual(@as(u1, 1), conn.flags.will_flag);
    try std.testing.expectEqual(@as(u2, 1), conn.flags.will_qos);
    try std.testing.expectEqual(@as(u1, 1), conn.flags.will_retain);
    try std.testing.expectEqual(@as(u1, 1), conn.flags.password_flag);
    try std.testing.expectEqual(@as(u1, 1), conn.flags.username_flag);
    try std.testing.expectEqual(@as(u16, 60), conn.keep_alive);

    // Properties
    try std.testing.expectEqual(@as(?u32, 10), conn.properties.session_expiry_interval);
    try std.testing.expectEqual(@as(?u16, 100), conn.properties.receive_maximum);
    try std.testing.expectEqual(@as(?u32, 1024), conn.properties.maximum_packet_size);
    try std.testing.expectEqual(@as(?u16, 10), conn.properties.topic_alias_maximum);
    try std.testing.expectEqual(@as(?u8, 1), conn.properties.request_response_information);
    try std.testing.expectEqual(@as(?u8, 1), conn.properties.request_problem_information);
    try std.testing.expectEqualStrings("auth", conn.properties.authentication_method.?);
    try std.testing.expectEqualStrings("data", conn.properties.authentication_data.?);

    const up = conn.properties.user_properties.?;
    try std.testing.expectEqual(@as(usize, 1), up.len);
    try std.testing.expectEqualStrings("key", up[0].name);
    try std.testing.expectEqualStrings("val", up[0].value);

    // Payload
    try std.testing.expectEqualStrings("zmq", conn.client_id);

    // Will Properties
    const wp = conn.will_properties.?;
    try std.testing.expectEqual(@as(?u32, 5), wp.will_delay_interval);
    try std.testing.expectEqual(@as(?u8, 1), wp.payload_format_indicator);
    try std.testing.expectEqual(@as(?u32, 60), wp.message_expiry_interval);
    try std.testing.expectEqualStrings("text", wp.content_type.?);
    try std.testing.expectEqualStrings("resp", wp.response_topic.?);
    try std.testing.expectEqualStrings("corr", wp.correlation_data.?);

    const wup = wp.user_properties.?;
    try std.testing.expectEqual(@as(usize, 1), wup.len);
    try std.testing.expectEqualStrings("wkey", wup[0].name);
    try std.testing.expectEqualStrings("wval", wup[0].value);

    try std.testing.expectEqualStrings("status", conn.will_topic.?);
    try std.testing.expectEqualStrings("offline", conn.will_message.?);
    try std.testing.expectEqualStrings("user", conn.username.?);
    try std.testing.expectEqualStrings("pass", conn.password.?);
}

test "parse_packet CONNECT errors" {
    const allocator = std.testing.allocator;

    // 1. Password flag set but username flag not set
    {
        const connect_bytes = [_]u8{
            0x10, 16, // Fixed Header
            0x00, 0x04, 'M', 'Q', 'T', 'T', // Protocol Name
            0x05, // Protocol Level
            0x40, // Connect Flags: Password=1, Username=0
            0x00, 0x3C, // Keep Alive
            0x00, // Properties Length
            0x00, 0x03, 'z', 'm', 'q', // Client ID
        };
        var parser = init(allocator);
        try std.testing.expectError(ParserError.ProtocolViolation, parser.parse(&connect_bytes));
    }

    // 2. Will QoS/Retain set but Will Flag not set
    {
        const connect_bytes = [_]u8{
            0x10, 16, // Fixed Header
            0x00, 0x04, 'M', 'Q', 'T', 'T', // Protocol Name
            0x05, // Protocol Level
            0x08, // Connect Flags: Will QoS=1, Will Flag=0
            0x00, 0x3C, // Keep Alive
            0x00, // Properties Length
            0x00, 0x03, 'z', 'm', 'q', // Client ID
        };
        var parser = init(allocator);
        try std.testing.expectError(ParserError.ProtocolViolation, parser.parse(&connect_bytes));
    }
}
