const std = @import("std");

pub const KeyValue = struct {
    name: []const u8,
    value: []const u8,
};

pub const PacketError = error{
    MalformedPacket,
    ProtocolViolation,
};

pub const PacketType = enum(u4) {
    reserved = 0, // MQTT protocol reserved. Cannot be used
    connect = 1, // Client request to connect
    connack = 2, // Conneck acknowledgment
    publish = 3, // Publish message
    puback = 4, // Publish acknowledgment (QoS1)
    pubrec = 5, // Publish received (QoS2)
    pubrel = 6, // Publish release (QoS2)
    pubcomp = 7, // Publish complete (QoS2)
    subscribe = 8, // Client subscribe request
    suback = 9, // Subscribe acknowledgment
    unsubscribe = 10, // Client unsubscribe request
    unsuback = 11, // Unsubscribe acknowledgment
    pingreq = 12, // PING request
    pingresp = 13, // PING response
    disconnect = 14, // Client is disconnecting
    auth = 15, // Authentication (MQTT v5 only)

    pub fn from_byte(byte: u8) PacketType {
        const type_val: u4 = @intCast((byte >> 4) & 0x0F);

        return @enumFromInt(type_val);
    }
};

// https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc464547805
pub const PropertyId = enum(u8) {
    payload_format_indicator = 0x01,
    message_expiry_interval = 0x02,
    content_type = 0x03,
    response_topic = 0x08,
    correlation_data = 0x09,
    subscription_identifier = 0x0B,
    session_expiry_interval = 0x11,
    assigned_client_identifier = 0x12,
    server_keep_alive = 0x13,
    authentication_method = 0x15,
    authentication_data = 0x16,
    request_problem_information = 0x17,
    will_delay_interval = 0x18,
    request_response_information = 0x19,
    response_information = 0x1A,
    server_reference = 0x1C,
    reason_string = 0x1F,
    receive_maximum = 0x21,
    topic_alias_maximum = 0x22,
    topic_alias = 0x23,
    maximum_qos = 0x24,
    retain_available = 0x25,
    user_property = 0x26,
    maximum_packet_size = 0x27,
    wildcard_subscription_available = 0x28,
    subscription_identifiers_available = 0x29,
    shared_subscription_available = 0x2A,
};

// Bit 7   6   5   4   3   2   1   0
//    ├─ Packet Type   ─┤ ├─ Flags ─┤
pub const FixedHeader = packed struct {
    packet_type: PacketType,
    flags: u4,

    pub fn parse(byte: u8) PacketError!FixedHeader {
        const packet_type = PacketType.from_byte(byte);
        const flags: u4 = @intCast(byte & 0x0F);

        switch (packet_type) {
            .reserved => return PacketError.ProtocolViolation,

            .pubrel, .subscribe, .unsubscribe => {
                if (flags != 2) return PacketError.ProtocolViolation;
            },

            .publish => {
                // bits: DUP (bit 3), QoS (bit 2-1), RETAIN (bit 0)
                const qos: u2 = @intCast((flags >> 1) & 0x3);
                if (qos == 3) return PacketError.ProtocolViolation;
            },

            else => {
                if (flags != 0) return PacketError.ProtocolViolation;
            },
        }

        return FixedHeader{ .packet_type = packet_type, .flags = flags };
    }
};

pub const ConnectPacket = struct {
    protocol_level: u8, // MUST be 5 for MQTT v5
    flags: Flags,
    keep_alive: u16,

    properties: Properties,

    client_id: []const u8,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,

    will_properties: ?WillProperties = null,
    will_topic: ?[]const u8 = null,
    will_message: ?[]const u8 = null,

    pub const Flags = packed struct(u8) {
        reserved: u1 = 0,
        clean_start: u1,
        will_flag: u1,
        will_qos: u2,
        will_retain: u1,
        password_flag: u1,
        username_flag: u1,
    };

    pub const Properties = struct {
        session_expiry_interval: ?u32 = null,
        receive_maximum: ?u16 = null,
        maximum_packet_size: ?u32 = null,
        topic_alias_maximum: ?u16 = null,
        request_response_information: ?u8 = null, // value MUST be 0 or 1
        request_problem_information: ?u8 = null, // value MUST be 0 or 1
        user_properties: ?[]const KeyValue = null,
        authentication_method: ?[]const u8 = null,
        authentication_data: ?[]const u8 = null,
    };

    pub const WillProperties = struct {
        will_delay_interval: ?u32 = null,
        payload_format_indicator: ?u8 = null, // value MUST be 0 or 1
        message_expiry_interval: ?u32 = null,
        content_type: ?[]const u8 = null,
        response_topic: ?[]const u8 = null,
        correlation_data: ?[]const u8 = null,
        user_properties: ?[]const KeyValue = null, // multiple allowed
    };
};

pub const ConnackPacket = struct {
    session_present: bool,
    reason_code: ReasonCode,
    properties: Properties,

    pub const ReasonCode = enum(u8) {
        success = 0x00,
        unspecified_error = 0x80,
        malformed_packet = 0x81,
        protocol_error = 0x82,
        implementation_specific_error = 0x83,
        unsupported_protocol_version = 0x84,
        client_identifier_not_valid = 0x85,
        bad_user_name_or_password = 0x86,
        not_authorized = 0x87,
        server_unavailable = 0x88,
        server_busy = 0x89,
        banned = 0x8A,
        bad_authentication_method = 0x8C,
        topic_name_invalid = 0x90,
        packet_too_large = 0x95,
        quota_exceeded = 0x97,
        payload_format_invalid = 0x99,
        retain_not_supported = 0x9A,
        qos_not_supported = 0x9B,
        use_another_server = 0x9C,
        server_moved = 0x9D,
        connection_rate_exceeded = 0x9F,
    };

    pub const Properties = struct {
        session_expiry_interval: ?u32 = null,
        receive_maximum: ?u16 = null,
        maximum_qos: ?u8 = null, // value MUST be 0 or 1
        retain_available: ?u8 = null, // value MUST be 0 or 1
        maximum_packet_size: ?u32 = null,
        assigned_client_identifier: ?[]const u8 = null,
        topic_alias_maximum: ?u16 = null,
        reason_string: ?[]const u8 = null,
        user_properties: ?[]const KeyValue = null,
        wildcard_subscription_available: ?u8 = null, // value MUST be 0 or 1
        subscription_identifiers_available: ?u8 = null, // value MUST be 0 or 1
        shared_subscription_available: ?u8 = null, // value MUST be 0 or 1
        server_keep_alive: ?u16 = null,
        response_information: ?[]const u8 = null,
        server_reference: ?[]const u8 = null,
        authentication_method: ?[]const u8 = null,
        authentication_data: ?[]const u8 = null,
    };
};

pub const QoS = enum(u2) {
    at_most_once = 0x0,
    at_least_once = 0x1,
    exactly_once = 0x2,
};

pub const PublishPacket = struct {
    dup: bool,
    qos: QoS,
    retain: bool,
    topic: []const u8,
    packet_id: ?u16, // only when QoS > 0
    properties: Properties,
    payload: []const u8,

    pub const Properties = struct {
        payload_format_indicator: ?u8 = null,
        message_expiry_interval: ?u32 = null,
        topic_alias: ?u16 = null,
        response_topic: ?[]const u8 = null,
        correlation_data: ?[]const u8 = null,
        user_properties: ?[]const KeyValue = null,
        subscription_identifiers: ?[]const u32 = null,
        content_type: ?[]const u8 = null,
    };
};

pub const AckProperties = struct {
    reason_string: ?[]const u8 = null,
    user_properties: ?[]const KeyValue = null,
};

pub const PubackPacket = struct {
    packet_id: u16,
    reason_code: ReasonCode = .success,
    properties: AckProperties = .{},

    pub const ReasonCode = enum(u8) {
        success = 0x00,
        no_matching_subscribers = 0x10,
        unspecified_error = 0x80,
        implementation_specific_error = 0x83,
        not_authorized = 0x87,
        topic_name_invalid = 0x90,
        packet_identifier_in_use = 0x91,
        quota_exceeded = 0x97,
        payload_format_invalid = 0x99,
    };
};

pub const PubrecPacket = struct {
    packet_id: u16,
    reason_code: ReasonCode = .success,
    properties: AckProperties = .{},

    pub const ReasonCode = enum(u8) {
        success = 0x00,
        no_matching_subscribers = 0x10,
        unspecified_error = 0x80,
        implementation_specific_error = 0x83,
        not_authorized = 0x87,
        topic_name_invalid = 0x90,
        packet_identifier_in_use = 0x91,
        quota_exceeded = 0x97,
        payload_format_invalid = 0x99,
    };
};

pub const PubrelPacket = struct {
    packet_id: u16,
    reason_code: ReasonCode = .success,
    properties: AckProperties = .{},

    pub const ReasonCode = enum(u8) {
        success = 0x00,
        packet_identifier_not_found = 0x92,
    };
};

pub const PubcompPacket = struct {
    packet_id: u16,
    reason_code: ReasonCode = .success,
    properties: AckProperties = .{},

    pub const ReasonCode = enum(u8) {
        success = 0x00,
        packet_identifier_not_found = 0x92,
    };
};

pub const SubscribePacket = struct {
    packet_id: u16,
    properties: Properties,
    subscriptions: []const Subscription,

    pub const Properties = struct {
        subscription_identifier: ?u32 = null,
        user_properties: ?[]const KeyValue = null,
    };

    pub const Subscription = struct {
        topic_filter: []const u8,
        options: Options,

        pub const Options = packed struct(u8) {
            qos: QoS,
            no_local: u1,
            retain_as_published: u1,
            retain_handling: RetainHandling,
            reserved: u2 = 0,
        };
    };

    pub const RetainHandling = enum(u2) {
        send_on_subscribe = 0,
        send_if_new_subscription = 1,
        do_not_send = 2,
    };
};

pub const SubackPacket = struct {
    packet_id: u16,
    properties: Properties,
    reason_codes: []const ReasonCode,

    pub const ReasonCode = enum(u8) {
        granted_qos_0 = 0x00,
        granted_qos_1 = 0x01,
        granted_qos_2 = 0x02,
        unspecified_error = 0x80,
        implementation_specific_error = 0x83,
        not_authorized = 0x87,
        topic_filter_invalid = 0x8F,
        packet_identifier_in_use = 0x91,
        quota_exceeded = 0x97,
        shared_subscriptions_not_supported = 0xA1,
        subscription_identifiers_not_supported = 0xA2,
        wildcard_subscriptions_not_supported = 0xA3,
    };

    pub const Properties = struct {
        reason_string: ?[]const u8 = null,
        user_properties: ?[]const KeyValue = null,
    };
};

pub const UnsubscribePacket = struct {
    packet_id: u16,
    properties: Properties,
    topic_filters: []const []const u8, // MUST contain at least 1

    pub const Properties = struct {
        user_properties: ?[]const KeyValue = null,
    };
};

pub const UnsubackPacket = struct {
    packet_id: u16,
    properties: Properties,
    reason_codes: []const ReasonCode,

    pub const ReasonCode = enum(u8) {
        success = 0x00,
        no_subscription_existed = 0x11,
        unspecified_error = 0x80,
        implementation_specific_error = 0x83,
        not_authorized = 0x87,
        topic_filter_invalid = 0x8F,
        packet_identifier_in_use = 0x91,
    };

    pub const Properties = struct {
        reason_string: ?[]const u8 = null,
        user_properties: ?[]const KeyValue = null,
    };
};

pub const DisconnectPacket = struct {
    reason_code: ReasonCode = .normal_disconnection,
    properties: Properties = .{},

    pub const ReasonCode = enum(u8) {
        normal_disconnection = 0x00,
        disconnect_with_will_message = 0x04,
        unspecified_error = 0x80,
        malformed_packet = 0x81,
        protocol_error = 0x82,
        implementation_specific_error = 0x83,
        not_authorized = 0x87,
        server_busy = 0x89,
        server_shutting_down = 0x8B,
        keep_alive_timeout = 0x8D,
        session_taken_over = 0x8E,
        topic_filter_invalid = 0x8F,
        topic_name_invalid = 0x90,
        receive_maximum_exceeded = 0x93,
        topic_alias_invalid = 0x94,
        packet_too_large = 0x95,
        message_rate_too_high = 0x96,
        quota_exceeded = 0x97,
        administrative_action = 0x98,
        payload_format_invalid = 0x99,
        retain_not_supported = 0x9A,
        qos_not_supported = 0x9B,
        use_another_server = 0x9C,
        server_moved = 0x9D,
        shared_subscriptions_not_supported = 0x9E,
        connection_rate_exceeded = 0x9F,
        maximum_connect_time = 0xA0,
        subscription_identifiers_not_supported = 0xA1,
        wildcard_subscriptions_not_supported = 0xA2,
    };

    pub const Properties = struct {
        session_expiry_interval: ?u32 = null,
        reason_string: ?[]const u8 = null,
        user_properties: ?[]const KeyValue = null,
        server_reference: ?[]const u8 = null,
    };
};

pub const AuthPacket = struct {
    reason_code: ReasonCode = .success,
    properties: Properties = .{},

    pub const ReasonCode = enum(u8) {
        success = 0x00,
        continue_authentication = 0x18,
        re_authenticate = 0x19,
    };

    pub const Properties = struct {
        authentication_method: ?[]const u8 = null,
        authentication_data: ?[]const u8 = null,
        reason_string: ?[]const u8 = null,
        user_properties: ?[]const KeyValue = null,
    };
};

pub const Packet = union(PacketType) {
    reserved: void,
    connect: ConnectPacket,
    connack: ConnackPacket,
    publish: PublishPacket,
    puback: PubackPacket,
    pubrec: PubrecPacket,
    pubrel: PubrelPacket,
    pubcomp: PubcompPacket,
    subscribe: SubscribePacket,
    suback: SubackPacket,
    unsubscribe: UnsubscribePacket,
    unsuback: UnsubackPacket,
    pingreq: void,
    pingresp: void,
    disconnect: DisconnectPacket,
    auth: AuthPacket,
};

test "FixedHeader.parse connect packet" {
    const header = try FixedHeader.parse(0x10); // connect packet type (1) with flags (0)
    try std.testing.expectEqual(PacketType.connect, header.packet_type);
    try std.testing.expectEqual(@as(u4, 0), header.flags);
}

test "FixedHeader.parse protocol violations" {
    // 1. Reserved packet type (0) must fail
    try std.testing.expectError(PacketError.ProtocolViolation, FixedHeader.parse(0x00));
    try std.testing.expectError(PacketError.ProtocolViolation, FixedHeader.parse(0x05));

    // 2. Pubrel (6), Subscribe (8), Unsubscribe (10) must have flags == 2
    // Pubrel with invalid flags (e.g. 0, 1, 3)
    try std.testing.expectError(PacketError.ProtocolViolation, FixedHeader.parse((6 << 4) | 0));
    try std.testing.expectError(PacketError.ProtocolViolation, FixedHeader.parse((6 << 4) | 1));
    try std.testing.expectError(PacketError.ProtocolViolation, FixedHeader.parse((6 << 4) | 3));
    // Subscribe with invalid flags
    try std.testing.expectError(PacketError.ProtocolViolation, FixedHeader.parse((8 << 4) | 0));
    // Unsubscribe with invalid flags
    try std.testing.expectError(PacketError.ProtocolViolation, FixedHeader.parse((10 << 4) | 0));

    // 3. Publish (3) cannot have QoS == 3 (QoS is bits 2-1)
    // QoS = 3 corresponds to flags like 0b0110 (6) or 0b0111 (7)
    try std.testing.expectError(PacketError.ProtocolViolation, FixedHeader.parse((3 << 4) | 6));
    try std.testing.expectError(PacketError.ProtocolViolation, FixedHeader.parse((3 << 4) | 7));

    // 4. Other packet types must have flags == 0
    // Connect (1) with flags != 0
    try std.testing.expectError(PacketError.ProtocolViolation, FixedHeader.parse((1 << 4) | 1));
    // Disconnect (14) with flags != 0
    try std.testing.expectError(PacketError.ProtocolViolation, FixedHeader.parse((14 << 4) | 15));
}
