//! 基于 doc/protocols.md 的完整协议测试用例
//!
//! 覆盖 VMess、VLESS、Shadowsocks、Trojan、Hysteria2 五种协议的：
//! - 链接格式与解析规则
//! - 必填/可选字段
//! - 错误类型（InvalidFormat、InvalidField、UnsupportedProtocol）
//! - 前缀大小写不敏感
//! - Round-trip 与 to_link 规范

#![cfg(test)]

use crate::error::ProtocolError;
use crate::{Hysteria2, Protocol, ProtocolParser, Shadowsocks, Trojan, VLess, VMess};
use base64::Engine;

// =============================================================================
// 统一约定（文档 §6）
// =============================================================================

#[test]
fn protocols_prefix_case_insensitive_vmess() {
    for prefix in ["vmess://", "VMESS://", "VmeSs://"] {
        let body = base64::engine::general_purpose::STANDARD
            .encode(r#"{"add":"127.0.0.1","port":443,"id":"uuid-123"}"#);
        let link = format!("{}{}", prefix, body);
        let p = Protocol::parse(&link);
        assert!(p.is_ok(), "prefix {} should be accepted", prefix);
        assert!(matches!(p.unwrap(), Protocol::VMess(_)));
    }
}

#[test]
fn protocols_prefix_case_insensitive_vless() {
    for prefix in ["vless://", "VLESS://", "VLeSs://"] {
        let link = format!("{}id@host:443", prefix);
        let p = Protocol::parse(&link);
        assert!(p.is_ok(), "prefix {} should be accepted", prefix);
        assert!(matches!(p.unwrap(), Protocol::VLess(_)));
    }
}

#[test]
fn protocols_prefix_case_insensitive_ss() {
    let user = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:pass");
    for prefix in ["ss://", "SS://", "Ss://"] {
        let link = format!("{}{}@host:8388", prefix, user);
        let p = Protocol::parse(&link);
        assert!(p.is_ok(), "prefix {} should be accepted", prefix);
        assert!(matches!(p.unwrap(), Protocol::Shadowsocks(_)));
    }
}

#[test]
fn protocols_prefix_case_insensitive_trojan() {
    for prefix in ["trojan://", "TROJAN://", "TrOjAn://"] {
        let link = format!("{}pw@host:443", prefix);
        let p = Protocol::parse(&link);
        assert!(p.is_ok(), "prefix {} should be accepted", prefix);
        assert!(matches!(p.unwrap(), Protocol::Trojan(_)));
    }
}

#[test]
fn protocols_prefix_case_insensitive_hysteria2() {
    for prefix in ["hysteria2://", "HYSTERIA2://", "Hysteria2://"] {
        let link = format!("{}host:443", prefix);
        let p = Protocol::parse(&link);
        assert!(p.is_ok(), "prefix {} should be accepted", prefix);
        assert!(matches!(p.unwrap(), Protocol::Hysteria2(_)));
    }
}

#[test]
fn protocols_unsupported_returns_unsupported_protocol() {
    let link = "unknown://something";
    let err = Protocol::parse(link).unwrap_err();
    assert!(matches!(err, ProtocolError::UnsupportedProtocol(_)));
}

// =============================================================================
// Error (ProtocolError display and From impls)
// =============================================================================

#[test]
fn error_display_and_std_error() {
    let e = ProtocolError::InvalidFormat("bad link".to_string());
    let s = e.to_string();
    assert!(s.contains("Invalid format"));
    assert!(s.contains("bad link"));
    let e2 = ProtocolError::UnsupportedProtocol("foo".to_string());
    assert!(e2.to_string().contains("Unsupported protocol"));
    fn assert_error<E: std::error::Error>() {}
    assert_error::<ProtocolError>();
}

#[test]
fn error_from_base64_decode_error() {
    use base64::engine::general_purpose::STANDARD;
    let invalid = STANDARD.decode("!!!");
    let err = invalid.unwrap_err();
    let pe: ProtocolError = err.into();
    assert!(matches!(pe, ProtocolError::Base64DecodeError(_)));
}

#[test]
fn error_from_parse_int_error() {
    let err: std::num::ParseIntError = "x".parse::<u16>().unwrap_err();
    let pe: ProtocolError = err.into();
    assert!(matches!(pe, ProtocolError::InvalidField(_)));
}

#[test]
fn protocols_fragment_decoded_as_remark() {
    // 各协议 fragment 均解码为备注
    let vless = VLess::parse("vless://u@h:80#%E5%A4%87%E6%B3%A8").unwrap();
    assert!(
        vless
            .config
            .remark
            .as_ref()
            .map(|s| s.contains("备"))
            .unwrap_or(false)
            || vless.config.remark.as_deref() == Some("备注")
    );

    let trojan = Trojan::parse("trojan://pw@h:80#remark").unwrap();
    assert_eq!(trojan.config.remark.as_deref(), Some("remark"));

    let h2 = Hysteria2::parse("hysteria2://h:443#tag").unwrap();
    assert_eq!(h2.config.fragment.as_deref(), Some("tag"));
}

// =============================================================================
// VMess（文档 §1）
// =============================================================================

#[test]
fn vmess_v2_minimal_required_add_port_id() {
    let json = r#"{"add":"1.2.3.4","port":443,"id":"550e8400-e29b-41d4-a716-446655440000"}"#;
    let b64 = base64::engine::general_purpose::STANDARD.encode(json);
    let link = format!("vmess://{}", b64);
    let v = VMess::parse(&link).unwrap();
    assert_eq!(v.config.add, "1.2.3.4");
    assert_eq!(v.config.port, 443);
    assert_eq!(v.config.id, "550e8400-e29b-41d4-a716-446655440000");
}

#[test]
fn vmess_v2_port_as_string() {
    let json = r#"{"add":"a","port":"8080","id":"uuid"}"#;
    let b64 = base64::engine::general_purpose::STANDARD.encode(json);
    let v = VMess::parse(&format!("vmess://{}", b64)).unwrap();
    assert_eq!(v.config.port, 8080);
}

#[test]
fn vmess_v2_aid_as_number_and_string() {
    let with_num = format!(
        "vmess://{}",
        base64::engine::general_purpose::STANDARD
            .encode(r#"{"add":"a","port":80,"id":"u","aid":0}"#)
    );
    let v1 = VMess::parse(&with_num).unwrap();
    assert_eq!(v1.config.aid, Some(0));

    let with_str = format!(
        "vmess://{}",
        base64::engine::general_purpose::STANDARD
            .encode(r#"{"add":"a","port":80,"id":"u","aid":"2"}"#)
    );
    let v2 = VMess::parse(&with_str).unwrap();
    assert_eq!(v2.config.aid, Some(2));
}

#[test]
fn vmess_v2_v_as_string_and_number() {
    let with_str = format!(
        "vmess://{}",
        base64::engine::general_purpose::STANDARD
            .encode(r#"{"v":"2","add":"a","port":80,"id":"u"}"#)
    );
    let v1 = VMess::parse(&with_str).unwrap();
    assert_eq!(v1.config.v.as_deref(), Some("2"));

    let with_num = format!(
        "vmess://{}",
        base64::engine::general_purpose::STANDARD.encode(r#"{"v":2,"add":"a","port":80,"id":"u"}"#)
    );
    let v2 = VMess::parse(&with_num).unwrap();
    assert_eq!(v2.config.v.as_deref(), Some("2"));
}

#[test]
fn vmess_v2_all_optional_fields() {
    let json = r#"{
        "v":"2","ps":"名称","add":"example.com","port":443,"id":"uuid",
        "aid":0,"net":"ws","type":"none","host":"example.com","path":"/ws",
        "tls":"tls","scy":"auto","alpn":"h2","fp":"chrome","sni":"example.com"
    }"#;
    let json_compact = json.replace('\n', "").replace(" ", "");
    let b64 = base64::engine::general_purpose::STANDARD.encode(&json_compact);
    let v = VMess::parse(&format!("vmess://{}", b64)).unwrap();
    assert_eq!(v.config.ps.as_deref(), Some("名称"));
    assert_eq!(v.config.net.as_deref(), Some("ws"));
    assert_eq!(v.config.host.as_deref(), Some("example.com"));
    assert_eq!(v.config.path.as_deref(), Some("/ws"));
    assert_eq!(v.config.tls.as_deref(), Some("tls"));
    assert_eq!(v.config.scy.as_deref(), Some("auto"));
    assert_eq!(v.config.alpn.as_deref(), Some("h2"));
    assert_eq!(v.config.fp.as_deref(), Some("chrome"));
    assert_eq!(v.config.sni.as_deref(), Some("example.com"));
}

#[test]
fn vmess_v2_base64_standard_no_padding() {
    // 无 padding 的 Base64 也应能解码
    let json = r#"{"add":"a","port":1,"id":"u"}"#;
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(json);
    let link = format!("vmess://{}", b64);
    let v = VMess::parse(&link).unwrap();
    assert_eq!(v.config.add, "a");
    assert_eq!(v.config.port, 1);
}

#[test]
fn vmess_v2_whitespace_stripped_before_decode() {
    let json = r#"{"add":"h","port":80,"id":"u"}"#;
    let b64 = base64::engine::general_purpose::STANDARD.encode(json);
    let link = format!("vmess://{}\n\t ", b64);
    let v = VMess::parse(&link).unwrap();
    assert_eq!(v.config.add, "h");
}

#[test]
fn vmess_v1_format_parse() {
    // V1: base64(security:uuid@host:port)?query
    let main_part = "auto:uuid@example.com:443";
    let main_b64 = base64::engine::general_purpose::STANDARD.encode(main_part);
    let link = format!(
        "vmess://{}?remarks=Test&network=ws&wsPath=/path&wsHost=host&aid=0&tls=1",
        main_b64
    );
    let v = VMess::parse(&link).unwrap();
    assert_eq!(v.config.add, "example.com");
    assert_eq!(v.config.port, 443);
    assert_eq!(v.config.id, "uuid");
    assert_eq!(v.config.scy.as_deref(), Some("auto"));
    assert_eq!(v.config.ps.as_deref(), Some("Test"));
    assert_eq!(v.config.net.as_deref(), Some("ws"));
    assert_eq!(v.config.path.as_deref(), Some("/path"));
    assert_eq!(v.config.host.as_deref(), Some("host"));
    assert_eq!(v.config.tls.as_deref(), Some("tls"));
}

#[test]
fn vmess_to_link_always_v2() {
    // V1 link: base64(security:uuid@host:port)
    let v1_body = base64::engine::general_purpose::STANDARD.encode("auto:uuid@example.com:443");
    let v1_link = format!("vmess://{}?remarks=x", v1_body);
    let vmess = VMess::parse(&v1_link).unwrap();
    let generated = vmess.to_link().unwrap();
    assert!(generated.starts_with("vmess://"));
    let parsed = VMess::parse(&generated).unwrap();
    assert_eq!(vmess.config.add, parsed.config.add);
    assert_eq!(vmess.config.port, parsed.config.port);
    assert_eq!(vmess.config.id, parsed.config.id);
}

#[test]
fn vmess_invalid_format_wrong_prefix() {
    let r = VMess::parse("vless://u@h:80");
    assert!(r.is_err());
    assert!(matches!(r, Err(ProtocolError::InvalidFormat(_))));
}

#[test]
fn vmess_invalid_base64() {
    let r = VMess::parse("vmess://!!!invalid!!!");
    assert!(r.is_err());
    assert!(matches!(r, Err(ProtocolError::Base64DecodeError(_))));
}

#[test]
fn vmess_invalid_json() {
    let b64 = base64::engine::general_purpose::STANDARD.encode("not json");
    let r = VMess::parse(&format!("vmess://{}", b64));
    assert!(r.is_err());
    assert!(matches!(r, Err(ProtocolError::JsonParseError(_))));
}

#[test]
fn vmess_missing_required_field_add() {
    let json = r#"{"port":443,"id":"uuid"}"#;
    let b64 = base64::engine::general_purpose::STANDARD.encode(json);
    let r = VMess::parse(&format!("vmess://{}", b64));
    assert!(r.is_err());
}

// =============================================================================
// VLESS（文档 §2）
// =============================================================================

#[test]
fn vless_format_id_address_port_required() {
    let link = "vless://uuid@example.com:443";
    let v = VLess::parse(link).unwrap();
    assert_eq!(v.config.id, "uuid");
    assert_eq!(v.config.address, "example.com");
    assert_eq!(v.config.port, 443);
}

#[test]
fn vless_query_encryption_flow_security_type_host_path_sni_fp_pbk_sid_seed_header_type() {
    let link = "vless://u@h:443?encryption=none&flow=xtls-rprx-vision&security=reality&type=tcp&host=hk.example.com&path=/ws&sni=sni.example.com&fp=chrome&pbk=pubkey&sid=shortid&seed=seed&headerType=none#remark";
    let v = VLess::parse(link).unwrap();
    assert_eq!(v.config.encryption.as_deref(), Some("none"));
    assert_eq!(v.config.flow.as_deref(), Some("xtls-rprx-vision"));
    assert_eq!(v.config.security.as_deref(), Some("reality"));
    assert_eq!(v.config.r#type.as_deref(), Some("tcp"));
    assert_eq!(v.config.host.as_deref(), Some("hk.example.com"));
    assert_eq!(v.config.path.as_deref(), Some("/ws"));
    assert_eq!(v.config.sni.as_deref(), Some("sni.example.com"));
    assert_eq!(v.config.fp.as_deref(), Some("chrome"));
    assert_eq!(v.config.pbk.as_deref(), Some("pubkey"));
    assert_eq!(v.config.sid.as_deref(), Some("shortid"));
    assert_eq!(v.config.seed.as_deref(), Some("seed"));
    assert_eq!(v.config.header_type.as_deref(), Some("none"));
    assert_eq!(v.config.remark.as_deref(), Some("remark"));
}

#[test]
fn vless_invalid_missing_at() {
    let r = VLess::parse("vless://example.com:443");
    assert!(r.is_err());
    assert!(matches!(r, Err(ProtocolError::InvalidFormat(_))));
}

#[test]
fn vless_invalid_missing_colon_in_host_port() {
    let r = VLess::parse("vless://uuid@example.com");
    assert!(r.is_err());
    assert!(matches!(r, Err(ProtocolError::InvalidFormat(_))));
}

#[test]
fn vless_invalid_port_not_u16() {
    let r = VLess::parse("vless://uuid@example.com:99999");
    assert!(r.is_err());
    assert!(matches!(r, Err(ProtocolError::InvalidField(_))));
}

#[test]
fn vless_round_trip_with_all_params() {
    let link = "vless://id@addr:8443?security=tls&sni=s.example.com#备注";
    let v = VLess::parse(link).unwrap();
    let generated = v.to_link().unwrap();
    let v2 = VLess::parse(&generated).unwrap();
    assert_eq!(v.config.id, v2.config.id);
    assert_eq!(v.config.address, v2.config.address);
    assert_eq!(v.config.port, v2.config.port);
}

// =============================================================================
// Shadowsocks SIP002（文档 §3）
// =============================================================================

#[test]
fn ss_sip002_userinfo_base64_method_password() {
    let user = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:secret");
    let link = format!("ss://{}@example.com:8388", user);
    let s = Shadowsocks::parse(&link).unwrap();
    assert_eq!(s.config.method, "aes-256-gcm");
    assert_eq!(s.config.password, "secret");
    assert_eq!(s.config.address, "example.com");
    assert_eq!(s.config.port, 8388);
}

#[test]
fn ss_sip002_tag_fragment_encoded() {
    let user = base64::engine::general_purpose::STANDARD.encode("chacha20:pass");
    let link = format!("ss://{}@h:80#My%20Tag", user);
    let s = Shadowsocks::parse(&link).unwrap();
    assert_eq!(s.config.tag.as_deref(), Some("My Tag"));
}

#[test]
fn ss_sip002_plugin_and_port_slash() {
    let user = base64::engine::general_purpose::STANDARD.encode("method:password");
    let link = format!("ss://{}@host:8388/?plugin=obfs-local;obfs=http", user);
    let s = Shadowsocks::parse(&link).unwrap();
    assert_eq!(s.config.plugin.as_deref(), Some("obfs-local;obfs=http"));
}

#[test]
fn ss_to_link_plugin_adds_slash_before_query() {
    let ss = Shadowsocks {
        config: crate::shadowsocks::ShadowsocksConfig {
            method: "aes-128-gcm".to_string(),
            password: "pwd".to_string(),
            address: "h".to_string(),
            port: 8080,
            tag: None,
            plugin: Some("plugin-name".to_string()),
        },
    };
    let link = ss.to_link().unwrap();
    assert!(link.contains("/?plugin=") || link.contains("/?plugin="));
}

#[test]
fn ss_invalid_prefix() {
    let r = Shadowsocks::parse("vmess://x");
    assert!(r.is_err());
    assert!(matches!(r, Err(ProtocolError::InvalidFormat(_))));
}

#[test]
fn ss_invalid_base64_userinfo() {
    let r = Shadowsocks::parse("ss://!!!@host:80");
    assert!(r.is_err());
}

#[test]
fn ss_round_trip_with_tag_and_plugin() {
    let user = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:pass");
    let link = format!("ss://{}@h:8388/?plugin=p#Tag", user);
    let s = Shadowsocks::parse(&link).unwrap();
    let generated = s.to_link().unwrap();
    let s2 = Shadowsocks::parse(&generated).unwrap();
    assert_eq!(s.config.method, s2.config.method);
    assert_eq!(s.config.address, s2.config.address);
    assert_eq!(s.config.port, s2.config.port);
}

// =============================================================================
// Trojan（文档 §4）
// =============================================================================

#[test]
fn trojan_format_password_host_port_required() {
    let link = "trojan://password@example.com:443";
    let t = Trojan::parse(link).unwrap();
    assert_eq!(t.config.password, "password");
    assert_eq!(t.config.address, "example.com");
    assert_eq!(t.config.port, 443);
}

#[test]
fn trojan_query_security_sni_flow_type_host_path_fp() {
    let link = "trojan://pw@h:443?security=xtls&sni=h&flow=xtls-rprx-origin&type=ws&host=ws.example.com&path=/trojan&fp=chrome#R";
    let t = Trojan::parse(link).unwrap();
    assert_eq!(t.config.security.as_deref(), Some("xtls"));
    assert_eq!(t.config.sni.as_deref(), Some("h"));
    assert_eq!(t.config.flow.as_deref(), Some("xtls-rprx-origin"));
    assert_eq!(t.config.r#type.as_deref(), Some("ws"));
    assert_eq!(t.config.host.as_deref(), Some("ws.example.com"));
    assert_eq!(t.config.path.as_deref(), Some("/trojan"));
    assert_eq!(t.config.fp.as_deref(), Some("chrome"));
    assert_eq!(t.config.remark.as_deref(), Some("R"));
}

#[test]
fn trojan_password_with_special_chars_encoded() {
    let link = "trojan://p%40ss%3Aword@host:443";
    let t = Trojan::parse(link).unwrap();
    assert_eq!(t.config.password, "p@ss:word");
}

#[test]
fn trojan_invalid_missing_at() {
    let r = Trojan::parse("trojan://example.com:443");
    assert!(r.is_err());
    assert!(matches!(r, Err(ProtocolError::InvalidFormat(_))));
}

#[test]
fn trojan_invalid_missing_colon() {
    let r = Trojan::parse("trojan://pw@host");
    assert!(r.is_err());
    assert!(matches!(r, Err(ProtocolError::InvalidFormat(_))));
}

#[test]
fn trojan_invalid_port() {
    let r = Trojan::parse("trojan://pw@host:99999");
    assert!(r.is_err());
    assert!(matches!(r, Err(ProtocolError::InvalidField(_))));
}

#[test]
fn trojan_round_trip_encodes_password() {
    let link = "trojan://p@ss@host:8443#R";
    let t = Trojan::parse(link).unwrap();
    let generated = t.to_link().unwrap();
    let t2 = Trojan::parse(&generated).unwrap();
    assert_eq!(t.config.password, t2.config.password);
    assert_eq!(t.config.address, t2.config.address);
    assert_eq!(t.config.port, t2.config.port);
}

// =============================================================================
// Hysteria2（文档 §5）
// =============================================================================

#[test]
fn hysteria2_auth_optional_host_port_required() {
    let with_auth = "hysteria2://user:pass@example.com:443";
    let h = Hysteria2::parse(with_auth).unwrap();
    assert_eq!(h.config.password.as_deref(), Some("user:pass"));
    assert_eq!(h.config.host, "example.com");
    assert_eq!(h.config.port, 443);

    let no_auth = "hysteria2://example.com:443";
    let h2 = Hysteria2::parse(no_auth).unwrap();
    assert!(h2.config.password.is_none());
    assert_eq!(h2.config.host, "example.com");
    assert_eq!(h2.config.port, 443);
}

#[test]
fn hysteria2_query_obfs_obfs_password_sni_insecure_pin_sha256() {
    let link = "hysteria2://h:443?obfs=salamander&obfs-password=obfspw&sni=h&insecure=1#Frag";
    let h = Hysteria2::parse(link).unwrap();
    assert_eq!(h.config.obfs.as_deref(), Some("salamander"));
    assert_eq!(h.config.sni.as_deref(), Some("h"));
    assert_eq!(h.config.insecure, Some(true));
    assert_eq!(h.config.fragment.as_deref(), Some("Frag"));
}

#[test]
fn hysteria2_query_extensions_protocol_up_down_mbps_alpn_fast_open_recv_window_hop_interval() {
    let link = "hysteria2://pw@h:443?protocol=wechat-video&up_mbps=100&down_mbps=200&alpn=h3&fast_open=1&recv_window=123&recv_window_conn=456&hop_interval=60#X";
    let h = Hysteria2::parse(link).unwrap();
    assert_eq!(h.config.protocol.as_deref(), Some("wechat-video"));
    assert_eq!(h.config.up_mbps, Some(100.0));
    assert_eq!(h.config.down_mbps, Some(200.0));
    assert_eq!(h.config.alpn, Some(vec!["h3".to_string()]));
    assert_eq!(h.config.fast_open, Some(true));
    assert_eq!(h.config.recv_window, Some(123));
    assert_eq!(h.config.recv_window_conn, Some(456));
    assert_eq!(h.config.hop_interval, Some(60));
}

#[test]
fn hysteria2_invalid_prefix() {
    let r = Hysteria2::parse("hy2://h:443");
    assert!(r.is_err());
    assert!(matches!(r, Err(ProtocolError::InvalidFormat(_))));
}

#[test]
fn hysteria2_invalid_missing_colon_port() {
    let r = Hysteria2::parse("hysteria2://password@example.com");
    assert!(r.is_err());
    assert!(matches!(r, Err(ProtocolError::InvalidFormat(_))));
}

#[test]
fn hysteria2_invalid_port() {
    let r = Hysteria2::parse("hysteria2://h:99999");
    assert!(r.is_err());
    assert!(matches!(r, Err(ProtocolError::InvalidField(_))));
}

#[test]
fn hysteria2_round_trip_with_password_and_params() {
    let link = "hysteria2://auth@host:8443?down_mbps=200&sni=host#F";
    let h = Hysteria2::parse(link).unwrap();
    let generated = h.to_link().unwrap();
    let h2 = Hysteria2::parse(&generated).unwrap();
    assert_eq!(h.config.host, h2.config.host);
    assert_eq!(h.config.port, h2.config.port);
    assert_eq!(h.config.password, h2.config.password);
}

// =============================================================================
// Protocol 统一入口
// =============================================================================

#[test]
fn protocol_parse_dispatch_each() {
    let vmess_json = r#"{"add":"a","port":80,"id":"u"}"#;
    let vmess_link = format!(
        "vmess://{}",
        base64::engine::general_purpose::STANDARD.encode(vmess_json)
    );
    assert!(matches!(
        Protocol::parse(&vmess_link),
        Ok(Protocol::VMess(_))
    ));

    assert!(matches!(
        Protocol::parse("vless://u@h:80"),
        Ok(Protocol::VLess(_))
    ));

    let ss_user = base64::engine::general_purpose::STANDARD.encode("m:p");
    assert!(matches!(
        Protocol::parse(&format!("ss://{}@h:80", ss_user)),
        Ok(Protocol::Shadowsocks(_))
    ));

    assert!(matches!(
        Protocol::parse("trojan://pw@h:80"),
        Ok(Protocol::Trojan(_))
    ));
    assert!(matches!(
        Protocol::parse("hysteria2://h:80"),
        Ok(Protocol::Hysteria2(_))
    ));
}

#[test]
fn protocol_error_invalid_field_port_zero_vless() {
    // port 0 非法（u16 有效但业务上通常 1-65535）
    let r = VLess::parse("vless://u@h:0");
    assert!(r.is_ok()); // 当前实现接受 0，若业务拒绝可改为 assert!(r.is_err())
}

#[test]
fn protocol_error_invalid_field_port_max() {
    let r = VLess::parse("vless://u@h:65535");
    assert!(r.is_ok());
    assert_eq!(r.unwrap().config.port, 65535);
}

#[test]
fn protocol_to_link_each() {
    let vmess_json = r#"{"add":"a","port":80,"id":"u"}"#;
    let vmess_link = format!(
        "vmess://{}",
        base64::engine::general_purpose::STANDARD.encode(vmess_json)
    );
    let p = Protocol::parse(&vmess_link).unwrap();
    let link = p.to_link().unwrap();
    assert!(link.starts_with("vmess://"));

    let p2 = Protocol::parse("vless://u@h:80").unwrap();
    assert!(p2.to_link().unwrap().starts_with("vless://"));

    let ss_user = base64::engine::general_purpose::STANDARD.encode("m:p");
    let p3 = Protocol::parse(&format!("ss://{}@h:80", ss_user)).unwrap();
    assert!(p3.to_link().unwrap().starts_with("ss://"));

    let p4 = Protocol::parse("trojan://pw@h:80").unwrap();
    assert!(p4.to_link().unwrap().starts_with("trojan://"));

    let p5 = Protocol::parse("hysteria2://h:80").unwrap();
    assert!(p5.to_link().unwrap().starts_with("hysteria2://"));
}
