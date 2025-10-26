pub mod protocol;
pub mod context;
pub mod internal;
pub mod config;
pub mod keystore;
pub mod error;
pub mod services;
pub mod common;
pub mod utils;

pub use context::BotContext;
pub use protocol::{EventMessage, Protocols, ProtocolEvent};
pub use error::{Error, Result};

/// Prelude module for service definitions.
///
/// This module provides a convenient import for all commonly used types
/// when defining services with the `define_service!` macro.
///
/// # Usage
///
/// ```ignore
/// use lagrange_core::service_prelude::*;
///
/// define_service! {
///     MyService: "my.command" {
///         request_type: RequestType::D2Auth,
///         encrypt_type: EncryptType::EncryptEmpty,
///         // ...
///     }
/// }
/// ```
///
/// This imports:
/// - `RequestType` and `EncryptType` for service metadata
/// - `BotContext` for service handlers
/// - `Bytes` for data handling
/// - `Arc` for shared references
/// - `Result` for error handling
pub mod service_prelude {
    //! Prelude for service definitions.
    //!
    //! Import this module to get all commonly needed types for defining services:
    //!
    //! ```ignore
    //! use lagrange_core::service_prelude::*;
    //! ```

    pub use crate::context::BotContext;
    pub use crate::error::Result;
    pub use crate::protocol::{EncryptType, RequestType, ProtocolEvent};
    pub use bytes::Bytes;
    pub use std::sync::Arc;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::*;
    use crate::config::*;
    use crate::keystore::*;

    #[test]
    fn test_bot_app_info_discriminated_union() {
        let linux = BotAppInfo::from_protocol(Protocols::Linux);
        assert!(matches!(linux, BotAppInfo::Linux(_)));
        assert_eq!(linux.app_id(), 1600001615);
        assert_eq!(linux.protocol(), Protocols::Linux);

        let windows = BotAppInfo::from_protocol(Protocols::Windows);
        assert!(matches!(windows, BotAppInfo::Windows(_)));
        assert_eq!(windows.app_id(), 1600001604);

        let android = BotAppInfo::from_protocol(Protocols::AndroidPhone);
        assert!(matches!(android, BotAppInfo::Android { variant: AndroidVariant::Phone, .. }));
        assert_eq!(android.app_id(), 16);
        assert_eq!(android.android_variant(), Some(AndroidVariant::Phone));

        let default = BotAppInfo::default();
        assert!(matches!(default, BotAppInfo::Linux(_)));
    }

    #[test]
    fn test_bot_app_info_accessors() {
        let linux = BotAppInfo::from_protocol(Protocols::Linux);
        assert_eq!(linux.package_name(), "com.tencent.qq");
        assert_eq!(linux.current_version(), "3.2.15-30366");

        let android = BotAppInfo::Android {
            info: AppInfo::android(AndroidVariant::Phone),
            variant: AndroidVariant::Phone,
        };
        assert_eq!(android.package_name(), "com.tencent.mobileqq");
    }

    #[test]
    fn test_bot_info() {
        let info = BotInfo::new(25, BotGender::Male, "TestBot".to_string());
        assert_eq!(info.age, 25);
        assert_eq!(info.gender, BotGender::Male);
        assert_eq!(info.name, "TestBot");

        let display = format!("{}", info);
        assert!(display.contains("TestBot"));
        assert!(display.contains("Male"));
        assert!(display.contains("25"));
    }

    #[test]
    fn test_bot_gender() {
        let male = BotGender::Male;
        let female = BotGender::Female;
        let default = BotGender::default();

        assert_eq!(male as u8, 1);
        assert_eq!(female as u8, 2);
        assert_eq!(default, BotGender::Unset);
    }

    #[test]
    fn test_bot_friend_contact() {
        let friend = BotFriend {
            uin: 123456,
            uid: "uid123".to_string(),
            nickname: "Friend1".to_string(),
            age: 20,
            gender: BotGender::Female,
            remarks: "Best friend".to_string(),
            personal_sign: "Hello".to_string(),
            qid: "qid123".to_string(),
            category: None,
        };

        assert_eq!(friend.uin(), 123456);
        assert_eq!(friend.uid(), "uid123");
        assert_eq!(friend.nickname(), "Friend1");
    }

    #[test]
    fn test_bot_group_contact() {
        let group = BotGroup {
            group_uin: 987654,
            group_uid: "987654".to_string(),
            group_name: "Test Group".to_string(),
            member_count: 100,
            max_member: 200,
            create_time: 1234567890,
            description: Some("A test group".to_string()),
            question: None,
            announcement: None,
        };

        assert_eq!(group.uin(), 987654);
        assert_eq!(group.uid(), "987654");
        assert_eq!(group.nickname(), "Test Group");
    }

    #[test]
    fn test_bot_config_builder() {
        let config = BotConfig::builder()
            .protocol(Protocols::Windows)
            .use_ipv6(true)
            .auto_reconnect(false)
            .verbose(true)
            .highway_chunk_size(512 * 1024)
            .highway_concurrent(2)
            .build();

        assert_eq!(config.protocol, Protocols::Windows);
        assert_eq!(config.use_ipv6_network, true);
        assert_eq!(config.auto_reconnect, false);
        assert_eq!(config.verbose, true);
        assert_eq!(config.highway_chunk_size, 512 * 1024);
        assert_eq!(config.highway_concurrent, 2);
    }

    #[test]
    fn test_bot_config_defaults() {
        let config = BotConfig::default();
        assert_eq!(config.protocol, Protocols::Linux);
        assert_eq!(config.auto_reconnect, true);
        assert_eq!(config.auto_re_login, true);
        assert_eq!(config.get_optimum_server, true);
        assert_eq!(config.highway_chunk_size, 1024 * 1024);
        assert_eq!(config.verbose, false);
    }

    #[test]
    fn test_wlogin_sigs() {
        let mut sigs = WLoginSigs::default();
        assert_eq!(sigs.a2.len(), 16);
        assert_eq!(sigs.random_key.len(), 16);

        let old_random = sigs.random_key.clone();
        sigs.clear();
        assert_ne!(sigs.random_key, old_random);
        assert_eq!(sigs.a2, vec![0; 16]);
    }

    #[test]
    fn test_bot_keystore() {
        let keystore = BotKeystore::new()
            .with_uin(123456)
            .with_uid("uid123".to_string())
            .with_qimei("qimei123".to_string());

        assert_eq!(keystore.uin, Some(123456));
        assert_eq!(keystore.uid, Some("uid123".to_string()));
        assert_eq!(keystore.qimei, "qimei123");
        assert_eq!(keystore.device_name, "lagrange-rs");
    }

    #[test]
    fn test_session_state() {
        let state = SessionState::default();
        assert!(state.exchange_key.is_none());
        assert!(state.cookies.is_empty());
        assert!(state.qr_sig.is_none());
        assert!(state.tlv_cache.is_empty());
    }

    #[test]
    fn test_sign_provider() {
        use crate::common::sign::{DefaultSignProvider, SignProvider};

        let provider = DefaultSignProvider::default();
        assert_eq!(provider.platform(), "default");
    }

    #[test]
    fn test_platform_values_match_csharp() {
        let linux = AppInfo::linux();
        assert_eq!(linux.os, "Linux");
        assert_eq!(linux.vendor_os, "linux");
        assert_eq!(linux.kernel, "Linux");
        assert_eq!(linux.current_version, "3.2.15-30366");
        assert_eq!(linux.pt_version, "2.0.0");
        assert_eq!(linux.sso_version, 19);
        assert_eq!(linux.app_id, 1600001615);
        assert_eq!(linux.sub_app_id, 537258424);
        assert_eq!(linux.app_client_version, 30366);
        assert_eq!(linux.sdk_info.sdk_version, "nt.wtlogin.0.0.1");

        let windows = AppInfo::windows();
        assert_eq!(windows.os, "Windows");
        assert_eq!(windows.vendor_os, "win32");
        assert_eq!(windows.kernel, "Windows_NT");
        assert_eq!(windows.current_version, "9.9.19-35184");
        assert_eq!(windows.pt_version, "2.0.0");
        assert_eq!(windows.sso_version, 23);
        assert_eq!(windows.app_id, 1600001604);
        assert_eq!(windows.sub_app_id, 537291048);
        assert_eq!(windows.app_client_version, 35184);

        let macos = AppInfo::macos();
        assert_eq!(macos.os, "Mac");
        assert_eq!(macos.vendor_os, "mac");
        assert_eq!(macos.kernel, "Darwin");
        assert_eq!(macos.current_version, "6.9.23-20139");
        assert_eq!(macos.pt_version, "2.0.0");
        assert_eq!(macos.sso_version, 23);
        assert_eq!(macos.app_id, 1600001602);
        assert_eq!(macos.sub_app_id, 537200848);
        assert_eq!(macos.app_client_version, 13172);
    }

    #[test]
    fn test_android_app_info_variants() {
        let phone = AppInfo::android(AndroidVariant::Phone);
        let pad = AppInfo::android(AndroidVariant::Pad);
        let watch = AppInfo::android(AndroidVariant::Watch);

        assert_eq!(phone.sub_app_id, 537275636);
        assert_eq!(pad.sub_app_id, 537275675);
        assert_eq!(watch.sub_app_id, 537258298);

        assert_eq!(phone.current_version, "9.1.60.045f5d19");
        assert_eq!(pad.current_version, "9.1.60.045f5d19");
        assert_eq!(watch.current_version, "testrevision");
        assert_eq!(phone.package_name, "com.tencent.mobileqq");
        assert_eq!(pad.package_name, "com.tencent.mobileqq");
        assert_eq!(watch.package_name, "com.tencent.qqlite");

        assert!(!phone.apk_signature_md5.is_empty());
        assert!(!pad.apk_signature_md5.is_empty());
        assert!(!watch.apk_signature_md5.is_empty());

        assert_eq!(
            phone.apk_signature_md5,
            vec![0xA6, 0xB7, 0x45, 0xBF, 0x24, 0xA2, 0xC2, 0x77, 0x52, 0x77, 0x16, 0xF6, 0xF3, 0x6E, 0xB6, 0x8D]
        );

        assert_eq!(phone.sdk_info.sdk_version, "6.0.0.2568");
        assert_eq!(pad.sdk_info.sdk_version, "6.0.0.2568");
        assert_eq!(watch.sdk_info.sdk_version, "6.0.0.2564");
    }
}
