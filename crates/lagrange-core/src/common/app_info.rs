use crate::protocol::Protocols;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum Sig {
    WloginA5 = 1 << 1,
    WloginReserved = 1 << 4,
    WloginStweb = 1 << 5,
    WloginA2 = 1 << 6,
    WloginSt = 1 << 7,
    WloginLskey = 1 << 9,
    WloginSkey = 1 << 12,
    WloginSig64 = 1 << 13,
    WloginOpenkey = 1 << 14,
    WloginToken = 1 << 15,
    WloginVkey = 1 << 17,
    WloginD2 = 1 << 18,
    WloginSid = 1 << 19,
    WloginPskey = 1 << 20,
    WloginAqsig = 1 << 21,
    WloginLhsig = 1 << 22,
    WloginPaytoken = 1 << 23,
    WloginPf = 1 << 24,
    WloginDa2 = 1 << 25,
    WloginQrpush = 1 << 26,
    WloginPt4Token = 1 << 27,
}

pub type MainSigMap = u32;

pub const fn create_sig_map(flags: &[Sig]) -> MainSigMap {
    let mut map = 0u32;
    let mut i = 0;
    while i < flags.len() {
        map |= flags[i] as u32;
        i += 1;
    }
    map
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WtLoginSdkInfo {
    pub sdk_build_time: u32,
    pub sdk_version: String,
    pub misc_bit_map: u32,
    pub sub_sig_map: u32,
    pub main_sig_map: MainSigMap,
}

impl WtLoginSdkInfo {
    pub fn desktop() -> Self {
        const DESKTOP_SIG_MAP: MainSigMap = create_sig_map(&[
            Sig::WloginStweb,
            Sig::WloginA2,
            Sig::WloginSt,
            Sig::WloginSkey,
            Sig::WloginVkey,
            Sig::WloginD2,
            Sig::WloginSid,
            Sig::WloginPskey,
            Sig::WloginDa2,
            Sig::WloginPt4Token,
        ]);

        Self {
            sdk_build_time: 0,
            sdk_version: "nt.wtlogin.0.0.1".to_string(),
            misc_bit_map: 12058620,
            sub_sig_map: 0,
            main_sig_map: DESKTOP_SIG_MAP,
        }
    }

    pub fn android(variant: AndroidVariant) -> Self {
        const ANDROID_SIG_MAP: MainSigMap = create_sig_map(&[
            Sig::WloginA5,
            Sig::WloginReserved,
            Sig::WloginStweb,
            Sig::WloginA2,
            Sig::WloginSt,
            Sig::WloginLskey,
            Sig::WloginSkey,
            Sig::WloginSig64,
            Sig::WloginVkey,
            Sig::WloginD2,
            Sig::WloginSid,
            Sig::WloginPskey,
            Sig::WloginAqsig,
            Sig::WloginLhsig,
            Sig::WloginPaytoken,
        ]);

        let (sdk_build_time, sdk_version) = match variant {
            AndroidVariant::Phone => (1740483688, "6.0.0.2568"),
            AndroidVariant::Pad => (1740483688, "6.0.0.2568"),
            AndroidVariant::Watch => (1724730201, "6.0.0.2564"),
        };

        Self {
            sdk_build_time,
            sdk_version: sdk_version.to_string(),
            misc_bit_map: 150470524,
            sub_sig_map: 66560,
            main_sig_map: ANDROID_SIG_MAP | (1 << 16),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AndroidVariant {
    Phone,
    Pad,
    Watch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub os: String,
    pub vendor_os: String,
    pub kernel: String,
    pub current_version: String,
    pub pt_version: String,
    pub sso_version: u32,
    pub package_name: String,
    pub apk_signature_md5: Vec<u8>,
    pub sdk_info: WtLoginSdkInfo,
    pub app_id: u32,
    pub sub_app_id: u32,
    pub app_client_version: u32,
}

impl AppInfo {
    pub fn windows() -> Self {
        Self {
            os: "Windows".to_string(),
            vendor_os: "win32".to_string(),
            kernel: "Windows_NT".to_string(),
            current_version: "9.9.19-35184".to_string(),
            pt_version: "2.0.0".to_string(),
            sso_version: 23,
            package_name: "com.tencent.qq".to_string(),
            apk_signature_md5: b"com.tencent.qq".to_vec(),
            sdk_info: WtLoginSdkInfo::desktop(),
            app_id: 1600001604,
            sub_app_id: 537291048,
            app_client_version: 35184,
        }
    }

    pub fn linux() -> Self {
        Self {
            os: "Linux".to_string(),
            vendor_os: "linux".to_string(),
            kernel: "Linux".to_string(),
            current_version: "3.2.15-30366".to_string(),
            pt_version: "2.0.0".to_string(),
            sso_version: 19,
            package_name: "com.tencent.qq".to_string(),
            apk_signature_md5: b"com.tencent.qq".to_vec(),
            sdk_info: WtLoginSdkInfo::desktop(),
            app_id: 1600001615,
            sub_app_id: 537258424,
            app_client_version: 30366,
        }
    }

    pub fn macos() -> Self {
        Self {
            os: "Mac".to_string(),
            vendor_os: "mac".to_string(),
            kernel: "Darwin".to_string(),
            current_version: "6.9.23-20139".to_string(),
            pt_version: "2.0.0".to_string(),
            sso_version: 23,
            package_name: "com.tencent.qq".to_string(),
            apk_signature_md5: b"com.tencent.qq".to_vec(),
            sdk_info: WtLoginSdkInfo::desktop(),
            app_id: 1600001602,
            sub_app_id: 537200848,
            app_client_version: 13172,
        }
    }

    pub fn android(variant: AndroidVariant) -> Self {
        let (sub_app_id, current_version, package_name) = match variant {
            AndroidVariant::Phone => (
                537275636,
                "9.1.60.045f5d19",
                "com.tencent.mobileqq",
            ),
            AndroidVariant::Pad => (
                537275675,
                "9.1.60.045f5d19",
                "com.tencent.mobileqq",
            ),
            AndroidVariant::Watch => (
                537258298,
                "testrevision",
                "com.tencent.qqlite",
            ),
        };

        Self {
            os: "Android".to_string(),
            vendor_os: String::new(),
            kernel: String::new(),
            current_version: current_version.to_string(),
            pt_version: "9.1.60".to_string(),
            sso_version: 22,
            package_name: package_name.to_string(),
            apk_signature_md5: vec![
                0xA6, 0xB7, 0x45, 0xBF, 0x24, 0xA2, 0xC2, 0x77, 0x52, 0x77, 0x16, 0xF6, 0xF3,
                0x6E, 0xB6, 0x8D,
            ],
            sdk_info: WtLoginSdkInfo::android(variant),
            app_id: 16,
            sub_app_id,
            app_client_version: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol")]
pub enum BotAppInfo {
    Windows(AppInfo),
    Linux(AppInfo),
    MacOs(AppInfo),
    Android {
        #[serde(flatten)]
        info: AppInfo,
        variant: AndroidVariant,
    },
}

impl Default for BotAppInfo {
    fn default() -> Self {
        Self::Linux(AppInfo::linux())
    }
}

impl BotAppInfo {
    pub fn from_protocol(protocol: Protocols) -> Self {
        match protocol {
            Protocols::Windows => Self::Windows(AppInfo::windows()),
            Protocols::Linux => Self::Linux(AppInfo::linux()),
            Protocols::MacOs => Self::MacOs(AppInfo::macos()),
            Protocols::AndroidPhone => Self::Android {
                info: AppInfo::android(AndroidVariant::Phone),
                variant: AndroidVariant::Phone,
            },
            Protocols::AndroidPad => Self::Android {
                info: AppInfo::android(AndroidVariant::Pad),
                variant: AndroidVariant::Pad,
            },
            Protocols::AndroidWatch => Self::Android {
                info: AppInfo::android(AndroidVariant::Watch),
                variant: AndroidVariant::Watch,
            },
            Protocols::None => Self::Linux(AppInfo::linux()),
        }
    }

    pub fn protocol(&self) -> Protocols {
        match self {
            Self::Windows(_) => Protocols::Windows,
            Self::Linux(_) => Protocols::Linux,
            Self::MacOs(_) => Protocols::MacOs,
            Self::Android { variant, .. } => match variant {
                AndroidVariant::Phone => Protocols::AndroidPhone,
                AndroidVariant::Pad => Protocols::AndroidPad,
                AndroidVariant::Watch => Protocols::AndroidWatch,
            },
        }
    }

    fn inner(&self) -> &AppInfo {
        match self {
            Self::Windows(info) | Self::Linux(info) | Self::MacOs(info) => info,
            Self::Android { info, .. } => info,
        }
    }

    pub fn app_id(&self) -> u32 {
        self.inner().app_id
    }

    pub fn current_version(&self) -> &str {
        &self.inner().current_version
    }

    pub fn package_name(&self) -> &str {
        &self.inner().package_name
    }

    pub fn android_variant(&self) -> Option<AndroidVariant> {
        match self {
            Self::Android { variant, .. } => Some(*variant),
            _ => None,
        }
    }
}
