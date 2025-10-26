use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WLoginSigs {
    #[serde(with = "serde_bytes")]
    pub a2: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub a2_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub d2: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub d2_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub a1: Vec<u8>,

    #[serde(with = "serde_bytes")]
    pub tgtgt_key: Vec<u8>,
    pub ksid: Option<Vec<u8>>,
    pub super_key: Option<Vec<u8>>,
    pub st_key: Option<Vec<u8>>,
    pub st_web: Option<Vec<u8>>,
    pub st: Option<Vec<u8>>,
    pub wt_session_ticket: Option<Vec<u8>>,
    pub wt_session_ticket_key: Option<Vec<u8>>,
    pub random_key: Vec<u8>,
    pub s_key: Option<Vec<u8>>,
    pub no_pic_sig: Option<Vec<u8>>,

    #[serde(default)]
    pub ps_key: std::collections::HashMap<String, Vec<u8>>,
}

impl Default for WLoginSigs {
    fn default() -> Self {
        Self {
            a2: vec![0; 16],
            a2_key: vec![0; 16],
            d2: vec![0; 16],
            d2_key: vec![0; 16],
            a1: vec![0; 16],
            tgtgt_key: vec![0; 16],
            ksid: None,
            super_key: None,
            st_key: None,
            st_web: None,
            st: None,
            wt_session_ticket: None,
            wt_session_ticket_key: None,
            random_key: Self::generate_random_key(),
            s_key: None,
            no_pic_sig: None,
            ps_key: Default::default(),
        }
    }
}

impl WLoginSigs {
    fn generate_random_key() -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..16).map(|_| rng.gen()).collect()
    }

    pub fn clear(&mut self) {
        self.a2 = vec![0; 16];
        self.d2 = vec![0; 16];
        self.a1 = vec![0; 16];
        self.random_key = Self::generate_random_key();
        self.ps_key.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    #[serde(skip)]
    pub exchange_key: Option<Vec<u8>>,
    #[serde(default)]
    pub cookies: std::collections::HashMap<String, Vec<u8>>,
    pub qr_sig: Option<Vec<u8>>,
    #[serde(default)]
    pub tlv_cache: std::collections::HashMap<u16, Vec<u8>>,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            exchange_key: None,
            cookies: Default::default(),
            qr_sig: None,
            tlv_cache: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotKeystore {
    pub uin: Option<u64>,
    pub uid: Option<String>,
    #[serde(skip)]
    pub bot_info: Option<crate::common::BotInfo>,

    #[serde(with = "serde_bytes", default = "default_guid")]
    pub guid: Vec<u8>,
    pub android_id: String,
    pub qimei: String,
    pub device_name: String,

    #[serde(default)]
    pub sigs: WLoginSigs,

    #[serde(default)]
    pub state: SessionState,
}

fn default_guid() -> Vec<u8> {
    vec![0; 16]
}

impl Default for BotKeystore {
    fn default() -> Self {
        Self {
            uin: None,
            uid: None,
            bot_info: None,
            guid: vec![0; 16],
            android_id: String::new(),
            qimei: String::new(),
            device_name: "lagrange-rs".to_string(),
            sigs: WLoginSigs::default(),
            state: SessionState::default(),
        }
    }
}

impl BotKeystore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_uin(mut self, uin: u64) -> Self {
        self.uin = Some(uin);
        self
    }

    pub fn with_uid(mut self, uid: String) -> Self {
        self.uid = Some(uid);
        self
    }

    pub fn with_device(mut self, android_id: String, guid: Vec<u8>) -> Self {
        self.android_id = android_id;
        self.guid = guid;
        self
    }

    pub fn with_qimei(mut self, qimei: String) -> Self {
        self.qimei = qimei;
        self
    }

    pub fn clear(&mut self) {
        self.sigs.clear();
        self.state = SessionState::default();
    }
}
