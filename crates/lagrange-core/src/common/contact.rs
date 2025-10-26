use crate::common::bot_info::BotGender;
use serde::{Deserialize, Serialize};

pub trait BotContact {
    fn uin(&self) -> u64;
    fn uid(&self) -> &str;
    fn nickname(&self) -> &str;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotFriendCategory {
    pub category_id: u32,
    pub category_name: String,
    pub sort_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotFriend {
    pub uin: u64,
    pub uid: String,
    pub nickname: String,
    pub age: u32,
    pub gender: BotGender,
    pub remarks: String,
    pub personal_sign: String,
    pub qid: String,
    pub category: Option<BotFriendCategory>,
}

impl BotContact for BotFriend {
    fn uin(&self) -> u64 {
        self.uin
    }

    fn uid(&self) -> &str {
        &self.uid
    }

    fn nickname(&self) -> &str {
        &self.nickname
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotGroup {
    pub group_uin: u64,
    #[serde(default)]
    pub group_uid: String,
    pub group_name: String,
    pub member_count: u32,
    pub max_member: u32,
    pub create_time: i64,
    pub description: Option<String>,
    pub question: Option<String>,
    pub announcement: Option<String>,
}

impl BotContact for BotGroup {
    fn uin(&self) -> u64 {
        self.group_uin
    }

    fn uid(&self) -> &str {
        &self.group_uid
    }

    fn nickname(&self) -> &str {
        &self.group_name
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupMemberPermission {
    Member,
    Admin,
    Owner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotGroupMember {
    pub uin: u64,
    pub uid: String,
    pub nickname: String,
    pub group_uin: u64,
    pub permission: GroupMemberPermission,
    pub group_level: u32,
    pub member_card: Option<String>,
    pub special_title: Option<String>,
    pub age: u32,
    pub gender: BotGender,
    pub join_time: chrono::DateTime<chrono::Utc>,
    pub last_msg_time: chrono::DateTime<chrono::Utc>,
    pub shut_up_timestamp: chrono::DateTime<chrono::Utc>,
}

impl BotContact for BotGroupMember {
    fn uin(&self) -> u64 {
        self.uin
    }

    fn uid(&self) -> &str {
        &self.uid
    }

    fn nickname(&self) -> &str {
        &self.nickname
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotStranger {
    pub uin: u64,
    pub uid: String,
    pub nickname: String,
    pub age: u32,
    pub gender: BotGender,
}

impl BotContact for BotStranger {
    fn uin(&self) -> u64 {
        self.uin
    }

    fn uid(&self) -> &str {
        &self.uid
    }

    fn nickname(&self) -> &str {
        &self.nickname
    }
}
