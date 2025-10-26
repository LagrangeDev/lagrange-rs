use dashmap::DashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Friend {
    pub uin: u64,
    pub uid: String,
    pub nickname: String,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub group_id: u64,
    pub group_name: String,
}

#[derive(Debug, Clone)]
pub struct GroupMember {
    pub uin: u64,
    pub uid: String,
    pub nickname: String,
    pub card: String,
}

pub struct CacheContext {
    friends: std::sync::RwLock<Option<Vec<Friend>>>,

    groups: std::sync::RwLock<Option<Vec<Group>>>,

    members: DashMap<u64, Vec<GroupMember>>,

    uin_to_uid: DashMap<u64, String>,

    uid_to_uin: DashMap<String, u64>,
}

impl CacheContext {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            friends: std::sync::RwLock::new(None),
            groups: std::sync::RwLock::new(None),
            members: DashMap::new(),
            uin_to_uid: DashMap::new(),
            uid_to_uin: DashMap::new(),
        })
    }

    pub fn get_friends(&self) -> Option<Vec<Friend>> {
        self.friends.read().expect("RwLock poisoned").clone()
    }

    pub fn cache_friends(&self, friends: Vec<Friend>) {
        for friend in &friends {
            self.uin_to_uid.insert(friend.uin, friend.uid.clone());
            self.uid_to_uin.insert(friend.uid.clone(), friend.uin);
        }
        *self.friends.write().expect("RwLock poisoned") = Some(friends);
    }

    pub fn get_groups(&self) -> Option<Vec<Group>> {
        self.groups.read().expect("RwLock poisoned").clone()
    }

    pub fn cache_groups(&self, groups: Vec<Group>) {
        *self.groups.write().expect("RwLock poisoned") = Some(groups);
    }

    pub fn get_members(&self, group_id: u64) -> Option<Vec<GroupMember>> {
        self.members.get(&group_id).map(|v| v.clone())
    }

    pub fn cache_members(&self, group_id: u64, members: Vec<GroupMember>) {
        for member in &members {
            self.uin_to_uid.insert(member.uin, member.uid.clone());
            self.uid_to_uin.insert(member.uid.clone(), member.uin);
        }
        self.members.insert(group_id, members);
    }

    pub fn resolve_uid(&self, uin: u64) -> Option<String> {
        self.uin_to_uid.get(&uin).map(|v| v.clone())
    }

    pub fn resolve_uin(&self, uid: &str) -> Option<u64> {
        self.uid_to_uin.get(uid).map(|v| *v)
    }

    pub fn clear(&self) {
        *self.friends.write().expect("RwLock poisoned") = None;
        *self.groups.write().expect("RwLock poisoned") = None;
        self.members.clear();
        self.uin_to_uid.clear();
        self.uid_to_uin.clear();
    }
}

impl Default for CacheContext {
    fn default() -> Self {
        Self {
            friends: std::sync::RwLock::new(None),
            groups: std::sync::RwLock::new(None),
            members: DashMap::new(),
            uin_to_uid: DashMap::new(),
            uid_to_uin: DashMap::new(),
        }
    }
}
