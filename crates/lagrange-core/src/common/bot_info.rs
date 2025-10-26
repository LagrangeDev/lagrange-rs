use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BotGender {
    Unset = 0,
    Male = 1,
    Female = 2,
    Unknown = 255,
}

impl Default for BotGender {
    fn default() -> Self {
        Self::Unset
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotInfo {
    pub age: u8,
    pub gender: BotGender,
    pub name: String,
}

impl BotInfo {
    pub fn new(age: u8, gender: BotGender, name: String) -> Self {
        Self { age, gender, name }
    }
}

impl std::fmt::Display for BotInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Bot name: {} | Gender: {:?} | Age: {}",
            self.name, self.gender, self.age
        )
    }
}
