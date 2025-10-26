use crate::{
    common::AppInfo,
    keystore::BotKeystore,
};

/// Base trait for packet struct builders
/// Provides access to keystore and app info
pub trait StructBase {
    fn keystore(&self) -> &BotKeystore;
    fn app_info(&self) -> &AppInfo;
}
