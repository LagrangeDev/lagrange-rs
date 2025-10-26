#[allow(unused_imports)]
use crate::{context::BotContext, error::Result};
#[allow(unused_imports)]
use bytes::Bytes;
use lagrange_macros::define_service;
#[allow(unused_imports)]
use std::sync::Arc;

define_service! {
    SendMessageService: "MessageSvc.PbSendMsg" {
        disable_log: true,

        request SendMessageEvent {
            target: u64,
            content: String,
            is_group: bool,
        }

        response SendMessageResponse {
            message_id: u64,
            time: i64,
            success: bool,
        }

        async fn parse(input: Bytes, context: Arc<BotContext>) -> Result<SendMessageResponse> {
            context.log_debug(&format!("Parsing send message response: {} bytes", input.len()));

            let message_id = u64::from_le_bytes(
                input
                    .get(0..8)
                    .and_then(|b| b.try_into().ok())
                    .unwrap_or([0u8; 8]),
            );

            let time = chrono::Utc::now().timestamp();

            Ok(SendMessageResponse {
                message_id,
                time,
                success: true,
            })
        }

        async fn build(input: SendMessageEvent, context: Arc<BotContext>) -> Result<Bytes> {
            let msg_type = if input.is_group { "group" } else { "friend" };
            context.log_debug(&format!(
                "Building {} message to {}: {}",
                msg_type, input.target, input.content
            ));

            let data = format!(
                "{{\"target\":{},\"content\":\"{}\",\"is_group\":{}}}",
                input.target, input.content, input.is_group
            );

            Ok(Bytes::from(data))
        }
    }
}
