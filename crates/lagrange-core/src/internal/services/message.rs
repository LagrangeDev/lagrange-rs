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

        service {
            async fn parse(input: Bytes, context: Arc<BotContext>) -> Result<SendMessageResponse> {
                tracing::debug!(
                    bytes = input.len(),
                    "Parsing send message response"
                );

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
                tracing::debug!(
                    target = input.target,
                    content = %input.content,
                    is_group = input.is_group,
                    "Building message"
                );

                let data = format!(
                    "{{\"target\":{},\"content\":\"{}\",\"is_group\":{}}}",
                    input.target, input.content, input.is_group
                );

                Ok(Bytes::from(data))
            }
        }
    }
}
