use std::sync::Arc;

use bytes::Bytes;
use lagrange_macros::define_service;

use crate::{
    context::BotContext,
    protocol::{EncryptType, EventMessage, Protocols, RequestType},
};

define_service! {
    AliveService {
        command: "Heartbeat.Alive",
        request_type: RequestType::Simple,
        encrypt_type: EncryptType::NoEncrypt,
        disable_log: true,

        events {
            AliveEvent(protocol = Protocols::ALL) {
                request AliveEventReq {}
                response AliveEventResp {}
            }
        }

        async fn parse(_input: Bytes, _context: Arc<BotContext>) -> Result<EventMessage> {
            Ok(EventMessage::new(AliveEventResp {}))
        }

        async fn build(_event: EventMessage, _context: Arc<BotContext>) -> Result<Bytes> {
            const HEARTBEAT_BUFFER: &[u8] = &[0x00, 0x00, 0x00, 0x04];
            Ok(Bytes::from_static(HEARTBEAT_BUFFER))
        }
    }
}
