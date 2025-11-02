use std::sync::Arc;
use crate::{BotContext, Error};
use crate::internal::services::{TransEmp31EventReq};

impl BotContext {
    pub async fn fetch_qrcode(self: &Arc<Self>) -> Result<Vec<u8>, Error> {
        let event = TransEmp31EventReq {
            unusual_sig: None
        };
        if let Err(e) = self.event.send_event(self.clone(), event).await {
            tracing::warn!(error = %e, "Failed to send fetch_qrcode");
        }

        Ok(vec![])
    }
}