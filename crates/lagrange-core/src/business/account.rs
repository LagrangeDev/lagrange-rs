use std::sync::Arc;
use crate::{BotContext, Error};
use crate::internal::services::login::{TransEmp31EventReq, TransEmpService, TransEmpServiceRequest, TransEmpServiceResponse};

impl BotContext {
    pub async fn fetch_qrcode(self: &Arc<Self>) -> Result<String, Error> {
        let event = TransEmpServiceRequest::TransEmp31Event(TransEmp31EventReq {
            unusual_sig: None
        });
        let response = self.event.send::<TransEmpService>(event, self.clone()).await?;

        match response {
            TransEmpServiceResponse::TransEmp31Event(resp) => Ok(resp.qr_url),
            _ => Err(Error::ParseError(
                "Expected TransEmp31Event response but got different variant".to_string()
            ))
        }
    }
}