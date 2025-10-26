use crate::protocol::EncryptType;
use crate::{context::BotContext, protocol::RequestType};
use bytes::Bytes;
use lagrange_macros::define_service;
use std::sync::Arc;

define_service! {
    LoginService: "wtlogin.login" {
        request_type: RequestType::D2Auth,
        encrypt_type: EncryptType::EncryptEmpty,

        request LoginEvent {
            uin: u64,
            password: String,
        }

        response LoginResponse {
            success: bool,
            message: String,
        }

        async fn parse(input: Bytes, context: Arc<BotContext>) -> Result<LoginResponse> {
            context.log_debug(&format!("Parsing login response: {} bytes", input.len()));

            let success = !input.is_empty();
            let message = if success {
                "Login successful".to_string()
            } else {
                "Login failed".to_string()
            };

            Ok(LoginResponse { success, message })
        }

        async fn build(input: LoginEvent, context: Arc<BotContext>) -> Result<Bytes> {
            context.log_debug(&format!("Building login request for UIN: {}", input.uin));

            let data = format!("{}:{}", input.uin, input.password);
            Ok(Bytes::from(data))
        }
    }
}
