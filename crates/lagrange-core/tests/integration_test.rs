use bytes::Bytes;
use lagrange_core::internal::services::{LoginCommand, LoginEventReq};
use lagrange_core::{config::BotConfig, keystore::BotKeystore, BotContext, Protocols};

#[tokio::test]
async fn test_bot_context_creation() {
    let config = BotConfig {
        protocol: Protocols::Linux,
        verbose: true,
        ..Default::default()
    };

    let keystore = BotKeystore::new().with_uin(123456);

    let bot = BotContext::builder()
        .config(config)
        .keystore(keystore)
        .build();

    assert_eq!(bot.bot_uin(), Some(123456));
    assert!(!bot.is_online());
}

#[tokio::test]
async fn test_cache_context() {
    let bot = BotContext::builder().build();

    bot.cache
        .cache_friends(vec![lagrange_core::internal::context::cache::Friend {
            uin: 123,
            uid: "user123".to_string(),
            nickname: "Test User".to_string(),
        }]);

    assert_eq!(bot.cache.resolve_uid(123), Some("user123".to_string()));
    assert_eq!(bot.cache.resolve_uin("user123"), Some(123));
}

#[tokio::test]
async fn test_packet_context() {
    let bot = BotContext::builder().build();

    let sequence = bot.packet.next_sequence();
    assert!(sequence > 0);

    let next_sequence = bot.packet.next_sequence();
    assert!(next_sequence > sequence);
}

#[tokio::test]
async fn test_socket_context() {
    let bot = BotContext::builder().build();

    assert!(!bot.socket.is_connected());

    bot.socket.set_connected(true);
    assert!(bot.socket.is_connected());

    let data = Bytes::from("test");
    assert!(bot.socket.send(data).is_ok());
}

#[tokio::test]
async fn test_event_context() {
    let bot = BotContext::builder().build();

    let mut receiver = bot.event.subscribe();

    let event = LoginEventReq {
        cmd: LoginCommand::Tgtgt,
        password: "test".to_string(),
        ticket: String::new(),
        code: String::new(),
    };

    bot.post(event);

    let received = receiver.try_recv();
    assert!(received.is_ok());
}

#[tokio::test]
async fn test_typed_event_subscription() {
    let bot = BotContext::builder().build();

    let mut typed_receiver = bot.event.subscribe_to::<LoginEventReq>();

    bot.post(LoginEventReq {
        cmd: LoginCommand::Tgtgt,
        password: "secure".to_string(),
        ticket: String::new(),
        code: String::new(),
    });

    let event = typed_receiver.try_recv();
    assert!(event.is_ok());

    if let Ok(login_event) = event {
        assert_eq!(login_event.password, "secure");
    }
}

#[test]
fn test_protocol_matching() {
    assert!(Protocols::Linux.matches(Protocols::ALL));
    assert!(Protocols::Windows.matches(Protocols::ALL));
    assert!(Protocols::AndroidPhone.matches(Protocols::ALL));

    assert!(Protocols::Linux.matches(Protocols::PC));
    assert!(Protocols::Windows.matches(Protocols::PC));
    assert!(Protocols::MacOs.matches(Protocols::PC));
    assert!(!Protocols::AndroidPhone.matches(Protocols::PC));

    assert!(Protocols::AndroidPhone.matches(Protocols::ANDROID));
    assert!(Protocols::AndroidPad.matches(Protocols::ANDROID));
    assert!(Protocols::AndroidWatch.matches(Protocols::ANDROID));
    assert!(!Protocols::Linux.matches(Protocols::ANDROID));

    assert!(Protocols::Linux.matches(Protocols::Linux as u8));
    assert!(!Protocols::Linux.matches(Protocols::Windows as u8));

    assert!(Protocols::Linux.is_desktop());
    assert!(Protocols::Windows.is_desktop());
    assert!(!Protocols::AndroidPhone.is_desktop());

    assert!(Protocols::AndroidPhone.is_android());
    assert!(!Protocols::Linux.is_android());
}

#[test]
fn test_service_metadata() {
    use lagrange_core::protocol::{RequestType, ServiceMetadata};

    let metadata = ServiceMetadata::new("test.command")
        .with_request_type(RequestType::Simple)
        .with_disable_log(true);

    assert_eq!(metadata.command, "test.command");
    assert_eq!(metadata.request_type, RequestType::Simple);
    assert!(metadata.disable_log);
}

#[tokio::test]
async fn test_service_registration() {
    use lagrange_core::internal::services::SsoPacket;

    // Create a bot context which initializes the ServiceContext
    let bot = BotContext::builder().build();

    // Create test packets with commands that should be registered
    let login_packet = SsoPacket::new(1, "wtlogin.login".to_string(), Bytes::from("test_data"));

    let message_packet = SsoPacket::new(
        2,
        "MessageSvc.PbSendMsg".to_string(),
        Bytes::from_static(&[0u8; 8]),
    );

    // These should not fail with ServiceNotFound because the services are registered via macro
    let login_result = bot
        .service
        .resolve_incoming(&login_packet, bot.clone())
        .await;
    let message_result = bot
        .service
        .resolve_incoming(&message_packet, bot.clone())
        .await;

    // Verify that services were found and parsed
    assert!(
        login_result.is_ok(),
        "LoginService should be registered via #[service] macro"
    );
    assert!(
        message_result.is_ok(),
        "SendMessageService should be registered via #[service] macro"
    );
}
