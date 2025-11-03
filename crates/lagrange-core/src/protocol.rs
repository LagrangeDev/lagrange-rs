#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum Protocols {
    None = 0b00000000,
    Windows = 0b00000001,
    MacOs = 0b00000010,
    Linux = 0b00000100,
    AndroidPhone = 0b00001000,
    AndroidPad = 0b00010000,
    AndroidWatch = 0b00100000,
}

impl Protocols {
    pub const PC: u8 = Self::Windows as u8 | Self::MacOs as u8 | Self::Linux as u8;

    pub const ANDROID: u8 =
        Self::AndroidPhone as u8 | Self::AndroidPad as u8 | Self::AndroidWatch as u8;

    pub const ALL: u8 = Self::PC | Self::ANDROID;

    pub fn matches(&self, mask: u8) -> bool {
        (*self as u8) & mask != 0
    }

    pub fn is_desktop(&self) -> bool {
        self.matches(Self::PC)
    }

    pub fn is_android(&self) -> bool {
        self.matches(Self::ANDROID)
    }

    pub const fn default() -> Self {
        Self::Linux
    }
}

impl Default for Protocols {
    fn default() -> Self {
        Self::Linux
    }
}

pub trait ProtocolEvent: Send + Sync + 'static {
    fn event_type(&self) -> &'static str {
        std::any::type_name::<Self>()
    }
}

/// Type-safe service trait with compile-time checked request/response pairs.
///
/// This trait defines a service that can build outgoing packets from requests
/// and parse incoming packets into responses. The associated types ensure that
/// request and response types are checked at compile time.
///
/// # Type Parameters
///
/// - `Request`: The request event type that this service accepts
/// - `Response`: The response event type that this service produces
///
/// # Example
///
/// ```ignore
/// struct HeartbeatService;
///
/// impl TypedService for HeartbeatService {
///     type Request = HeartbeatReq;
///     type Response = HeartbeatResp;
///
///     fn metadata(&self) -> &ServiceMetadata {
///         static METADATA: ServiceMetadata = ServiceMetadata {
///             command: "trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat",
///             request_type: RequestType::Simple,
///             encrypt_type: EncryptType::EncryptD2Key,
///             disable_log: false,
///         };
///         &METADATA
///     }
///
///     async fn build(&self, request: &Self::Request, context: std::sync::Arc<crate::context::BotContext>) -> crate::Result<bytes::Bytes> {
///         // Serialize request into packet bytes
///         todo!()
///     }
///
///     async fn parse(&self, bytes: bytes::Bytes, context: std::sync::Arc<crate::context::BotContext>) -> crate::Result<Self::Response> {
///         // Parse packet bytes into response
///         todo!()
///     }
/// }
/// ```
#[async_trait::async_trait]
pub trait TypedService: Send + Sync + 'static {
    /// The request event type for this service.
    type Request: ProtocolEvent;

    /// The response event type for this service.
    type Response: ProtocolEvent;

    /// Returns the metadata for this service, including command name and encryption settings.
    fn metadata(&self) -> &ServiceMetadata;

    /// Builds an outgoing packet from a request event.
    ///
    /// This method serializes the request into bytes that can be sent over the network.
    ///
    /// # Arguments
    ///
    /// * `request` - The request event to serialize
    /// * `context` - The bot context containing state and configuration
    ///
    /// # Returns
    ///
    /// The serialized packet bytes, or an error if serialization fails.
    async fn build(
        &self,
        request: &Self::Request,
        context: std::sync::Arc<crate::context::BotContext>,
    ) -> crate::Result<bytes::Bytes>;

    /// Parses an incoming packet into a response event.
    ///
    /// This method deserializes the packet bytes into a typed response.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The packet bytes to parse
    /// * `context` - The bot context containing state and configuration
    ///
    /// # Returns
    ///
    /// The parsed response event, or an error if parsing fails.
    async fn parse(
        &self,
        bytes: bytes::Bytes,
        context: std::sync::Arc<crate::context::BotContext>,
    ) -> crate::Result<Self::Response>;
}

#[derive(Clone)]
pub struct EventMessage {
    type_id: std::any::TypeId,

    payload: std::sync::Arc<dyn std::any::Any + Send + Sync>,
}

impl EventMessage {
    pub fn new<T: ProtocolEvent>(event: T) -> Self {
        Self {
            type_id: std::any::TypeId::of::<T>(),
            payload: std::sync::Arc::new(event),
        }
    }

    pub fn type_id(&self) -> std::any::TypeId {
        self.type_id
    }

    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.payload.downcast_ref::<T>()
    }

    pub fn downcast<T: 'static>(&self) -> Option<std::sync::Arc<T>> {
        if self.type_id == std::any::TypeId::of::<T>() {
            let ptr = std::sync::Arc::as_ptr(&self.payload);
            let typed_ptr = ptr as *const T;
            unsafe {
                std::sync::Arc::increment_strong_count(typed_ptr);
                Some(std::sync::Arc::from_raw(typed_ptr))
            }
        } else {
            None
        }
    }
}

impl std::fmt::Debug for EventMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventMessage")
            .field("type_id", &self.type_id)
            .finish()
    }
}

/// Request type for services commands.
///
/// Specifies how the services request should be handled by the protocol layer.
///
/// # Usage in `define_service!`
///
/// ```ignore
/// define_service! {
///     MyService: "my.command" {
///         request_type: RequestType::D2Auth,  // or RequestType::Simple
///         // ...
///     }
/// }
/// ```
///
/// # Variants
///
/// - `D2Auth`: Use D2 authentication (default, most common)
/// - `Simple`: Use simple request handling (for basic commands)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestType {
    /// Use D2 authentication for the request.
    ///
    /// This is the default and most commonly used request type for authenticated operations.
    D2Auth = 0x0C,

    /// Use simple request handling.
    ///
    /// Used for basic commands that don't require full D2 authentication.
    Simple = 0x0D,
}

impl RequestType {
    /// Returns all available request type variants.
    ///
    /// Useful for validation and tooling.
    #[inline]
    pub const fn variants() -> &'static [RequestType] {
        &[RequestType::D2Auth, RequestType::Simple]
    }

    /// Returns the string representation of this request type.
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            RequestType::D2Auth => "D2Auth",
            RequestType::Simple => "Simple",
        }
    }
}

impl Default for RequestType {
    #[inline]
    fn default() -> Self {
        RequestType::D2Auth
    }
}

/// Encryption type for services commands.
///
/// Specifies how the services data should be encrypted.
///
/// # Usage in `define_service!`
///
/// ```ignore
/// define_service! {
///     MyService: "my.command" {
///         encrypt_type: EncryptType::EncryptD2Key,  // or EncryptType::EncryptEmpty
///         // ...
///     }
/// }
/// ```
///
/// # Variants
///
/// - `NoEncrypt`: No encryption at all
/// - `EncryptEmpty`: Encrypt with empty key
/// - `EncryptD2Key`: Encrypt with D2 key (default, for secure commands)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EncryptType {
    /// No encryption at all.
    NoEncrypt = 0x00,

    /// Encrypt using the D2 key.
    ///
    /// This is the default and should be used for most secure communications.
    EncryptD2Key = 0x01,

    /// Encrypt with empty key.
    ///
    /// Used for commands that don't contain sensitive data.
    EncryptEmpty = 0x02,
}

impl EncryptType {
    /// Returns all available encryption type variants.
    ///
    /// Useful for validation and tooling.
    #[inline]
    pub const fn variants() -> &'static [EncryptType] {
        &[EncryptType::NoEncrypt, EncryptType::EncryptD2Key, EncryptType::EncryptEmpty]
    }

    /// Returns the string representation of this encryption type.
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            EncryptType::NoEncrypt => "NoEncrypt",
            EncryptType::EncryptEmpty => "EncryptEmpty",
            EncryptType::EncryptD2Key => "EncryptD2Key",
        }
    }
}

impl Default for EncryptType {
    #[inline]
    fn default() -> Self {
        EncryptType::EncryptD2Key
    }
}

#[derive(Debug, Clone)]
pub struct ServiceMetadata {
    pub command: &'static str,
    pub request_type: RequestType,
    pub encrypt_type: EncryptType,
    pub disable_log: bool,
}

impl ServiceMetadata {
    pub fn new(command: &'static str) -> Self {
        Self {
            command,
            request_type: RequestType::D2Auth,
            encrypt_type: EncryptType::EncryptD2Key,
            disable_log: false,
        }
    }

    pub fn with_request_type(mut self, request_type: RequestType) -> Self {
        self.request_type = request_type;
        self
    }

    pub fn with_encrypt_type(mut self, encrypt_type: EncryptType) -> Self {
        self.encrypt_type = encrypt_type;
        self
    }

    pub fn with_disable_log(mut self, disable: bool) -> Self {
        self.disable_log = disable;
        self
    }
}
