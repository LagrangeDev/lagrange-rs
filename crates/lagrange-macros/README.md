# lagrange-macros

Procedural macros for the lagrange-rs QQ protocol library.

## Macros

### `#[service]`

Automatically registers a service with the service registry and generates required boilerplate.

#### Features

- Automatically injects `metadata: ServiceMetadata` field
- Generates `Default` implementation with proper metadata initialization
- Registers service with the global service registry via `inventory`
- Supports metadata configuration through attributes

#### Syntax

```rust
#[service(
    command = "service.command.name",
    request_type = RequestType::Variant,  // Optional
    encrypt_type = EncryptType::Variant,  // Optional
    disable_log = true                     // Optional, defaults to false
)]
pub struct YourService {}
```

#### Attributes

- **`command`** (required): String literal specifying the service command name
- **`request_type`** (optional): Request type enum variant as a path
  - Must be a full path like `RequestType::D2Auth` or `RequestType::Simple`
  - Validated at compile time - invalid variants produce helpful errors
  - Valid variants: `D2Auth`, `Simple`
- **`encrypt_type`** (optional): Encrypt type enum variant as a path
  - Must be a full path like `EncryptType::EncryptEmpty` or `EncryptType::EncryptD2Key`
  - Validated at compile time - invalid variants produce helpful errors
  - Valid variants: `EncryptEmpty`, `EncryptD2Key`
- **`disable_log`** (optional): Boolean to disable logging for this service
  - Defaults to `false`

#### Examples

##### Basic service
```rust
#[service(command = "MessageSvc.PbSendMsg")]
pub struct SendMessageService {}
```

##### Service with request type
```rust
#[service(command = "wtlogin.login", request_type = RequestType::D2Auth)]
pub struct LoginService {}
```

##### Service with encrypt type
```rust
#[service(command = "wtlogin.trans_emp", encrypt_type = EncryptType::EncryptEmpty)]
pub struct TransEmpService {}
```

##### Service with disabled logging
```rust
#[service(command = "MessageSvc.PbSendMsg", disable_log = true)]
pub struct SendMessageService {}
```

##### Service with all options
```rust
#[service(
    command = "wtlogin.login",
    request_type = RequestType::D2Auth,
    encrypt_type = EncryptType::EncryptD2Key,
    disable_log = false
)]
pub struct LoginService {}
```

#### What the macro generates

For a service definition like:
```rust
#[service(
    command = "wtlogin.login",
    request_type = RequestType::D2Auth,
    encrypt_type = EncryptType::EncryptD2Key
)]
pub struct LoginService {}
```

The macro expands to:
```rust
pub struct LoginService {
    metadata: crate::protocol::ServiceMetadata  // Injected field
}

#[automatically_derived]
impl Default for LoginService {
    fn default() -> Self {
        Self {
            metadata: crate::protocol::ServiceMetadata::new("wtlogin.login")
                .with_request_type(RequestType::D2Auth)
                .with_encrypt_type(EncryptType::EncryptD2Key)
        }
    }
}

inventory::submit! {
    crate::internal::service::ServiceRegistration {
        command: "wtlogin.login",
        factory: || Box::new(LoginService::default()),
    }
}
```

---

### `#[event_subscribe]`

Registers an event handler for a specific event type with optional protocol filtering.

#### Syntax

```rust
#[event_subscribe(EventType, protocol = ProtocolPath)]  // protocol is optional
pub struct YourEventHandler;
```

#### Attributes

- **Event type** (required): First argument, the type of event to subscribe to
- **`protocol`** (optional): Path to a protocol filter (strongly typed)
  - Individual protocols: `Protocols::Linux`, `Protocols::Windows`, `Protocols::MacOs`,
    `Protocols::AndroidPhone`, `Protocols::AndroidPad`, `Protocols::AndroidWatch`
  - Protocol groups: `Protocols::PC` (Windows/MacOs/Linux), `Protocols::ANDROID` (all Android variants), `Protocols::ALL`
  - Defaults to `Protocols::ALL` if not specified
  - Provides compile-time type checking and IDE autocomplete

#### Examples

##### Subscribe to all protocols
```rust
#[event_subscribe(LoginEvent)]
pub struct LoginEventHandler;
```

##### Subscribe to specific protocol
```rust
#[event_subscribe(LoginEvent, protocol = Protocols::Linux)]
pub struct LinuxLoginHandler;
```

##### Subscribe to PC platforms only
```rust
#[event_subscribe(MessageEvent, protocol = Protocols::PC)]
pub struct PcMessageHandler;
```

#### What the macro generates

For an event subscription like:
```rust
#[event_subscribe(LoginEvent, protocol = Protocols::Linux)]
pub struct LoginEventHandler;
```

The macro expands to:
```rust
pub struct LoginEventHandler;

inventory::submit! {
    crate::internal::service::EventSubscription {
        event_type: std::any::TypeId::of::<LoginEvent>(),
        protocol_mask: (Protocols::Linux) as u8,
        handler: |ctx, event| {
            Box::pin(async move {
                let service = LoginEventHandler;
                service.handle(ctx, event).await
            })
        },
    }
}
```

## Implementation Requirements

### For `#[service]`

Your service struct must:
1. Be a struct with named fields (even if empty: `struct Name {}`)
2. Implement the `Service` trait or `BaseService` trait
3. Implement a `metadata()` method that returns `&ServiceMetadata`

Example:
```rust
#[service(command = "test.command")]
pub struct TestService {}

#[async_trait]
impl BaseService for TestService {
    type Request = TestRequest;
    type Response = TestResponse;

    async fn parse_impl(&self, input: Bytes, context: Arc<BotContext>) -> Result<Self::Response> {
        // Implementation
    }

    async fn build_impl(&self, input: Self::Request, context: Arc<BotContext>) -> Result<Bytes> {
        // Implementation
    }

    fn metadata(&self) -> &ServiceMetadata {
        &self.metadata  // Field injected by macro
    }
}
```

### For `#[event_subscribe]`

Your event handler must:
1. Implement an async `handle()` method with signature:
   ```rust
   async fn handle(&self, ctx: Arc<BotContext>, event: EventMessage) -> Result<Bytes>
   ```

## Error Messages

The macros provide helpful error messages for common mistakes:

- **Missing `command` attribute**: "service macro requires 'command' attribute"
- **Unknown attribute**: "Unknown attribute '{attribute}'. Valid attributes: command, request_type, encrypt_type, disable_log"
- **Tuple/unit structs**: "service macro only supports structs with named fields (e.g., `struct Name {}`)"
- **Invalid RequestType variant**: "Invalid RequestType variant '{variant}'. Valid variants: D2Auth, Simple"
- **Invalid EncryptType variant**: "Invalid EncryptType variant '{variant}'. Valid variants: EncryptEmpty, EncryptD2Key"
- **Invalid protocol path**: "Invalid path for protocol: path cannot be empty"

## How It Works

Both macros use the `inventory` crate to collect registrations at compile time:

1. The macro generates an `inventory::submit!` call for each annotated struct
2. At runtime, the `ServiceContext` or `EventContext` iterates over collected registrations
3. Services/handlers are instantiated and stored for later use

This approach allows for compile-time service discovery without runtime reflection.

## Dependencies

Required in your `Cargo.toml`:
```toml
[dependencies]
lagrange-macros = { path = "crates/lagrange-macros" }
inventory = "0.3"
async-trait = "0.1"
```
