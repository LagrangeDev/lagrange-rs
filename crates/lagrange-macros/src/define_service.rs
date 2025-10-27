use proc_macro::TokenStream;
use quote::quote;
use syn::{
    braced,
    parse::{Parse, ParseStream},
    parse_macro_input,
    spanned::Spanned,
    Block, Expr, Ident, LitBool, LitStr, Path, ReturnType, Signature, Token, Type,
};
use crate::utils::{suggest_closest_match, validate_path_structure};

/// Validate that a protocol expression is valid and extract the constant name
/// Expects expressions like `Protocols::PC`, `Protocols::ANDROID`, etc.
/// Returns the constant name (e.g., "PC", "ANDROID")
fn validate_and_extract_protocol(expr: &Expr) -> syn::Result<String> {
    const VALID_PROTOCOLS: &[&str] = &[
        // Bit mask constants
        "PC",
        "ANDROID",
        "ALL",
        // Individual variants
        "Windows",
        "MacOs",
        "Linux",
        "AndroidPhone",
        "AndroidPad",
        "AndroidWatch",
    ];

    // Expression should be a path like Protocols::PC
    if let Expr::Path(expr_path) = expr {
        let path = &expr_path.path;

        // Validate it's of the form Protocols::X
        if path.segments.len() == 2 {
            let first_segment = &path.segments[0];
            let second_segment = &path.segments[1];

            if first_segment.ident == "Protocols" {
                let constant_name = second_segment.ident.to_string();

                if VALID_PROTOCOLS.contains(&constant_name.as_str()) {
                    return Ok(constant_name);
                }

                let mut error_msg = format!(
                    "Invalid protocol constant: 'Protocols::{}'\n\nValid protocol constants are:\n\nBit masks:\n  - Protocols::PC\n  - Protocols::ANDROID\n  - Protocols::ALL\n\nIndividual variants:\n  - Protocols::Windows\n  - Protocols::MacOs\n  - Protocols::Linux\n  - Protocols::AndroidPhone\n  - Protocols::AndroidPad\n  - Protocols::AndroidWatch",
                    constant_name
                );

                if let Some(suggestion) = suggest_closest_match(&constant_name, VALID_PROTOCOLS) {
                    error_msg.push_str(&format!("\n\nDid you mean 'Protocols::{}'?", suggestion));
                }

                return Err(syn::Error::new(expr.span(), error_msg));
            }
        }
    }

    Err(syn::Error::new(
        expr.span(),
        "Protocol must be specified as Protocols::CONSTANT\n\nExamples:\n  - Protocols::PC\n  - Protocols::ANDROID\n  - Protocols::ALL\n  - Protocols::Windows"
    ))
}

/// Struct field definition for services! macro
struct ServiceField {
    name: Ident,
    ty: Type,
}

/// Function definition with full signature for IDE support
struct ServiceFunction {
    signature: Signature,
    body: Block,
}

/// Protocol handler containing protocol filter and parse/build functions
struct ProtocolHandler {
    protocol_expr: Option<Expr>, // The full expression like Protocols::PC (for code gen)
    protocol_suffix: Option<String>, // The extracted constant name like "PC" (for naming)
    parse_fn: ServiceFunction,
    build_fn: ServiceFunction,
}

impl ServiceFunction {
    fn parse_with_name(input: ParseStream, expected_name: &str) -> syn::Result<Self> {
        // Parse: async fn name(params) -> ReturnType { body }
        input.parse::<Token![async]>()?;
        input.parse::<Token![fn]>()?;

        let fn_name: Ident = input.parse()?;
        if fn_name != expected_name {
            return Err(syn::Error::new(
                fn_name.span(),
                format!(
                    "Expected function name '{}', found '{}'",
                    expected_name, fn_name
                ),
            ));
        }

        // Parse full signature (parameters and return type)
        let content;
        syn::parenthesized!(content in input);

        let mut inputs = syn::punctuated::Punctuated::new();
        while !content.is_empty() {
            inputs.push_value(content.parse()?);
            if content.peek(Token![,]) {
                inputs.push_punct(content.parse()?);
            } else {
                break;
            }
        }

        let output: ReturnType = input.parse()?;

        let signature = Signature {
            constness: None,
            asyncness: Some(Default::default()),
            unsafety: None,
            abi: None,
            fn_token: Default::default(),
            ident: fn_name,
            generics: Default::default(),
            paren_token: Default::default(),
            inputs,
            variadic: None,
            output,
        };

        let body: Block = input.parse()?;

        Ok(ServiceFunction { signature, body })
    }
}

impl Parse for ServiceField {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let name: Ident = input.parse()?;
        input.parse::<Token![:]>()?;
        let ty: Type = input.parse()?;

        // Optional trailing comma
        let _ = input.parse::<Token![,]>();

        Ok(ServiceField { name, ty })
    }
}

/// Arguments for the unified services! macro
struct UnifiedServiceArgs {
    service_name: Ident,
    command: String,
    request_type: Option<Path>,
    encrypt_type: Option<Path>,
    disable_log: bool,
    request_name: Ident,
    request_fields: Vec<ServiceField>,
    response_name: Ident,
    response_fields: Vec<ServiceField>,
    handlers: Vec<ProtocolHandler>,
}

impl Parse for UnifiedServiceArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Parse: ServiceName: "command" {
        let service_name: Ident = input.parse()?;
        input.parse::<Token![:]>()?;
        let command: LitStr = input.parse()?;

        let content;
        braced!(content in input);

        // Parse optional metadata fields
        let mut request_type = None;
        let mut encrypt_type = None;
        let mut disable_log = false;

        // Parse metadata and blocks
        let mut request_name = None;
        let mut request_fields = Vec::new();
        let mut response_name = None;
        let mut response_fields = Vec::new();
        let mut handlers = Vec::new();

        while !content.is_empty() {
            let lookahead = content.lookahead1();

            if lookahead.peek(Ident) {
                let key: Ident = content.parse()?;

                if key == "request_type" {
                    content.parse::<Token![:]>()?;
                    let path: Path = content.parse()?;
                    validate_path_structure(&path, "request_type")?;
                    request_type = Some(path);
                    let _ = content.parse::<Token![,]>();
                } else if key == "encrypt_type" {
                    content.parse::<Token![:]>()?;
                    let path: Path = content.parse()?;
                    validate_path_structure(&path, "encrypt_type")?;
                    encrypt_type = Some(path);
                    let _ = content.parse::<Token![,]>();
                } else if key == "disable_log" {
                    content.parse::<Token![:]>()?;
                    let value: LitBool = content.parse()?;
                    disable_log = value.value;
                    let _ = content.parse::<Token![,]>();
                } else if key == "request" {
                    // Parse: request RequestName { fields }
                    let name: Ident = content.parse()?;
                    let fields_content;
                    braced!(fields_content in content);

                    let mut fields = Vec::new();
                    while !fields_content.is_empty() {
                        fields.push(fields_content.parse()?);
                    }

                    request_name = Some(name);
                    request_fields = fields;
                } else if key == "response" {
                    // Parse: response ResponseName { fields }
                    let name: Ident = content.parse()?;
                    let fields_content;
                    braced!(fields_content in content);

                    let mut fields = Vec::new();
                    while !fields_content.is_empty() {
                        fields.push(fields_content.parse()?);
                    }

                    response_name = Some(name);
                    response_fields = fields;
                } else if key == "service" {
                    // Parse: service {} or service(protocol = Protocols::PC) {}
                    let (protocol_expr, protocol_suffix) = if content.peek(syn::token::Paren) {
                        // Parse (protocol = Protocols::PC)
                        let protocol_content;
                        syn::parenthesized!(protocol_content in content);

                        let protocol_key: Ident = protocol_content.parse()?;
                        if protocol_key != "protocol" {
                            return Err(syn::Error::new(
                                protocol_key.span(),
                                "Expected 'protocol' parameter",
                            ));
                        }

                        protocol_content.parse::<Token![=]>()?;
                        let protocol_expr: Expr = protocol_content.parse()?;

                        // Validate the protocol expression and extract the suffix
                        let suffix = validate_and_extract_protocol(&protocol_expr)?;

                        (Some(protocol_expr), Some(suffix))
                    } else {
                        // No parameters, defaults to Protocols::ALL
                        (None, None)
                    };

                    // Parse service block containing parse and build functions
                    let service_content;
                    braced!(service_content in content);

                    let mut parse_fn = None;
                    let mut build_fn = None;

                    while !service_content.is_empty() {
                        let fork = service_content.fork();
                        fork.parse::<Token![async]>()?;
                        fork.parse::<Token![fn]>()?;
                        let fn_name: Ident = fork.parse()?;

                        if fn_name == "parse" {
                            parse_fn =
                                Some(ServiceFunction::parse_with_name(&service_content, "parse")?);
                        } else if fn_name == "build" {
                            build_fn =
                                Some(ServiceFunction::parse_with_name(&service_content, "build")?);
                        } else {
                            return Err(syn::Error::new(
                                fn_name.span(),
                                "Expected 'parse' or 'build' function in service block",
                            ));
                        }
                    }

                    let parse_fn = parse_fn.ok_or_else(|| {
                        syn::Error::new(key.span(), "Missing 'parse' function in service block")
                    })?;

                    let build_fn = build_fn.ok_or_else(|| {
                        syn::Error::new(key.span(), "Missing 'build' function in service block")
                    })?;

                    handlers.push(ProtocolHandler {
                        protocol_expr,
                        protocol_suffix,
                        parse_fn,
                        build_fn,
                    });
                } else {
                    // Unknown key - provide helpful suggestions
                    let valid_keys = &[
                        "request_type",
                        "encrypt_type",
                        "disable_log",
                        "request",
                        "response",
                        "service",
                    ];
                    let key_str = key.to_string();
                    let mut error_msg = format!("Unknown key: '{}'\n\nValid keys are:\n  - request_type: RequestType\n  - encrypt_type: EncryptType\n  - disable_log: bool\n  - request <Name> {{ fields }}\n  - response <Name> {{ fields }}", key_str);

                    if let Some(suggestion) = suggest_closest_match(&key_str, valid_keys) {
                        error_msg.push_str(&format!("\n\nDid you mean '{}'?", suggestion));
                    }

                    return Err(syn::Error::new(key.span(), error_msg));
                }
            } else {
                return Err(lookahead.error());
            }
        }

        // Validate required fields with detailed error messages
        let request_name = request_name.ok_or_else(|| {
            syn::Error::new(
                input.span(),
                "Missing 'request' block\n\nExpected syntax:\n  request RequestEventName {\n    field_name: Type,\n    // ...\n  }"
            )
        })?;
        let response_name = response_name.ok_or_else(|| {
            syn::Error::new(
                input.span(),
                "Missing 'response' block\n\nExpected syntax:\n  response ResponseEventName {\n    field_name: Type,\n    // ...\n  }"
            )
        })?;

        if handlers.is_empty() {
            return Err(syn::Error::new(
                input.span(),
                "Missing service block\n\nExpected syntax:\n  service {\n    async fn parse(input: Bytes, context: Arc<BotContext>) -> Result<ResponseEventName> { ... }\n    async fn build(input: RequestEventName, context: Arc<BotContext>) -> Result<Bytes> { ... }\n  }\n\nOr for protocol-specific services:\n  service(protocol = PC) { ... }\n  service(protocol = ANDROID) { ... }\n  service(protocol = Windows) { ... }"
            ));
        }

        Ok(UnifiedServiceArgs {
            service_name,
            command: command.value(),
            request_type,
            encrypt_type,
            disable_log,
            request_name,
            request_fields,
            response_name,
            response_fields,
            handlers,
        })
    }
}

/// Defines a service with request/response types and protocol handling.
///
/// This macro generates a complete service implementation including:
/// - Request and Response event structs with constructors, getters, and builders
/// - Service struct with BaseService trait implementation
/// - Automatic service registration via inventory
/// - Proper documentation for all generated types
/// - Type aliases for better IDE support
///
/// # Syntax
///
/// ```ignore
/// define_service! {
///     ServiceName: "command.string" {
///         // Optional: Specify request type (default: RequestType::D2Auth)
///         request_type: RequestType::D2Auth,  // or RequestType::Simple
///
///         // Optional: Specify encryption type (default: EncryptType::EncryptD2Key)
///         encrypt_type: EncryptType::EncryptEmpty,  // or EncryptType::EncryptD2Key
///
///         // Optional: Disable logging for this service (default: false)
///         disable_log: true,
///
///         // Required: Define the request event structure
///         request RequestEventName {
///             field_name: Type,
///             another_field: AnotherType,
///         }
///
///         // Required: Define the response event structure
///         response ResponseEventName {
///             result_field: Type,
///             status: bool,
///         }
///
///         // Required: Define service handlers (can have multiple for different protocols)
///         service {
///             // Parse incoming bytes into a response
///             // Signature: async fn parse(bytes: Bytes, context: Arc<BotContext>) -> Result<Response>
///             // Parameter names can be anything, but types must match exactly
///             async fn parse(input: Bytes, context: Arc<BotContext>) -> Result<ResponseEventName> {
///                 // Parse logic here
///                 Ok(ResponseEventName::new(/* ... */))
///             }
///
///             // Build outgoing bytes from a request
///             // Signature: async fn build(request: Request, context: Arc<BotContext>) -> Result<Bytes>
///             // Parameter names can be anything, but types must match exactly
///             async fn build(req: RequestEventName, ctx: Arc<BotContext>) -> Result<Bytes> {
///                 // Build logic here
///                 Ok(Bytes::from(data))
///             }
///         }
///
///         // Optional: Protocol-specific handlers
///         service(protocol = Protocols::PC) {
///             async fn parse(input: Bytes, context: Arc<BotContext>) -> Result<ResponseEventName> { /* ... */ }
///             async fn build(req: RequestEventName, ctx: Arc<BotContext>) -> Result<Bytes> { /* ... */ }
///         }
///     }
/// }
/// ```
///
/// # Function Signatures (IDE Reference)
///
/// When implementing `parse` and `build` functions, use these signatures.
/// **Parameter names are flexible** - you can use any names you want!
///
/// ```ignore
/// // Parse function - convert incoming bytes to response
/// async fn parse(
///     data: Bytes,              // or: input, bytes, packet, etc.
///     ctx: Arc<BotContext>      // or: context, bot, bot_ctx, etc.
/// ) -> Result<YourResponse>     // Must return Result<ResponseType>
/// {
///     // Your parsing logic
/// }
///
/// // Build function - convert request to outgoing bytes
/// async fn build(
///     request: YourRequest,     // or: req, event, input, etc.
///     ctx: Arc<BotContext>      // or: context, bot, bot_ctx, etc.
/// ) -> Result<Bytes>            // Must return Result<Bytes>
/// {
///     // Your building logic
/// }
/// ```
///
/// # Complete Example
///
/// ```ignore
/// use crate::protocol::{RequestType, EncryptType};
/// use crate::context::BotContext;
/// use bytes::Bytes;
/// use std::sync::Arc;
///
/// define_service! {
///     LoginService: "wtlogin.login" {
///         request_type: RequestType::D2Auth,
///         encrypt_type: EncryptType::EncryptEmpty,
///
///         request LoginEvent {
///             uin: u64,
///             password: String,
///         }
///
///         response LoginResponse {
///             success: bool,
///             message: String,
///         }
///
///         async fn parse(input: Bytes, context: Arc<BotContext>) -> Result<LoginResponse> {
///             // Parse the response bytes
///             let success = !input.is_empty();
///             Ok(LoginResponse {
///                 success,
///                 message: "Login successful".to_string(),
///             })
///         }
///
///         async fn build(input: LoginEvent, context: Arc<BotContext>) -> Result<Bytes> {
///             // Build the request bytes
///             let data = format!("{}:{}", input.uin, input.password);
///             Ok(Bytes::from(data))
///         }
///     }
/// }
/// ```
///
/// # Generated Code
///
/// The macro generates:
///
/// 1. **Command Constant**: `SERVICENAME_COMMAND` with the command string
/// 2. **Request Struct**: With `new()`, field getters, Debug, Clone, PartialEq
/// 3. **Response Struct**: With `new()`, field getters, Debug, Clone, PartialEq
/// 4. **Service Struct**: Implements BaseService trait with parse_impl/build_impl
/// 5. **Service Registration**: Automatically registered with the inventory system
///
/// # Available Options
///
/// - **request_type**: `RequestType::D2Auth` (default) or `RequestType::Simple`
/// - **encrypt_type**: `EncryptType::EncryptD2Key` (default) or `EncryptType::EncryptEmpty`
/// - **disable_log**: `true` or `false` (default: false)
///
/// # Notes
///
/// - All field types must implement required traits (Clone for request, etc.)
/// - The Result type in function signatures refers to `crate::error::Result`
/// - Request and Response types automatically implement `ProtocolEvent`
/// - Services are automatically discovered and registered at compile time
///
/// # IDE Support
///
/// For better autocomplete:
/// - Import `RequestType` and `EncryptType` from `crate::protocol`
/// - Use rust-analyzer or IntelliJ IDEA with Rust plugin
/// - Hover over `RequestType::` or `EncryptType::` to see available variants
pub(crate) fn define_service_impl(input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(input as UnifiedServiceArgs);

    let service_name = &args.service_name;
    let command = &args.command;
    let request_name = &args.request_name;
    let response_name = &args.response_name;

    // Builder names (needed for documentation)
    let request_builder_name = Ident::new(
        &format!("{}Builder", request_name),
        request_name.span(),
    );
    let response_builder_name = Ident::new(
        &format!("{}Builder", response_name),
        response_name.span(),
    );

    // Generate documentation with cross-references
    let request_doc = format!("Request event for `{}` command.\n\n# Related Types\n\n- Response: [`{}`]\n- Builder: [`{}`]\n- Service: [`{}`]",
        command, response_name, request_builder_name, service_name);
    let response_doc = format!("Response event for `{}` command.\n\n# Related Types\n\n- Request: [`{}`]\n- Builder: [`{}`]\n- Service: [`{}`]",
        command, request_name, response_builder_name, service_name);

    // Generate request fields with proper visibility
    let request_fields = args.request_fields.iter().map(|f| {
        let name = &f.name;
        let ty = &f.ty;
        quote! { pub #name: #ty }
    });

    // Generate response fields with proper visibility
    let response_fields = args.response_fields.iter().map(|f| {
        let name = &f.name;
        let ty = &f.ty;
        quote! { pub #name: #ty }
    });

    // Generate constructor parameters for request
    let request_ctor_params = args.request_fields.iter().map(|f| {
        let name = &f.name;
        let ty = &f.ty;
        quote! { #name: #ty }
    });

    // Generate constructor field assignments for request
    let request_ctor_fields = args.request_fields.iter().map(|f| {
        let name = &f.name;
        quote! { #name }
    });

    // Generate field accessors for request
    let request_accessors = args.request_fields.iter().map(|f| {
        let name = &f.name;
        let ty = &f.ty;
        let getter_doc = format!("Get a reference to the `{}` field.", name);
        quote! {
            #[doc = #getter_doc]
            #[inline]
            pub fn #name(&self) -> &#ty {
                &self.#name
            }
        }
    });

    // Generate builder fields and methods for request
    let request_builder_fields = args.request_fields.iter().map(|f| {
        let name = &f.name;
        let ty = &f.ty;
        quote! { #name: Option<#ty> }
    });

    let request_builder_methods = args.request_fields.iter().map(|f| {
        let name = &f.name;
        let ty = &f.ty;
        let method_doc = format!("Set the `{}` field.", name);
        quote! {
            #[doc = #method_doc]
            #[inline]
            pub fn #name(mut self, value: #ty) -> Self {
                self.#name = Some(value);
                self
            }
        }
    });

    let request_builder_build_checks = args.request_fields.iter().map(|f| {
        let name = &f.name;
        let name_str = name.to_string();
        quote! {
            let #name = self.#name.ok_or_else(|| {
                crate::error::Error::BuildError(
                    format!("Missing required field: {}", #name_str)
                )
            })?;
        }
    });

    let request_builder_field_names = args.request_fields.iter().map(|f| &f.name);

    // Generate constructor parameters for response
    let response_ctor_params = args.response_fields.iter().map(|f| {
        let name = &f.name;
        let ty = &f.ty;
        quote! { #name: #ty }
    });

    // Generate constructor field assignments for response
    let response_ctor_fields = args.response_fields.iter().map(|f| {
        let name = &f.name;
        quote! { #name }
    });

    // Generate field accessors for response
    let response_accessors = args.response_fields.iter().map(|f| {
        let name = &f.name;
        let ty = &f.ty;
        let getter_doc = format!("Get a reference to the `{}` field.", name);
        quote! {
            #[doc = #getter_doc]
            #[inline]
            pub fn #name(&self) -> &#ty {
                &self.#name
            }
        }
    });

    // Generate builder fields and methods for response
    let response_builder_fields = args.response_fields.iter().map(|f| {
        let name = &f.name;
        let ty = &f.ty;
        quote! { #name: Option<#ty> }
    });

    let response_builder_methods = args.response_fields.iter().map(|f| {
        let name = &f.name;
        let ty = &f.ty;
        let method_doc = format!("Set the `{}` field.", name);
        quote! {
            #[doc = #method_doc]
            #[inline]
            pub fn #name(mut self, value: #ty) -> Self {
                self.#name = Some(value);
                self
            }
        }
    });

    let response_builder_build_checks = args.response_fields.iter().map(|f| {
        let name = &f.name;
        let name_str = name.to_string();
        quote! {
            let #name = self.#name.ok_or_else(|| {
                crate::error::Error::BuildError(
                    format!("Missing required field: {}", #name_str)
                )
            })?;
        }
    });

    let response_builder_field_names = args.response_fields.iter().map(|f| &f.name);

    // Build explicit return types for IDE clarity
    let parse_return_type = quote! { crate::error::Result<Self::Response> };
    let build_return_type = quote! { crate::error::Result<bytes::Bytes> };

    // Generate metadata initialization
    let mut metadata_init = quote! {
        crate::protocol::ServiceMetadata::new(#command)
    };

    if let Some(ref rt_path) = args.request_type {
        metadata_init = quote! {
            #metadata_init.with_request_type(#rt_path)
        };
    }

    if let Some(ref et_path) = args.encrypt_type {
        metadata_init = quote! {
            #metadata_init.with_encrypt_type(#et_path)
        };
    }

    if args.disable_log {
        metadata_init = quote! {
            #metadata_init.with_disable_log(true)
        };
    }

    // Generate command constant for IDE navigation
    let command_const_name = Ident::new(
        &format!("{}_COMMAND", service_name.to_string().to_uppercase()),
        service_name.span(),
    );

    // Generate service structs for each handler
    let service_impls = args.handlers.iter().map(|handler| {
        // Determine service struct name based on protocol
        let handler_service_name = if args.handlers.len() == 1 && handler.protocol_suffix.is_none() {
            // Single handler with no protocol: use base service name
            service_name.clone()
        } else {
            // Multiple handlers or protocol-specific: append suffix
            let suffix = handler.protocol_suffix.clone()
                .unwrap_or_else(|| "All".to_string());
            Ident::new(
                &format!("{}{}", service_name, suffix),
                service_name.span(),
            )
        };

        let parse_params = &handler.parse_fn.signature.inputs;
        let parse_body = &handler.parse_fn.body;
        let build_params = &handler.build_fn.signature.inputs;
        let build_body = &handler.build_fn.body;

        let handler_service_doc = if let Some(ref protocol_expr) = handler.protocol_expr {
            let protocol_str = quote!(#protocol_expr).to_string();
            format!("Service for handling `{}` protocol command (protocol: {}).\n\n# Related Types\n\n- Request: [`{}`]\n- Response: [`{}`]\n- Request Builder: [`{}`]\n- Response Builder: [`{}`]",
                command, protocol_str, request_name, response_name, request_builder_name, response_builder_name)
        } else {
            format!("Service for handling `{}` protocol command (all protocols).\n\n# Related Types\n\n- Request: [`{}`]\n- Response: [`{}`]\n- Request Builder: [`{}`]\n- Response Builder: [`{}`]",
                command, request_name, response_name, request_builder_name, response_builder_name)
        };

        quote! {
            // Service struct
            #[doc = #handler_service_doc]
            #[doc = ""]
            #[doc = "This service implements protocol handling for the command and provides"]
            #[doc = "methods to parse incoming data and build outgoing requests."]
            #[derive(Debug)]
            pub struct #handler_service_name {
                metadata: crate::protocol::ServiceMetadata,
            }

            impl #handler_service_name {
                #[doc = "Get the protocol command string for this service."]
                #[inline]
                pub const fn command() -> &'static str {
                    #command
                }

                #[doc = "Get the service metadata."]
                #[inline]
                pub fn metadata(&self) -> &crate::protocol::ServiceMetadata {
                    &self.metadata
                }
            }

            // Default implementation
            #[automatically_derived]
            impl Default for #handler_service_name {
                #[inline]
                fn default() -> Self {
                    Self {
                        metadata: #metadata_init,
                    }
                }
            }

            // BaseService implementation with explicit types
            #[async_trait::async_trait]
            impl crate::internal::services::BaseService for #handler_service_name {
                type Request = #request_name;
                type Response = #response_name;

                #[doc = "Parse incoming bytes into a response event."]
                #[doc = ""]
                #[doc = "This method is called when the service receives data from the protocol layer."]
                #[must_use]
                #[inline]
                async fn parse_impl(&self, #parse_params) -> #parse_return_type #parse_body

                #[doc = "Build outgoing bytes from a request event."]
                #[doc = ""]
                #[doc = "This method is called when the service needs to send a request."]
                #[must_use]
                #[inline]
                async fn build_impl(&self, #build_params) -> #build_return_type #build_body

                #[inline]
                fn metadata(&self) -> &crate::protocol::ServiceMetadata {
                    &self.metadata
                }
            }

            // Service registration
            inventory::submit! {
                crate::internal::services::ServiceRegistration {
                    command: #command,
                    factory: || Box::new(#handler_service_name::default()),
                }
            }
        }
    });

    let expanded = quote! {
        // Command constant for easy access and IDE navigation
        #[doc = "Protocol command string for this service."]
        pub const #command_const_name: &str = #command;

        // Request event struct with comprehensive derives
        #[doc = #request_doc]
        #[doc = ""]
        #[doc = "This struct represents a request event that can be sent to trigger"]
        #[doc = "the service operation."]
        #[doc = ""]
        #[doc = "# Example"]
        #[doc = ""]
        #[doc = "```ignore"]
        #[doc = "// Using constructor"]
        #[doc = concat!("let request = ", stringify!(#request_name), "::new(...);")]
        #[doc = ""]
        #[doc = "// Using builder (recommended for IDE auto-completion)"]
        #[doc = concat!("let request = ", stringify!(#request_name), "::builder()")]
        #[doc = "    .field_name(value)"]
        #[doc = "    .build()?;"]
        #[doc = "```"]
        #[derive(Debug, Clone, PartialEq)]
        pub struct #request_name {
            #(#request_fields),*
        }

        impl #request_name {
            #[doc = "Create a new request instance."]
            #[inline]
            pub fn new(#(#request_ctor_params),*) -> Self {
                Self {
                    #(#request_ctor_fields),*
                }
            }

            #[doc = "Create a builder for this request type."]
            #[doc = ""]
            #[doc = "The builder pattern provides better IDE auto-completion and allows"]
            #[doc = "for incremental construction of the request."]
            #[inline]
            pub fn builder() -> #request_builder_name {
                #request_builder_name::default()
            }

            #(#request_accessors)*
        }

        impl crate::protocol::ProtocolEvent for #request_name {}

        // Request builder struct
        #[doc = concat!("Builder for [`", stringify!(#request_name), "`].")]
        #[doc = ""]
        #[doc = "Provides a fluent API for constructing request events with IDE auto-completion."]
        #[doc = ""]
        #[doc = "# Example"]
        #[doc = ""]
        #[doc = "```ignore"]
        #[doc = concat!("let request = ", stringify!(#request_name), "::builder()")]
        #[doc = "    .field1(value1)"]
        #[doc = "    .field2(value2)"]
        #[doc = "    .build()?;"]
        #[doc = "```"]
        #[derive(Debug, Default, Clone)]
        pub struct #request_builder_name {
            #(#request_builder_fields),*
        }

        impl #request_builder_name {
            #(#request_builder_methods)*

            #[doc = "Build the request instance."]
            #[doc = ""]
            #[doc = "Returns an error if any required fields are missing."]
            #[inline]
            pub fn build(self) -> crate::error::Result<#request_name> {
                #(#request_builder_build_checks)*
                Ok(#request_name {
                    #(#request_builder_field_names),*
                })
            }
        }

        // Response event struct with comprehensive derives
        #[doc = #response_doc]
        #[doc = ""]
        #[doc = "This struct represents the response from the service operation."]
        #[doc = ""]
        #[doc = "# Example"]
        #[doc = ""]
        #[doc = "```ignore"]
        #[doc = "// Using constructor"]
        #[doc = concat!("let response = ", stringify!(#response_name), "::new(...);")]
        #[doc = ""]
        #[doc = "// Using builder (recommended for IDE auto-completion)"]
        #[doc = concat!("let response = ", stringify!(#response_name), "::builder()")]
        #[doc = "    .field_name(value)"]
        #[doc = "    .build()?;"]
        #[doc = "```"]
        #[derive(Debug, Clone, PartialEq)]
        pub struct #response_name {
            #(#response_fields),*
        }

        impl #response_name {
            #[doc = "Create a new response instance."]
            #[inline]
            pub fn new(#(#response_ctor_params),*) -> Self {
                Self {
                    #(#response_ctor_fields),*
                }
            }

            #[doc = "Create a builder for this response type."]
            #[doc = ""]
            #[doc = "The builder pattern provides better IDE auto-completion and allows"]
            #[doc = "for incremental construction of the response."]
            #[inline]
            pub fn builder() -> #response_builder_name {
                #response_builder_name::default()
            }

            #(#response_accessors)*
        }

        impl crate::protocol::ProtocolEvent for #response_name {}

        // Response builder struct
        #[doc = concat!("Builder for [`", stringify!(#response_name), "`].")]
        #[doc = ""]
        #[doc = "Provides a fluent API for constructing response events with IDE auto-completion."]
        #[doc = ""]
        #[doc = "# Example"]
        #[doc = ""]
        #[doc = "```ignore"]
        #[doc = concat!("let response = ", stringify!(#response_name), "::builder()")]
        #[doc = "    .field1(value1)"]
        #[doc = "    .field2(value2)"]
        #[doc = "    .build()?;"]
        #[doc = "```"]
        #[derive(Debug, Default, Clone)]
        pub struct #response_builder_name {
            #(#response_builder_fields),*
        }

        impl #response_builder_name {
            #(#response_builder_methods)*

            #[doc = "Build the response instance."]
            #[doc = ""]
            #[doc = "Returns an error if any required fields are missing."]
            #[inline]
            pub fn build(self) -> crate::error::Result<#response_name> {
                #(#response_builder_build_checks)*
                Ok(#response_name {
                    #(#response_builder_field_names),*
                })
            }
        }

        // Generate service implementations for each handler
        #(#service_impls)*
    };

    TokenStream::from(expanded)
}
