use proc_macro::TokenStream;
use quote::quote;
use syn::{
    braced,
    parse::{Parse, ParseStream},
    parse_macro_input, Block, Ident, LitBool, LitStr, Path, ReturnType, Signature, Token, Type,
};

use crate::utils::{suggest_closest_match, validate_path_structure};

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
    parse_fn: ServiceFunction,
    build_fn: ServiceFunction,
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
        let mut parse_fn = None;
        let mut build_fn = None;

        while !content.is_empty() {
            let lookahead = content.lookahead1();

            if lookahead.peek(Token![async]) {
                // Parse full async function with signature
                let fork = content.fork();
                fork.parse::<Token![async]>()?;
                fork.parse::<Token![fn]>()?;
                let fn_name: Ident = fork.parse()?;

                if fn_name == "parse" {
                    parse_fn = Some(ServiceFunction::parse_with_name(&content, "parse")?);
                } else if fn_name == "build" {
                    build_fn = Some(ServiceFunction::parse_with_name(&content, "build")?);
                } else {
                    return Err(syn::Error::new(
                        fn_name.span(),
                        "Expected 'parse' or 'build'",
                    ));
                }
            } else if lookahead.peek(Ident) {
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
                } else {
                    // Unknown key - provide helpful suggestions
                    let valid_keys = &[
                        "request_type",
                        "encrypt_type",
                        "disable_log",
                        "request",
                        "response",
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
        let parse_fn = parse_fn.ok_or_else(|| {
            syn::Error::new(
                input.span(),
                "Missing 'parse' function\n\nExpected syntax:\n  async fn parse(input: Bytes, context: Arc<BotContext>) -> Result<ResponseEventName> {\n    // Parse logic here\n  }"
            )
        })?;
        let build_fn = build_fn.ok_or_else(|| {
            syn::Error::new(
                input.span(),
                "Missing 'build' function\n\nExpected syntax:\n  async fn build(input: RequestEventName, context: Arc<BotContext>) -> Result<Bytes> {\n    // Build logic here\n  }"
            )
        })?;

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
            parse_fn,
            build_fn,
        })
    }
}

/// Defines a services with request/response types and protocol handling.
///
/// This macro generates a complete services implementation including:
/// - Request and Response event structs with constructors and getters
/// - Service struct with BaseService trait implementation
/// - Automatic services registration via inventory
/// - Proper documentation for all generated types
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
///         // Optional: Disable logging for this services (default: false)
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
///         // Required: Parse incoming bytes into a response
///         async fn parse(input: Bytes, context: Arc<BotContext>) -> Result<ResponseEventName> {
///             // Parse logic here
///             Ok(ResponseEventName { /* ... */ })
///         }
///
///         // Required: Build outgoing bytes from a request
///         async fn build(input: RequestEventName, context: Arc<BotContext>) -> Result<Bytes> {
///             // Build logic here
///             Ok(Bytes::from(data))
///         }
///     }
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

    // Generate documentation
    let service_doc = format!("Service for handling `{}` protocol command.", command);
    let request_doc = format!("Request event for `{}` command.", command);
    let response_doc = format!("Response event for `{}` command.", command);

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

    // Extract function parameters and bodies
    let parse_params = &args.parse_fn.signature.inputs;
    let parse_body = &args.parse_fn.body;
    let build_params = &args.build_fn.signature.inputs;
    let build_body = &args.build_fn.body;

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
    let command_const_name = syn::Ident::new(
        &format!("{}_COMMAND", service_name.to_string().to_uppercase()),
        service_name.span(),
    );

    let expanded = quote! {
        // Command constant for easy access and IDE navigation
        #[doc = "Protocol command string for this services."]
        pub const #command_const_name: &str = #command;

        // Request event struct with comprehensive derives
        #[doc = #request_doc]
        #[doc = ""]
        #[doc = "This struct represents a request event that can be sent to trigger"]
        #[doc = "the services operation."]
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

            #(#request_accessors)*
        }

        impl crate::protocol::ProtocolEvent for #request_name {}

        // Response event struct with comprehensive derives
        #[doc = #response_doc]
        #[doc = ""]
        #[doc = "This struct represents the response from the services operation."]
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

            #(#response_accessors)*
        }

        impl crate::protocol::ProtocolEvent for #response_name {}

        // Service struct
        #[doc = #service_doc]
        #[doc = ""]
        #[doc = "This services implements protocol handling for the command and provides"]
        #[doc = "methods to parse incoming data and build outgoing requests."]
        #[derive(Debug)]
        pub struct #service_name {
            metadata: crate::protocol::ServiceMetadata,
        }

        impl #service_name {
            #[doc = "Get the protocol command string for this services."]
            #[inline]
            pub const fn command() -> &'static str {
                #command
            }

            #[doc = "Get the services metadata."]
            #[inline]
            pub fn metadata(&self) -> &crate::protocol::ServiceMetadata {
                &self.metadata
            }
        }

        // Default implementation
        #[automatically_derived]
        impl Default for #service_name {
            #[inline]
            fn default() -> Self {
                Self {
                    metadata: #metadata_init,
                }
            }
        }

        // BaseService implementation with explicit types
        #[async_trait::async_trait]
        impl crate::internal::services::BaseService for #service_name {
            type Request = #request_name;
            type Response = #response_name;

            #[doc = "Parse incoming bytes into a response event."]
            #[doc = ""]
            #[doc = "This method is called when the services receives data from the protocol layer."]
            #[inline]
            async fn parse_impl(&self, #parse_params) -> #parse_return_type #parse_body

            #[doc = "Build outgoing bytes from a request event."]
            #[doc = ""]
            #[doc = "This method is called when the services needs to send a request."]
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
                factory: || Box::new(#service_name::default()),
            }
        }
    };

    TokenStream::from(expanded)
}
