use crate::utils::{suggest_closest_match, validate_path_structure};
use proc_macro::TokenStream;
use quote::quote;
use syn::{
    braced,
    parse::{Parse, ParseStream},
    parse_macro_input,
    spanned::Spanned,
    Block, Expr, Ident, LitBool, LitStr, Path, ReturnType, Signature, Token, Type,
};

fn validate_and_extract_protocol(expr: &Expr) -> syn::Result<String> {
    const VALID_PROTOCOLS: &[&str] = &[
        "PC",
        "ANDROID",
        "ALL",
        "Windows",
        "MacOs",
        "Linux",
        "AndroidPhone",
        "AndroidPad",
        "AndroidWatch",
    ];

    if let Expr::Path(expr_path) = expr {
        let path = &expr_path.path;

        if path.segments.len() == 2 {
            let first_segment = &path.segments[0];
            let second_segment = &path.segments[1];

            if first_segment.ident == "Protocols" {
                let constant_name = second_segment.ident.to_string();

                if VALID_PROTOCOLS.contains(&constant_name.as_str()) {
                    return Ok(constant_name);
                }

                let mut error_msg = format!(
                    "Invalid protocol constant: 'Protocols::{}'\\n\\nValid protocol constants are:\\n\\nBit masks:\\n  - Protocols::PC\\n  - Protocols::ANDROID\\n  - Protocols::ALL\\n\\nIndividual variants:\\n  - Protocols::Windows\\n  - Protocols::MacOs\\n  - Protocols::Linux\\n  - Protocols::AndroidPhone\\n  - Protocols::AndroidPad\\n  - Protocols::AndroidWatch",
                    constant_name
                );

                if let Some(suggestion) = suggest_closest_match(&constant_name, VALID_PROTOCOLS) {
                    error_msg.push_str(&format!("\\n\\nDid you mean 'Protocols::{}'?", suggestion));
                }

                return Err(syn::Error::new(expr.span(), error_msg));
            }
        }
    }

    Err(syn::Error::new(
        expr.span(),
        "Protocol must be specified as Protocols::CONSTANT\\n\\nExamples:\\n  - Protocols::PC\\n  - Protocols::ANDROID\\n  - Protocols::ALL\\n  - Protocols::Windows"
    ))
}

struct ServiceField {
    name: Ident,
    ty: Type,
}

impl Parse for ServiceField {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let name: Ident = input.parse()?;
        input.parse::<Token![:]>()?;
        let ty: Type = input.parse()?;

        let _ = input.parse::<Token![,]>();

        Ok(ServiceField { name, ty })
    }
}

struct ServiceFunction {
    signature: Signature,
    body: Block,
}

impl ServiceFunction {
    fn parse_with_name(input: ParseStream, expected_name: &str) -> syn::Result<Self> {
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

struct EventDefinition {
    #[allow(dead_code)]
    name: Ident,
    protocol_expr: Expr,
    #[allow(dead_code)]
    protocol_name: String,
    request_name: Ident,
    request_fields: Vec<ServiceField>,
    response_name: Ident,
    response_fields: Vec<ServiceField>,
}

impl Parse for EventDefinition {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let name: Ident = input.parse()?;

        let protocol_content;
        syn::parenthesized!(protocol_content in input);

        let protocol_key: Ident = protocol_content.parse()?;
        if protocol_key != "protocol" {
            return Err(syn::Error::new(
                protocol_key.span(),
                "Expected 'protocol' parameter",
            ));
        }

        protocol_content.parse::<Token![=]>()?;
        let protocol_expr: Expr = protocol_content.parse()?;
        let protocol_name = validate_and_extract_protocol(&protocol_expr)?;

        let event_content;
        braced!(event_content in input);

        let mut request_name = None;
        let mut request_fields = Vec::new();
        let mut response_name = None;
        let mut response_fields = Vec::new();

        while !event_content.is_empty() {
            let key: Ident = event_content.parse()?;

            if key == "request" {
                let req_name: Ident = event_content.parse()?;
                let fields_content;
                braced!(fields_content in event_content);

                let mut fields = Vec::new();
                while !fields_content.is_empty() {
                    fields.push(fields_content.parse()?);
                }

                request_name = Some(req_name);
                request_fields = fields;
            } else if key == "response" {
                let resp_name: Ident = event_content.parse()?;
                let fields_content;
                braced!(fields_content in event_content);

                let mut fields = Vec::new();
                while !fields_content.is_empty() {
                    fields.push(fields_content.parse()?);
                }

                response_name = Some(resp_name);
                response_fields = fields;
            } else {
                return Err(syn::Error::new(
                    key.span(),
                    "Expected 'request' or 'response' in event definition",
                ));
            }
        }

        let request_name = request_name.ok_or_else(|| {
            syn::Error::new(input.span(), "Missing 'request' block in event definition")
        })?;
        let response_name = response_name.ok_or_else(|| {
            syn::Error::new(input.span(), "Missing 'response' block in event definition")
        })?;

        Ok(EventDefinition {
            name,
            protocol_expr,
            protocol_name,
            request_name,
            request_fields,
            response_name,
            response_fields,
        })
    }
}

struct UnifiedServiceArgs {
    service_name: Ident,
    command: String,
    request_type: Option<Path>,
    encrypt_type: Option<Path>,
    disable_log: bool,
    events: Vec<EventDefinition>,
    parse_fn: ServiceFunction,
    build_fn: ServiceFunction,
}

impl Parse for UnifiedServiceArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let service_name: Ident = input.parse()?;

        let content;
        braced!(content in input);

        let mut command = None;
        let mut request_type = None;
        let mut encrypt_type = None;
        let mut disable_log = false;
        let mut events = Vec::new();
        let mut parse_fn = None;
        let mut build_fn = None;

        while !content.is_empty() {
            let lookahead = content.lookahead1();

            if lookahead.peek(Ident) {
                let key: Ident = content.parse()?;

                if key == "command" {
                    content.parse::<Token![:]>()?;
                    let cmd: LitStr = content.parse()?;
                    command = Some(cmd.value());
                    let _ = content.parse::<Token![,]>();
                } else if key == "request_type" {
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
                } else if key == "events" {
                    let events_content;
                    braced!(events_content in content);

                    while !events_content.is_empty() {
                        events.push(events_content.parse()?);
                    }
                } else {
                    return Err(syn::Error::new(
                        key.span(),
                        "Unknown key in service definition. Expected: command, request_type, encrypt_type, disable_log, events",
                    ));
                }
            } else if lookahead.peek(Token![async]) {
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
                        "Expected 'parse' or 'build' function",
                    ));
                }
            } else {
                return Err(lookahead.error());
            }
        }

        let command = command.ok_or_else(|| {
            syn::Error::new(
                input.span(),
                "Missing 'command' field in service definition",
            )
        })?;

        if events.is_empty() {
            return Err(syn::Error::new(
                input.span(),
                "Service must define at least one event",
            ));
        }

        let parse_fn =
            parse_fn.ok_or_else(|| syn::Error::new(input.span(), "Missing 'parse' function"))?;

        let build_fn =
            build_fn.ok_or_else(|| syn::Error::new(input.span(), "Missing 'build' function"))?;

        Ok(UnifiedServiceArgs {
            service_name,
            command,
            request_type,
            encrypt_type,
            disable_log,
            events,
            parse_fn,
            build_fn,
        })
    }
}

pub(crate) fn define_service_impl(input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(input as UnifiedServiceArgs);

    let service_name = &args.service_name;
    let command = &args.command;

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

    let event_structs = args.events.iter().map(|event| {
        let request_name = &event.request_name;
        let response_name = &event.response_name;
        let request_builder_name =
            Ident::new(&format!("{}Builder", request_name), request_name.span());
        let response_builder_name =
            Ident::new(&format!("{}Builder", response_name), response_name.span());

        let request_fields = event.request_fields.iter().map(|f| {
            let name = &f.name;
            let ty = &f.ty;
            quote! { pub #name: #ty }
        });

        let request_ctor_params = event.request_fields.iter().map(|f| {
            let name = &f.name;
            let ty = &f.ty;
            quote! { #name: #ty }
        });

        let request_ctor_fields = event.request_fields.iter().map(|f| &f.name);

        let request_accessors = event.request_fields.iter().map(|f| {
            let name = &f.name;
            let ty = &f.ty;
            quote! {
                #[inline]
                pub fn #name(&self) -> &#ty {
                    &self.#name
                }
            }
        });

        let request_builder_fields = event.request_fields.iter().map(|f| {
            let name = &f.name;
            let ty = &f.ty;
            quote! { #name: Option<#ty> }
        });

        let request_builder_methods = event.request_fields.iter().map(|f| {
            let name = &f.name;
            let ty = &f.ty;
            quote! {
                #[inline]
                pub fn #name(mut self, value: #ty) -> Self {
                    self.#name = Some(value);
                    self
                }
            }
        });

        let request_builder_build_checks = event.request_fields.iter().map(|f| {
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

        let request_builder_field_names = event.request_fields.iter().map(|f| &f.name);

        let response_fields = event.response_fields.iter().map(|f| {
            let name = &f.name;
            let ty = &f.ty;
            quote! { pub #name: #ty }
        });

        let response_ctor_params = event.response_fields.iter().map(|f| {
            let name = &f.name;
            let ty = &f.ty;
            quote! { #name: #ty }
        });

        let response_ctor_fields = event.response_fields.iter().map(|f| &f.name);

        let response_accessors = event.response_fields.iter().map(|f| {
            let name = &f.name;
            let ty = &f.ty;
            quote! {
                #[inline]
                pub fn #name(&self) -> &#ty {
                    &self.#name
                }
            }
        });

        let response_builder_fields = event.response_fields.iter().map(|f| {
            let name = &f.name;
            let ty = &f.ty;
            quote! { #name: Option<#ty> }
        });

        let response_builder_methods = event.response_fields.iter().map(|f| {
            let name = &f.name;
            let ty = &f.ty;
            quote! {
                #[inline]
                pub fn #name(mut self, value: #ty) -> Self {
                    self.#name = Some(value);
                    self
                }
            }
        });

        let response_builder_build_checks = event.response_fields.iter().map(|f| {
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

        let response_builder_field_names = event.response_fields.iter().map(|f| &f.name);

        quote! {
            #[derive(Debug, Clone, PartialEq)]
            pub struct #request_name {
                #(#request_fields),*
            }

            impl #request_name {
                #[inline]
                pub fn new(#(#request_ctor_params),*) -> Self {
                    Self {
                        #(#request_ctor_fields),*
                    }
                }

                #[inline]
                pub fn builder() -> #request_builder_name {
                    #request_builder_name::default()
                }

                #(#request_accessors)*
            }

            impl crate::protocol::ProtocolEvent for #request_name {}

            #[derive(Debug, Default, Clone)]
            pub struct #request_builder_name {
                #(#request_builder_fields),*
            }

            impl #request_builder_name {
                #(#request_builder_methods)*

                #[inline]
                pub fn build(self) -> crate::error::Result<#request_name> {
                    #(#request_builder_build_checks)*
                    Ok(#request_name {
                        #(#request_builder_field_names),*
                    })
                }
            }

            #[derive(Debug, Clone, PartialEq)]
            pub struct #response_name {
                #(#response_fields),*
            }

            impl #response_name {
                #[inline]
                pub fn new(#(#response_ctor_params),*) -> Self {
                    Self {
                        #(#response_ctor_fields),*
                    }
                }

                #[inline]
                pub fn builder() -> #response_builder_name {
                    #response_builder_name::default()
                }

                #(#response_accessors)*
            }

            impl crate::protocol::ProtocolEvent for #response_name {}

            #[derive(Debug, Default, Clone)]
            pub struct #response_builder_name {
                #(#response_builder_fields),*
            }

            impl #response_builder_name {
                #(#response_builder_methods)*

                #[inline]
                pub fn build(self) -> crate::error::Result<#response_name> {
                    #(#response_builder_build_checks)*
                    Ok(#response_name {
                        #(#response_builder_field_names),*
                    })
                }
            }
        }
    });

    let parse_params = &args.parse_fn.signature.inputs;
    let parse_body = &args.parse_fn.body;
    let build_params = &args.build_fn.signature.inputs;
    let build_body = &args.build_fn.body;

    let event_registrations = args.events.iter().map(|event| {
        let request_name = &event.request_name;
        let protocol_expr = &event.protocol_expr;
        quote! {
            registry.register_event(
                std::any::TypeId::of::<#request_name>(),
                service.clone(),
                #protocol_expr,
            );
        }
    });

    let registration_fn_name = Ident::new(
        &format!("__register_{}", service_name.to_string().to_lowercase()),
        service_name.span(),
    );

    let expanded = quote! {
        #(#event_structs)*

        #[derive(Debug)]
        pub struct #service_name {
            metadata: crate::protocol::ServiceMetadata,
        }

        impl #service_name {
            #[inline]
            pub const fn command() -> &'static str {
                #command
            }

            #[inline]
            pub fn metadata(&self) -> &crate::protocol::ServiceMetadata {
                &self.metadata
            }
        }

        impl Default for #service_name {
            #[inline]
            fn default() -> Self {
                Self {
                    metadata: #metadata_init,
                }
            }
        }

        #[async_trait::async_trait]
        impl crate::internal::services::Service for #service_name {
            #[inline]
            async fn parse(&self, #parse_params) -> crate::error::Result<crate::protocol::EventMessage> #parse_body

            #[inline]
            async fn build(&self, #build_params) -> crate::error::Result<bytes::Bytes> #build_body

            #[inline]
            fn metadata(&self) -> &crate::protocol::ServiceMetadata {
                &self.metadata
            }
        }

        #[linkme::distributed_slice(crate::internal::services::SERVICE_INITIALIZERS)]
        fn #registration_fn_name(registry: &mut crate::internal::services::ServiceRegistry) {
            let service = std::sync::Arc::new(#service_name::default());

            registry.register_service(
                #command.to_string(),
                service.clone(),
            );

            #(#event_registrations)*
        }
    };

    TokenStream::from(expanded)
}
