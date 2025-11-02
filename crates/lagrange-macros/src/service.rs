use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Ident, ItemStruct, LitBool, LitStr, Path, Token,
};

use crate::utils::validate_path_structure;

struct ServiceArgs {
    command: String,
    request_type: Option<Path>,
    encrypt_type: Option<Path>,
    disable_log: bool,
}

impl Parse for ServiceArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut command = None;
        let mut request_type = None;
        let mut encrypt_type = None;
        let mut disable_log = false;

        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            if key == "command" {
                let value: LitStr = input.parse()?;
                command = Some(value.value());
            } else if key == "request_type" {
                let path: Path = input.parse()?;
                validate_path_structure(&path, "request_type")?;
                request_type = Some(path);
            } else if key == "encrypt_type" {
                let path: Path = input.parse()?;
                validate_path_structure(&path, "encrypt_type")?;
                encrypt_type = Some(path);
            } else if key == "disable_log" {
                let value: LitBool = input.parse()?;
                disable_log = value.value;
            } else {
                return Err(syn::Error::new(
                    key.span(),
                    format!(
                        "Unknown attribute '{}'. Valid attributes: command, request_type, encrypt_type, disable_log",
                        key
                    ),
                ));
            }

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        let command = command.ok_or_else(|| {
            syn::Error::new(input.span(), "services macro requires 'command' attribute")
        })?;

        Ok(ServiceArgs {
            command,
            request_type,
            encrypt_type,
            disable_log,
        })
    }
}

pub(crate) fn service_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as ServiceArgs);
    let mut input = parse_macro_input!(item as ItemStruct);

    let name = &input.ident;
    let generics = &input.generics;
    let command = &args.command;

    if let syn::Fields::Named(ref mut fields) = input.fields {
        let metadata_field: syn::Field = syn::parse_quote! {
            metadata: crate::protocol::ServiceMetadata
        };
        fields.named.push(metadata_field);
    } else {
        return syn::Error::new_spanned(
            &input,
            "services macro only supports structs with named fields (e.g., `struct Name {}`)",
        )
        .to_compile_error()
        .into();
    }

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

    let expanded = quote! {
        #input

        #[automatically_derived]
        impl #generics Default for #name #generics {
            fn default() -> Self {
                Self {
                    metadata: #metadata_init,
                }
            }
        }

        inventory::submit! {
            crate::internal::service::ServiceRegistration {
                command: #command,
                factory: || Box::new(#name::default()),
            }
        }
    };

    TokenStream::from(expanded)
}
