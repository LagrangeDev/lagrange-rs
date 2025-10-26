use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Ident, ItemStruct, Token,
};

use crate::utils::validate_path_structure;

/// Attribute arguments for the #[event_subscribe] macro
struct EventSubscribeArgs {
    event_type: syn::Path,
    protocol: Option<syn::Path>,
}

impl Parse for EventSubscribeArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // First argument is the event type (required)
        let event_type: syn::Path = input.parse()?;
        let mut protocol = None;

        // Parse optional protocol filter
        if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;

            let key: Ident = input.parse()?;
            if key != "protocol" {
                return Err(syn::Error::new(key.span(), "Expected 'protocol' attribute"));
            }

            input.parse::<Token![=]>()?;
            let value: syn::Path = input.parse()?;
            validate_path_structure(&value, "protocol")?;
            protocol = Some(value);
        }

        Ok(EventSubscribeArgs {
            event_type,
            protocol,
        })
    }
}

pub(crate) fn event_subscribe_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as EventSubscribeArgs);
    let input = parse_macro_input!(item as ItemStruct);

    let name = &input.ident;
    let event_type = &args.event_type;

    // Generate protocol mask from the provided path or default to ALL
    let protocol_mask = if let Some(ref protocol_path) = args.protocol {
        // Always cast to u8 - safe for both enum variants and u8 constants
        quote! { (#protocol_path) as u8 }
    } else {
        quote! { crate::protocol::Protocols::ALL }
    };

    let expanded = quote! {
        #input

        inventory::submit! {
            crate::internal::service::EventSubscription {
                event_type: std::any::TypeId::of::<#event_type>(),
                protocol_mask: #protocol_mask,
                handler: |ctx, event| {
                    Box::pin(async move {
                        let service = #name;
                        service.handle(ctx, event).await
                    })
                },
            }
        }
    };

    TokenStream::from(expanded)
}
