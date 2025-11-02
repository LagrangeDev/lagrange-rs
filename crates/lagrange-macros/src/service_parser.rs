use proc_macro2::{TokenStream as TokenStream2, TokenTree};
use syn::{
    parse::{Parse, ParseStream},
    Ident, Result,
};

#[derive(Debug, Clone)]
pub struct ServiceDefinition {
    pub service_name: Ident,
    pub events: Vec<EventDefinition>,
}

#[derive(Debug, Clone)]
pub struct EventDefinition {
    pub request_name: Ident,
    pub response_name: Ident,
}

impl Parse for ServiceDefinition {
    fn parse(input: ParseStream) -> Result<Self> {
        let service_name: Ident = input.parse()?;

        let service_body: TokenTree = input.parse()?;

        let service_stream = if let TokenTree::Group(group) = service_body {
            group.stream()
        } else {
            return Err(syn::Error::new_spanned(
                service_body,
                "Expected braced block after service name",
            ));
        };

        let events = syn::parse::Parser::parse2(
            |input: ParseStream| {
                let mut found_events = None;

                while !input.is_empty() {
                    let tt: TokenTree = input.parse()?;

                    if let TokenTree::Ident(ref ident) = tt {
                        if ident == "events" && found_events.is_none() {
                            if let Ok(TokenTree::Group(group)) = input.parse::<TokenTree>() {
                                let events_stream = group.stream();
                                let evs = syn::parse::Parser::parse2(
                                    |input: ParseStream| {
                                        let mut evs = Vec::new();
                                        while !input.is_empty() {
                                            evs.push(input.parse::<EventDefinition>()?);
                                        }
                                        Ok(evs)
                                    },
                                    events_stream,
                                )?;
                                found_events = Some(evs);
                            }
                        }
                    }
                }
                Ok(found_events.unwrap_or_else(Vec::new))
            },
            service_stream,
        )?;

        Ok(ServiceDefinition {
            service_name,
            events,
        })
    }
}

impl Parse for EventDefinition {
    fn parse(input: ParseStream) -> Result<Self> {
        let _event_name: Ident = input.parse()?;

        let _ = input.parse::<TokenTree>();

        let event_group: TokenTree = input.parse()?;

        let event_stream = if let TokenTree::Group(group) = event_group {
            group.stream()
        } else {
            return Err(syn::Error::new_spanned(
                event_group,
                "Expected braced block after event name",
            ));
        };

        let (request_name, response_name) = syn::parse::Parser::parse2(
            |input: ParseStream| {
                let mut req_name = None;
                let mut resp_name = None;

                while !input.is_empty() {
                    let tt: TokenTree = input.parse()?;

                    if let TokenTree::Ident(ref ident) = tt {
                        if ident == "request" {
                            if let Ok(TokenTree::Ident(name)) = input.parse::<TokenTree>() {
                                req_name = Some(name);
                                let _ = input.parse::<TokenTree>();
                            }
                        } else if ident == "response" {
                            if let Ok(TokenTree::Ident(name)) = input.parse::<TokenTree>() {
                                resp_name = Some(name);
                                let _ = input.parse::<TokenTree>();
                            }
                        }
                    }
                }

                let request_name = req_name.ok_or_else(|| {
                    syn::Error::new(input.span(), "Missing 'request' in event definition")
                })?;
                let response_name = resp_name.ok_or_else(|| {
                    syn::Error::new(input.span(), "Missing 'response' in event definition")
                })?;

                Ok((request_name, response_name))
            },
            event_stream,
        )?;

        Ok(EventDefinition {
            request_name,
            response_name,
        })
    }
}

pub fn parse_service_tokens(tokens: TokenStream2) -> Result<ServiceDefinition> {
    syn::parse2::<ServiceDefinition>(tokens)
}

pub fn extract_generated_types(def: &ServiceDefinition) -> Vec<Ident> {
    let mut types = vec![def.service_name.clone()];

    for event in &def.events {
        types.push(event.request_name.clone());
        types.push(event.response_name.clone());
    }

    types
}
