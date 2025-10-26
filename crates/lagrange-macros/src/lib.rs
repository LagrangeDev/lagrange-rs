//! Procedural macros for the lagrange-rs QQ protocol library.
//!
//! This crate provides three main macros:
//! - `#[services]` - Attribute macro for services registration
//! - `#[event_subscribe]` - Attribute macro for event handler registration
//! - `define_service!` - Declarative macro for defining complete services

use proc_macro::TokenStream;

mod define_service;
mod event_subscribe;
mod service;
mod utils;

/// Attribute macro for services registration.
///
/// See the `services` module documentation for details.
#[proc_macro_attribute]
pub fn service(attr: TokenStream, item: TokenStream) -> TokenStream {
    service::service_impl(attr, item)
}

/// Attribute macro for event handler registration.
///
/// See the `event_subscribe` module documentation for details.
#[proc_macro_attribute]
pub fn event_subscribe(attr: TokenStream, item: TokenStream) -> TokenStream {
    event_subscribe::event_subscribe_impl(attr, item)
}

/// Declarative macro for defining complete services.
///
/// See the `define_service` module documentation for details.
#[proc_macro]
pub fn define_service(input: TokenStream) -> TokenStream {
    define_service::define_service_impl(input)
}
