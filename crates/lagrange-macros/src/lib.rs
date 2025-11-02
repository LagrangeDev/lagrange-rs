use proc_macro::TokenStream;

mod auto_reexport;
mod define_service;
mod event_subscribe;
mod service;
mod service_parser;
mod utils;

#[proc_macro_attribute]
pub fn service(attr: TokenStream, item: TokenStream) -> TokenStream {
    service::service_impl(attr, item)
}

#[proc_macro_attribute]
pub fn event_subscribe(attr: TokenStream, item: TokenStream) -> TokenStream {
    event_subscribe::event_subscribe_impl(attr, item)
}

#[proc_macro]
pub fn define_service(input: TokenStream) -> TokenStream {
    define_service::define_service_impl(input)
}

#[proc_macro]
pub fn auto_reexport(input: TokenStream) -> TokenStream {
    auto_reexport::auto_reexport_impl(input)
}
