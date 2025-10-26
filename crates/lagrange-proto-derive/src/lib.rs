
use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod attributes;
mod builder_derive;
mod enum_derive;
mod message;
mod oneof_derive;

#[proc_macro_derive(ProtoMessage, attributes(proto))]
pub fn derive_proto_message(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    message::expand_derive_proto_message(input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_derive(ProtoEnum, attributes(proto))]
pub fn derive_proto_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    enum_derive::expand_derive_proto_enum(input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_derive(ProtoOneof, attributes(proto))]
pub fn derive_proto_oneof(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    oneof_derive::expand_derive_proto_oneof(input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_derive(ProtoBuilder)]
pub fn derive_proto_builder(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    builder_derive::expand_derive_proto_builder(input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}
