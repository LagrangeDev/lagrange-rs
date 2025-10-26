
use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    Data, DeriveInput, Error, Fields, Meta, Result, Variant,
};

fn extract_tag(variant: &Variant) -> Result<u32> {
    for attr in &variant.attrs {
        if attr.path().is_ident("proto") {
            
            if let Ok(Meta::NameValue(nv)) = attr.parse_args::<Meta>() {
                if nv.path.is_ident("tag") {
                    if let syn::Expr::Lit(expr_lit) = &nv.value {
                        if let syn::Lit::Int(lit_int) = &expr_lit.lit {
                            return lit_int.base10_parse();
                        }
                    }
                }
            }
        }
    }

    Err(Error::new_spanned(
        variant,
        "Missing #[proto(tag = N)] attribute on oneof variant",
    ))
}

pub fn expand_derive_proto_oneof(input: DeriveInput) -> Result<TokenStream> {
    let enum_name = &input.ident;

    let variants = match &input.data {
        Data::Enum(data_enum) => &data_enum.variants,
        _ => {
            return Err(Error::new_spanned(
                input,
                "ProtoOneof can only be derived for enums",
            ))
        }
    };

    let mut variant_infos = Vec::new();
    for variant in variants {
        let variant_name = &variant.ident;
        let tag = extract_tag(variant)?;

        let field_ty = match &variant.fields {
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                fields.unnamed.first().unwrap().ty.clone()
            }
            _ => {
                return Err(Error::new_spanned(
                    variant,
                    "ProtoOneof variants must have exactly one unnamed field (e.g., Name(String))",
                ))
            }
        };

        variant_infos.push((variant_name, tag, field_ty));
    }

    let encode_arms = variant_infos.iter().map(|(name, tag, field_ty)| {
        let wire_type = wire_type_for_type(&field_ty);
        quote! {
            #enum_name::#name(ref value) => {
                
                let key = ::lagrange_proto::wire::encode_key(#tag, #wire_type);
                {
                    let mut temp = [0u8; 5];
                    let len = ::lagrange_proto::varint::encode_to_slice(key, &mut temp);
                    buf.put_slice(&temp[..len]);
                }
                
                value.encode(buf)?;
            }
        }
    });

    let size_arms = variant_infos.iter().map(|(name, tag, field_ty)| {
        let wire_type = wire_type_for_type(&field_ty);
        quote! {
            #enum_name::#name(ref value) => {
                let key = ::lagrange_proto::wire::encode_key(#tag, #wire_type);
                ::lagrange_proto::helpers::get_varint_length_u32(key) + value.encoded_size()
            }
        }
    });

    let decode_arms: Vec<_> = variant_infos.iter().map(|(name, tag, field_ty)| {
        let decode_value = generate_decode_value(&field_ty);
        quote! {
            #tag => {
                let value = #decode_value;
                Ok(#enum_name::#name(value))
            }
        }
    }).collect();

    let expanded = quote! {
        impl ::lagrange_proto::ProtoEncode for #enum_name {
            fn encode<B: ::bytes::BufMut>(&self, buf: &mut B) -> Result<(), ::lagrange_proto::EncodeError> {
                match self {
                    #(#encode_arms)*
                }
                Ok(())
            }

            fn encoded_size(&self) -> usize {
                match self {
                    #(#size_arms),*
                }
            }
        }

        impl #enum_name {
            #[allow(dead_code)]
            pub fn decode_with_tag(tag: u32, wire_type: ::lagrange_proto::wire::WireType, reader: &mut ::lagrange_proto::decoding::FieldReader<'_>) -> Result<Self, ::lagrange_proto::DecodeError> {
                match tag {
                    #(#decode_arms),*,
                    _ => Err(::lagrange_proto::DecodeError::InvalidEnumValue(tag as i32))
                }
            }
        }
    };

    Ok(expanded)
}

/// Determine the wire type for a Rust type.
fn wire_type_for_type(ty: &syn::Type) -> TokenStream {
    let type_str = quote!(#ty).to_string();
    let type_str = type_str.trim();

    match type_str {
        // Varint types
        "u32" | "u64" | "i32" | "i64" | "bool" => {
            quote! { ::lagrange_proto::wire::WireType::Varint }
        }
        // Explicit protobuf types - varint with zigzag
        "SInt32" | "SInt64" | ":: lagrange_proto :: SInt32" | ":: lagrange_proto :: SInt64" => {
            quote! { ::lagrange_proto::wire::WireType::Varint }
        }
        // Fixed32 types
        "f32" | "Fixed32" | "SFixed32" |
        ":: lagrange_proto :: Fixed32" | ":: lagrange_proto :: SFixed32" => {
            quote! { ::lagrange_proto::wire::WireType::Fixed32 }
        }
        // Fixed64 types
        "f64" | "Fixed64" | "SFixed64" |
        ":: lagrange_proto :: Fixed64" | ":: lagrange_proto :: SFixed64" => {
            quote! { ::lagrange_proto::wire::WireType::Fixed64 }
        }
        // String and bytes
        "String" | "Vec < u8 >" | "Vec<u8>" => {
            quote! { ::lagrange_proto::wire::WireType::LengthDelimited }
        }
        _ => {
            // For custom types, assume nested message
            quote! { ::lagrange_proto::wire::WireType::LengthDelimited }
        }
    }
}

/// Generate decoding logic for a type
fn generate_decode_value(ty: &syn::Type) -> TokenStream {
    let type_str = quote!(#ty).to_string();
    let type_str = type_str.trim();

    match type_str {
        "u32" => quote! { reader.read_varint()? as u32 },
        "u64" => quote! { reader.read_varint()? },
        "i32" => {
            quote! {
                {
                    let (value, len) = ::lagrange_proto::varint::decode_zigzag::<u32>(reader.remaining())?;
                    reader.advance(len);
                    value
                }
            }
        },
        "i64" => {
            quote! {
                {
                    let (value, len) = ::lagrange_proto::varint::decode_zigzag::<u64>(reader.remaining())?;
                    reader.advance(len);
                    value
                }
            }
        },
        "bool" => {
            quote! {
                {
                    let (value, len) = ::lagrange_proto::varint::decode::<u32>(reader.remaining())?;
                    reader.advance(len);
                    value != 0
                }
            }
        },
        "f32" => quote! { f32::from_bits(reader.read_fixed32()?) },
        "f64" => quote! { f64::from_bits(reader.read_fixed64()?) },

        // Explicit protobuf types
        "SInt32" | ":: lagrange_proto :: SInt32" => {
            quote! {
                {
                    let (value, len) = ::lagrange_proto::varint::decode_zigzag::<u32>(reader.remaining())?;
                    reader.advance(len);
                    ::lagrange_proto::SInt32(value)
                }
            }
        },
        "SInt64" | ":: lagrange_proto :: SInt64" => {
            quote! {
                {
                    let (value, len) = ::lagrange_proto::varint::decode_zigzag::<u64>(reader.remaining())?;
                    reader.advance(len);
                    ::lagrange_proto::SInt64(value)
                }
            }
        },
        "Fixed32" | ":: lagrange_proto :: Fixed32" => {
            quote! { ::lagrange_proto::Fixed32(reader.read_fixed32()?) }
        },
        "Fixed64" | ":: lagrange_proto :: Fixed64" => {
            quote! { ::lagrange_proto::Fixed64(reader.read_fixed64()?) }
        },
        "SFixed32" | ":: lagrange_proto :: SFixed32" => {
            quote! {
                {
                    let value = reader.read_fixed32()?;
                    ::lagrange_proto::SFixed32(value as i32)
                }
            }
        },
        "SFixed64" | ":: lagrange_proto :: SFixed64" => {
            quote! {
                {
                    let value = reader.read_fixed64()?;
                    ::lagrange_proto::SFixed64(value as i64)
                }
            }
        },

        "String" => {
            quote! {
                {
                    let data = reader.read_length_delimited()?;
                    String::from_utf8(data).map_err(::lagrange_proto::DecodeError::InvalidUtf8)?
                }
            }
        },
        "Vec < u8 >" | "Vec<u8>" => {
            quote! { reader.read_length_delimited()? }
        },
        _ => {
            // For unknown types, delegate to the type's ProtoDecode::decode method
            
            quote! {
                {
                    
                    let value = ::lagrange_proto::ProtoDecode::decode(reader.remaining())?;
                    let value_size = ::lagrange_proto::ProtoEncode::encoded_size(&value);
                    reader.advance(value_size);
                    value
                }
            }
        }
    }
}
