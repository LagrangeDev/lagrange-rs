
use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    Data, DeriveInput, Error, Fields, Meta, Result, Variant,
};

fn extract_enum_value(variant: &Variant) -> Result<i32> {
    for attr in &variant.attrs {
        if attr.path().is_ident("proto") {
            
            if let Ok(Meta::NameValue(nv)) = attr.parse_args::<Meta>() {
                if nv.path.is_ident("value") {
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
        "Missing #[proto(value = N)] attribute on enum variant",
    ))
}

pub fn expand_derive_proto_enum(input: DeriveInput) -> Result<TokenStream> {
    let enum_name = &input.ident;

    let variants = match &input.data {
        Data::Enum(data_enum) => &data_enum.variants,
        _ => {
            return Err(Error::new_spanned(
                input,
                "ProtoEnum can only be derived for enums",
            ))
        }
    };

    let mut variant_infos = Vec::new();
    for variant in variants {
        
        match &variant.fields {
            Fields::Unit => {}
            _ => {
                return Err(Error::new_spanned(
                    variant,
                    "ProtoEnum only supports unit variants (no fields)",
                ))
            }
        }

        let variant_name = &variant.ident;
        let value = extract_enum_value(variant)?;

        variant_infos.push((variant_name, value));
    }

    let encode_arms = variant_infos.iter().map(|(name, value)| {
        let value_i32 = *value;
        quote! {
            #enum_name::#name => {
                let (arr, len) = ::lagrange_proto::varint::encode(#value_i32 as u64);
                buf.put_slice(&arr[..len]);
            }
        }
    });

    let size_arms = variant_infos.iter().map(|(name, value)| {
        let value_i32 = *value;
        quote! {
            #enum_name::#name => ::lagrange_proto::helpers::get_varint_length_u32(#value_i32 as u32)
        }
    });

    let decode_arms: Vec<_> = variant_infos.iter().map(|(name, value)| {
        let value_i32 = *value;
        quote! {
            #value_i32 => Ok(#enum_name::#name)
        }
    }).collect();

    let to_i32_arms = variant_infos.iter().map(|(name, value)| {
        let value_i32 = *value;
        quote! {
            #enum_name::#name => #value_i32
        }
    });

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

        impl ::lagrange_proto::ProtoDecode for #enum_name {
            fn decode(buf: &[u8]) -> Result<Self, ::lagrange_proto::DecodeError> {
                let (value, _) = ::lagrange_proto::varint::decode::<u64>(buf)?;
                let value_i32 = value as i32;

                match value_i32 {
                    #(#decode_arms),*,
                    _ => Err(::lagrange_proto::DecodeError::InvalidEnumValue(value_i32))
                }
            }
        }

        impl #enum_name {
            
            #[allow(dead_code)]
            pub fn to_i32(&self) -> i32 {
                match self {
                    #(#to_i32_arms),*
                }
            }

            #[allow(dead_code)]
            pub fn from_i32(value: i32) -> Result<Self, i32> {
                match value {
                    #(#decode_arms),*,
                    _ => Err(value)
                }
            }
        }
    };

    Ok(expanded)
}
