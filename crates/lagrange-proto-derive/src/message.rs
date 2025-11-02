use crate::attributes::{ProtoFieldAttrs, ProtoMessageAttrs};
use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    Data, DeriveInput, Error, Field, Fields, FieldsNamed, GenericArgument, PathArguments, Result,
    Type,
};

struct FieldInfo {
    name: syn::Ident,
    tag: u32,
    ty: Type,
    is_optional: bool,
    is_repeated: bool,
    is_map: bool,
    is_oneof: bool,
    attrs: ProtoFieldAttrs,
}

fn extract_field_attrs(field: &Field) -> Result<ProtoFieldAttrs> {
    let attrs = ProtoFieldAttrs::from_field(field)?;
    attrs.validate()?;

    if attrs.tag.is_none() && attrs.oneof.is_none() {
        return Err(Error::new_spanned(
            field,
            "Missing #[proto(tag = N)] or #[proto(oneof)] attribute",
        ));
    }

    Ok(attrs)
}

fn extract_inner_type(ty: &Type) -> Option<Type> {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            if segment.ident == "Option" || segment.ident == "Vec" {
                if let PathArguments::AngleBracketed(args) = &segment.arguments {
                    if let Some(GenericArgument::Type(inner_ty)) = args.args.first() {
                        return Some(inner_ty.clone());
                    }
                }
            }
        }
    }
    None
}

fn is_option(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            return segment.ident == "Option";
        }
    }
    false
}

fn is_vec(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            return segment.ident == "Vec";
        }
    }
    false
}

fn is_map(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            return segment.ident == "HashMap" || segment.ident == "BTreeMap";
        }
    }
    false
}

fn extract_map_types(ty: &Type) -> Option<(Type, Type)> {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            if segment.ident == "HashMap" || segment.ident == "BTreeMap" {
                if let PathArguments::AngleBracketed(args) = &segment.arguments {
                    if args.args.len() == 2 {
                        if let (
                            Some(GenericArgument::Type(key_ty)),
                            Some(GenericArgument::Type(val_ty)),
                        ) = (args.args.first(), args.args.iter().nth(1))
                        {
                            return Some((key_ty.clone(), val_ty.clone()));
                        }
                    }
                }
            }
        }
    }
    None
}

fn can_be_packed(ty: &Type) -> bool {
    let type_str = quote!(#ty).to_string();
    let type_str = type_str.trim();

    matches!(
        type_str,
        "u32"
            | "u64"
            | "i32"
            | "i64"
            | "bool"
            | "f32"
            | "f64"
            | "SInt32"
            | "SInt64"
            | "Fixed32"
            | "Fixed64"
            | "SFixed32"
            | "SFixed64"
            | ":: lagrange_proto :: SInt32"
            | ":: lagrange_proto :: SInt64"
            | ":: lagrange_proto :: Fixed32"
            | ":: lagrange_proto :: Fixed64"
            | ":: lagrange_proto :: SFixed32"
            | ":: lagrange_proto :: SFixed64"
    )
}

fn wire_type_for_type(ty: &Type) -> TokenStream {
    let inner_type = if is_option(ty) || is_vec(ty) {
        extract_inner_type(ty)
    } else {
        None
    };

    let actual_type = inner_type.as_ref().unwrap_or(ty);
    let actual_type_str = quote!(#actual_type).to_string();
    let actual_type_str = actual_type_str.trim();

    match actual_type_str {
        "u32" | "u64" | "i32" | "i64" | "bool" => {
            quote! { ::lagrange_proto::wire::WireType::Varint }
        }

        "SInt32" | "SInt64" | ":: lagrange_proto :: SInt32" | ":: lagrange_proto :: SInt64" => {
            quote! { ::lagrange_proto::wire::WireType::Varint }
        }

        "f32"
        | "Fixed32"
        | "SFixed32"
        | ":: lagrange_proto :: Fixed32"
        | ":: lagrange_proto :: SFixed32" => {
            quote! { ::lagrange_proto::wire::WireType::Fixed32 }
        }

        "f64"
        | "Fixed64"
        | "SFixed64"
        | ":: lagrange_proto :: Fixed64"
        | ":: lagrange_proto :: SFixed64" => {
            quote! { ::lagrange_proto::wire::WireType::Fixed64 }
        }

        "String" => {
            quote! { ::lagrange_proto::wire::WireType::LengthDelimited }
        }
        _ => {
            if actual_type_str.contains("::") {
                quote! { ::lagrange_proto::wire::WireType::LengthDelimited }
            } else {
                quote! { ::lagrange_proto::wire::WireType::Varint }
            }
        }
    }
}

fn generate_field_encode(field: &FieldInfo) -> TokenStream {
    let name = &field.name;
    let tag = field.tag;
    let wire_type = wire_type_for_type(&field.ty);

    if field.is_oneof {
        return quote! {
            if let Some(ref value) = self.#name {
                value.encode(buf)?;
            }
        };
    }

    if field.is_map {
        if let Some((key_ty, val_ty)) = extract_map_types(&field.ty) {
            let key_wire_type = wire_type_for_type(&key_ty);
            let val_wire_type = wire_type_for_type(&val_ty);

            return quote! {
                for (k, v) in &self.#name {

                    let mut entry_size = 0usize;

                    let key_field_key = ::lagrange_proto::wire::encode_key(1, #key_wire_type);
                    entry_size += ::lagrange_proto::helpers::get_varint_length_u32(key_field_key);
                    entry_size += k.encoded_size();

                    let val_field_key = ::lagrange_proto::wire::encode_key(2, #val_wire_type);
                    entry_size += ::lagrange_proto::helpers::get_varint_length_u32(val_field_key);
                    entry_size += v.encoded_size();

                    let entry_tag = ::lagrange_proto::wire::encode_key(#tag, ::lagrange_proto::wire::WireType::LengthDelimited);
                    {
                        let mut temp = [0u8; 5];
                        let len = ::lagrange_proto::varint::encode_to_slice(entry_tag, &mut temp);
                        buf.put_slice(&temp[..len]);
                    }

                    {
                        let mut temp = [0u8; 5];
                        let len = ::lagrange_proto::varint::encode_to_slice(entry_size as u32, &mut temp);
                        buf.put_slice(&temp[..len]);
                    }

                    {
                        let mut temp = [0u8; 5];
                        let len = ::lagrange_proto::varint::encode_to_slice(key_field_key, &mut temp);
                        buf.put_slice(&temp[..len]);
                    }
                    k.encode(buf)?;

                    {
                        let mut temp = [0u8; 5];
                        let len = ::lagrange_proto::varint::encode_to_slice(val_field_key, &mut temp);
                        buf.put_slice(&temp[..len]);
                    }
                    v.encode(buf)?;
                }
            };
        }
    }

    if field.is_repeated {
        let inner_ty = extract_inner_type(&field.ty).unwrap_or_else(|| field.ty.clone());
        if field.attrs.packed && can_be_packed(&inner_ty) {
            quote! {
                if !self.#name.is_empty() {

                    let mut packed_size = 0usize;
                    for item in &self.#name {
                        packed_size += item.encoded_size();
                    }

                    let key = ::lagrange_proto::wire::encode_key(#tag, ::lagrange_proto::wire::WireType::LengthDelimited);
                    {
                        let mut temp = [0u8; 5];
                        let len = ::lagrange_proto::varint::encode_to_slice(key, &mut temp);
                        buf.put_slice(&temp[..len]);
                    }

                    {
                        let mut temp = [0u8; 5];
                        let len = ::lagrange_proto::varint::encode_to_slice(packed_size as u32, &mut temp);
                        buf.put_slice(&temp[..len]);
                    }

                    for item in &self.#name {
                        item.encode(buf)?;
                    }
                }
            }
        } else {
            quote! {
                for item in &self.#name {
                    let key = ::lagrange_proto::wire::encode_key(#tag, #wire_type);
                    {
                        let mut temp = [0u8; 5];
                        let len = ::lagrange_proto::varint::encode_to_slice(key, &mut temp);
                        buf.put_slice(&temp[..len]);
                    }
                    item.encode(buf)?;
                }
            }
        }
    } else if field.is_optional {
        quote! {
            if let Some(ref value) = self.#name {
                let key = ::lagrange_proto::wire::encode_key(#tag, #wire_type);
                {
                    let mut temp = [0u8; 5];
                    let len = ::lagrange_proto::varint::encode_to_slice(key, &mut temp);
                    buf.put_slice(&temp[..len]);
                }
                value.encode(buf)?;
            }
        }
    } else {
        quote! {
            let key = ::lagrange_proto::wire::encode_key(#tag, #wire_type);
            {
                let mut temp = [0u8; 5];
                let len = ::lagrange_proto::varint::encode_to_slice(key, &mut temp);
                buf.put_slice(&temp[..len]);
            }
            self.#name.encode(buf)?;
        }
    }
}

fn generate_field_size(field: &FieldInfo) -> TokenStream {
    let name = &field.name;
    let tag = field.tag;
    let wire_type = wire_type_for_type(&field.ty);

    if field.is_oneof {
        return quote! {
            if let Some(ref value) = self.#name {
                size += value.encoded_size();
            }
        };
    }

    if field.is_map {
        if let Some((key_ty, val_ty)) = extract_map_types(&field.ty) {
            let key_wire_type = wire_type_for_type(&key_ty);
            let val_wire_type = wire_type_for_type(&val_ty);

            return quote! {
                for (k, v) in &self.#name {

                    let entry_tag = ::lagrange_proto::wire::encode_key(#tag, ::lagrange_proto::wire::WireType::LengthDelimited);
                    size += ::lagrange_proto::helpers::get_varint_length_u32(entry_tag);

                    let mut entry_size = 0usize;

                    let key_field_key = ::lagrange_proto::wire::encode_key(1, #key_wire_type);
                    entry_size += ::lagrange_proto::helpers::get_varint_length_u32(key_field_key);
                    entry_size += k.encoded_size();

                    let val_field_key = ::lagrange_proto::wire::encode_key(2, #val_wire_type);
                    entry_size += ::lagrange_proto::helpers::get_varint_length_u32(val_field_key);
                    entry_size += v.encoded_size();

                    size += ::lagrange_proto::helpers::get_varint_length_u32(entry_size as u32);
                    size += entry_size;
                }
            };
        }
    }

    if field.is_repeated {
        let inner_ty = extract_inner_type(&field.ty).unwrap_or_else(|| field.ty.clone());
        if field.attrs.packed && can_be_packed(&inner_ty) {
            quote! {
                if !self.#name.is_empty() {
                    let key = ::lagrange_proto::wire::encode_key(#tag, ::lagrange_proto::wire::WireType::LengthDelimited);
                    size += ::lagrange_proto::helpers::get_varint_length_u32(key);

                    let mut packed_size = 0usize;
                    for item in &self.#name {
                        packed_size += item.encoded_size();
                    }

                    size += ::lagrange_proto::helpers::get_varint_length_u32(packed_size as u32);
                    size += packed_size;
                }
            }
        } else {
            quote! {
                for item in &self.#name {
                    let key = ::lagrange_proto::wire::encode_key(#tag, #wire_type);
                    size += ::lagrange_proto::helpers::get_varint_length_u32(key);
                    size += item.encoded_size();
                }
            }
        }
    } else if field.is_optional {
        quote! {
            if let Some(ref value) = self.#name {
                let key = ::lagrange_proto::wire::encode_key(#tag, #wire_type);
                size += ::lagrange_proto::helpers::get_varint_length_u32(key);
                size += value.encoded_size();
            }
        }
    } else {
        quote! {
            let key = ::lagrange_proto::wire::encode_key(#tag, #wire_type);
            size += ::lagrange_proto::helpers::get_varint_length_u32(key);
            size += self.#name.encoded_size();
        }
    }
}

fn generate_decode_value(ty: &Type) -> TokenStream {
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
        }
        "i64" => {
            quote! {
                {
                    let (value, len) = ::lagrange_proto::varint::decode_zigzag::<u64>(reader.remaining())?;
                    reader.advance(len);
                    value
                }
            }
        }
        "bool" => {
            quote! {
                {
                    let (value, len) = ::lagrange_proto::varint::decode::<u32>(reader.remaining())?;
                    reader.advance(len);
                    value != 0
                }
            }
        }
        "f32" => quote! { f32::from_bits(reader.read_fixed32()?) },
        "f64" => quote! { f64::from_bits(reader.read_fixed64()?) },

        "SInt32" | ":: lagrange_proto :: SInt32" => {
            quote! {
                {
                    let (value, len) = ::lagrange_proto::varint::decode_zigzag::<u32>(reader.remaining())?;
                    reader.advance(len);
                    ::lagrange_proto::SInt32(value)
                }
            }
        }
        "SInt64" | ":: lagrange_proto :: SInt64" => {
            quote! {
                {
                    let (value, len) = ::lagrange_proto::varint::decode_zigzag::<u64>(reader.remaining())?;
                    reader.advance(len);
                    ::lagrange_proto::SInt64(value)
                }
            }
        }
        "Fixed32" | ":: lagrange_proto :: Fixed32" => {
            quote! { ::lagrange_proto::Fixed32(reader.read_fixed32()?) }
        }
        "Fixed64" | ":: lagrange_proto :: Fixed64" => {
            quote! { ::lagrange_proto::Fixed64(reader.read_fixed64()?) }
        }
        "SFixed32" | ":: lagrange_proto :: SFixed32" => {
            quote! {
                {
                    let value = reader.read_fixed32()?;
                    ::lagrange_proto::SFixed32(value as i32)
                }
            }
        }
        "SFixed64" | ":: lagrange_proto :: SFixed64" => {
            quote! {
                {
                    let value = reader.read_fixed64()?;
                    ::lagrange_proto::SFixed64(value as i64)
                }
            }
        }

        "String" => {
            quote! {
                {
                    let data = reader.read_length_delimited()?;
                    String::from_utf8(data).map_err(::lagrange_proto::DecodeError::InvalidUtf8)?
                }
            }
        }
        "Vec < u8 >" | "Vec<u8>" => {
            quote! { reader.read_length_delimited()? }
        }
        "Bytes" | "bytes :: Bytes" | ":: bytes :: Bytes" => {
            quote! {
                {
                    let data = reader.read_length_delimited()?;
                    ::bytes::Bytes::from(data)
                }
            }
        }
        "BytesMut" | "bytes :: BytesMut" | ":: bytes :: BytesMut" => {
            quote! {
                {
                    let data = reader.read_length_delimited()?;
                    ::bytes::BytesMut::from(data.as_slice())
                }
            }
        }
        _ => {
            quote! {
                {
                    let data = reader.read_length_delimited()?;
                    ::lagrange_proto::ProtoDecode::decode(&data)?
                }
            }
        }
    }
}

fn generate_varint_decode(ty: &Type) -> TokenStream {
    quote! {
        {
            let value = #ty::decode(reader.remaining())?;
            let value_size = value.encoded_size();
            reader.advance(value_size);
            value
        }
    }
}

fn generate_field_decode(fields: &[FieldInfo], preserve_unknown: bool) -> TokenStream {
    let (oneof_fields, regular_fields): (Vec<_>, Vec<_>) = fields.iter().partition(|f| f.is_oneof);

    let field_matches = regular_fields.iter().map(|field| {
        let name = &field.name;
        let tag = field.tag;

        if field.is_map {
            if let Some((key_ty, val_ty)) = extract_map_types(&field.ty) {
                let key_decode = generate_decode_value(&key_ty);
                let val_decode = generate_decode_value(&val_ty);

                return quote! {
                    #tag => {

                        let entry_data = reader.read_length_delimited()?;
                        let mut entry_reader = ::lagrange_proto::decoding::FieldReader::new(&entry_data);

                        let mut key: Option<#key_ty> = None;
                        let mut value: Option<#val_ty> = None;

                        while entry_reader.has_remaining() {
                            let (entry_tag, entry_wire_type) = entry_reader.read_field_key()?;
                            match entry_tag {
                                1 => {

                                    let reader = &mut entry_reader;
                                    key = Some(#key_decode);
                                }
                                2 => {

                                    let reader = &mut entry_reader;
                                    value = Some(#val_decode);
                                }
                                _ => {

                                    entry_reader.skip_field(entry_wire_type)?;
                                }
                            }
                        }

                        if let (Some(k), Some(v)) = (key, value) {
                            result.#name.insert(k, v);
                        }
                    }
                };
            }
        }

        let decode_ty = if field.is_optional || field.is_repeated {
            extract_inner_type(&field.ty).unwrap_or_else(|| field.ty.clone())
        } else {
            field.ty.clone()
        };

        let decode_value = generate_decode_value(&decode_ty);

        if field.is_repeated {

            if field.attrs.packed && can_be_packed(&decode_ty) {

                quote! {
                    #tag => {

                        if wire_type == ::lagrange_proto::wire::WireType::LengthDelimited {

                            let data = reader.read_length_delimited()?;
                            let mut packed_reader = ::lagrange_proto::decoding::FieldReader::new(&data);
                            while packed_reader.has_remaining() {

                                let reader = &mut packed_reader;
                                let value = #decode_value;
                                result.#name.push(value);
                            }
                        } else {

                            let value = #decode_value;
                            result.#name.push(value);
                        }
                    }
                }
            } else {

                quote! {
                    #tag => {
                        let value = #decode_value;
                        result.#name.push(value);
                    }
                }
            }
        } else if field.is_optional {

            let type_str = quote!(#decode_ty).to_string();
            let type_str_trimmed = type_str.trim();

            let is_known_primitive = matches!(
                type_str_trimmed,
                "u32" | "u64" | "i32" | "i64" | "bool" | "f32" | "f64" |
                "String" | "Vec < u8 >" | "Vec<u8>" |
                "Bytes" | "bytes :: Bytes" | ":: bytes :: Bytes" |
                "BytesMut" | "bytes :: BytesMut" | ":: bytes :: BytesMut" |
                "SInt32" | "SInt64" | "Fixed32" | "Fixed64" | "SFixed32" | "SFixed64" |
                ":: lagrange_proto :: SInt32" | ":: lagrange_proto :: SInt64" |
                ":: lagrange_proto :: Fixed32" | ":: lagrange_proto :: Fixed64" |
                ":: lagrange_proto :: SFixed32" | ":: lagrange_proto :: SFixed64"
            );

            if !is_known_primitive {

                let varint_decode = generate_varint_decode(&decode_ty);
                quote! {
                    #tag => {
                        if wire_type == ::lagrange_proto::wire::WireType::Varint {
                            result.#name = Some(#varint_decode);
                        } else {
                            let value = #decode_value;
                            result.#name = Some(value);
                        }
                    }
                }
            } else {
                quote! {
                    #tag => {
                        let value = #decode_value;
                        result.#name = Some(value);
                    }
                }
            }
        } else {

            let type_str = quote!(#decode_ty).to_string();
            let type_str_trimmed = type_str.trim();

            let is_known_primitive = matches!(
                type_str_trimmed,
                "u32" | "u64" | "i32" | "i64" | "bool" | "f32" | "f64" |
                "String" | "Vec < u8 >" | "Vec<u8>" |
                "Bytes" | "bytes :: Bytes" | ":: bytes :: Bytes" |
                "BytesMut" | "bytes :: BytesMut" | ":: bytes :: BytesMut" |
                "SInt32" | "SInt64" | "Fixed32" | "Fixed64" | "SFixed32" | "SFixed64" |
                ":: lagrange_proto :: SInt32" | ":: lagrange_proto :: SInt64" |
                ":: lagrange_proto :: Fixed32" | ":: lagrange_proto :: Fixed64" |
                ":: lagrange_proto :: SFixed32" | ":: lagrange_proto :: SFixed64"
            );

            if !is_known_primitive {

                let varint_decode = generate_varint_decode(&decode_ty);
                quote! {
                    #tag => {
                        if wire_type == ::lagrange_proto::wire::WireType::Varint {
                            result.#name = #varint_decode;
                        } else {

                            result.#name = #decode_value;
                        }
                    }
                }
            } else {
                quote! {
                    #tag => {
                        result.#name = #decode_value;
                    }
                }
            }
        }
    });

    let oneof_handlers = oneof_fields.iter().map(|field| {
        let name = &field.name;

        let oneof_ty = if field.is_optional {
            extract_inner_type(&field.ty).unwrap_or_else(|| field.ty.clone())
        } else {
            field.ty.clone()
        };

        quote! {
            if let Ok(value) = #oneof_ty::decode_with_tag(tag, wire_type, &mut reader) {
                result.#name = Some(value);
                oneof_handled = true;
            }
        }
    });

    let unknown_handler = if preserve_unknown {
        quote! {

            if !oneof_handled {
                let data = reader.read_field_data(wire_type)?;
                result._unknown_fields.add(tag, wire_type, data);
            }
        }
    } else {
        quote! {

            if !oneof_handled {
                reader.skip_field(wire_type)?;
            }
        }
    };

    quote! {
        let mut oneof_handled = false;
        match tag {
            #(#field_matches)*
            _ => {

                #(#oneof_handlers)*

                #unknown_handler
            }
        }
    }
}

fn generate_default_init(fields: &[FieldInfo], preserve_unknown: bool) -> TokenStream {
    let inits = fields.iter().map(|field| {
        let name = &field.name;

        if let Some(ref default_val) = field.attrs.default {
            let default_expr = parse_default_value(&field.ty, default_val);
            quote! { #name: #default_expr }
        } else if field.is_optional {
            quote! { #name: None }
        } else if field.is_repeated {
            quote! { #name: Vec::new() }
        } else {
            quote! { #name: Default::default() }
        }
    });

    if preserve_unknown {
        quote! {
            #(#inits,)*
            _unknown_fields: ::lagrange_proto::UnknownFields::new()
        }
    } else {
        quote! {
            #(#inits),*
        }
    }
}

fn parse_default_value(ty: &Type, default_str: &str) -> TokenStream {
    let type_str = quote!(#ty).to_string();
    let type_str = type_str.trim();

    match type_str {
        "u32" | "u64" | "i32" | "i64" | "usize" | "isize" => {
            if let Ok(num) = default_str.parse::<i64>() {
                quote! { #num as #ty }
            } else {
                quote! { Default::default() }
            }
        }
        "f32" | "f64" => {
            if let Ok(num) = default_str.parse::<f64>() {
                quote! { #num as #ty }
            } else {
                quote! { Default::default() }
            }
        }
        "bool" => match default_str {
            "true" => quote! { true },
            "false" => quote! { false },
            _ => quote! { Default::default() },
        },
        "String" => {
            quote! { #default_str.to_string() }
        }
        "SInt32" | ":: lagrange_proto :: SInt32" => {
            if let Ok(num) = default_str.parse::<i32>() {
                quote! { ::lagrange_proto::SInt32(#num) }
            } else {
                quote! { ::lagrange_proto::SInt32(0) }
            }
        }
        "SInt64" | ":: lagrange_proto :: SInt64" => {
            if let Ok(num) = default_str.parse::<i64>() {
                quote! { ::lagrange_proto::SInt64(#num) }
            } else {
                quote! { ::lagrange_proto::SInt64(0) }
            }
        }
        "Fixed32" | ":: lagrange_proto :: Fixed32" => {
            if let Ok(num) = default_str.parse::<u32>() {
                quote! { ::lagrange_proto::Fixed32(#num) }
            } else {
                quote! { ::lagrange_proto::Fixed32(0) }
            }
        }
        "Fixed64" | ":: lagrange_proto :: Fixed64" => {
            if let Ok(num) = default_str.parse::<u64>() {
                quote! { ::lagrange_proto::Fixed64(#num) }
            } else {
                quote! { ::lagrange_proto::Fixed64(0) }
            }
        }
        "SFixed32" | ":: lagrange_proto :: SFixed32" => {
            if let Ok(num) = default_str.parse::<i32>() {
                quote! { ::lagrange_proto::SFixed32(#num) }
            } else {
                quote! { ::lagrange_proto::SFixed32(0) }
            }
        }
        "SFixed64" | ":: lagrange_proto :: SFixed64" => {
            if let Ok(num) = default_str.parse::<i64>() {
                quote! { ::lagrange_proto::SFixed64(#num) }
            } else {
                quote! { ::lagrange_proto::SFixed64(0) }
            }
        }
        _ => {
            let ident = syn::Ident::new(default_str, proc_macro2::Span::call_site());
            quote! { #ty::#ident }
        }
    }
}

pub fn expand_derive_proto_message(input: DeriveInput) -> Result<TokenStream> {
    let name = &input.ident;

    let msg_attrs = ProtoMessageAttrs::from_derive_input(&input)?;

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(FieldsNamed { named, .. }) => named,
            _ => {
                return Err(Error::new_spanned(
                    input,
                    "ProtoMessage only supports structs with named fields",
                ))
            }
        },
        _ => {
            return Err(Error::new_spanned(
                input,
                "ProtoMessage can only be derived for structs",
            ))
        }
    };

    let has_unknown_fields = fields.iter().any(|f| {
        f.ident
            .as_ref()
            .map(|id| id == "_unknown_fields")
            .unwrap_or(false)
    });

    if msg_attrs.preserve_unknown && !has_unknown_fields {
        return Err(Error::new_spanned(
            input,
            "When using #[proto(preserve_unknown)], the struct must have a field: pub _unknown_fields: UnknownFields",
        ));
    }

    let mut field_infos = Vec::new();
    for field in fields {
        let field_name = field.ident.as_ref().unwrap().clone();

        if field_name == "_unknown_fields" {
            continue;
        }

        let attrs = extract_field_attrs(field)?;
        let is_oneof = attrs.oneof.is_some();
        let tag = if is_oneof { 0 } else { attrs.tag.unwrap() };
        let ty = field.ty.clone();
        let is_optional = is_option(&ty);
        let is_repeated = is_vec(&ty);
        let is_map = is_map(&ty);

        field_infos.push(FieldInfo {
            name: field_name,
            tag,
            ty,
            is_optional,
            is_repeated,
            is_map,
            is_oneof,
            attrs,
        });
    }

    let encode_fields = field_infos.iter().map(generate_field_encode);

    let size_fields = field_infos.iter().map(generate_field_size);

    let unknown_encode = if msg_attrs.preserve_unknown {
        quote! { self._unknown_fields.encode(buf)?; }
    } else {
        quote! {}
    };

    let unknown_size = if msg_attrs.preserve_unknown {
        quote! { size += self._unknown_fields.encoded_size(); }
    } else {
        quote! {}
    };

    let decode_match = generate_field_decode(&field_infos, msg_attrs.preserve_unknown);
    let default_init = generate_default_init(&field_infos, msg_attrs.preserve_unknown);

    let expanded = quote! {
        impl ::lagrange_proto::ProtoEncode for #name {
            fn encode<B: ::bytes::BufMut>(&self, buf: &mut B) -> Result<(), ::lagrange_proto::EncodeError> {
                #(#encode_fields)*
                #unknown_encode
                Ok(())
            }

            fn encoded_size(&self) -> usize {
                let mut size = 0;
                #(#size_fields)*
                #unknown_size
                size
            }
        }

        impl ::lagrange_proto::ProtoDecode for #name {
            fn decode(buf: &[u8]) -> Result<Self, ::lagrange_proto::DecodeError> {
                let mut reader = ::lagrange_proto::decoding::FieldReader::new(buf);
                let mut result = Self {
                    #default_init
                };

                while reader.has_remaining() {
                    let (tag, wire_type) = reader.read_field_key()?;
                    #decode_match
                }

                Ok(result)
            }
        }
    };

    Ok(expanded)
}
