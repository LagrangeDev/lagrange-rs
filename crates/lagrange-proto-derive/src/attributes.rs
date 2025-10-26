use syn::{
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    Field, Ident, Lit, Result, Token,
};

#[derive(Debug, Clone, Default)]
pub struct ProtoFieldAttrs {
    pub tag: Option<u32>,

    pub packed: bool,

    pub required: bool,

    pub optional: bool,

    pub default: Option<String>,

    pub oneof: Option<String>,

    pub map: bool,

    pub wire_type: Option<String>,
}

impl ProtoFieldAttrs {
    pub fn from_field(field: &Field) -> Result<Self> {
        let mut attrs = ProtoFieldAttrs::default();

        for attr in &field.attrs {
            if attr.path().is_ident("proto") {
                attrs.merge_with(attr.parse_args::<ProtoAttrList>()?)?;
            }
        }

        Ok(attrs)
    }

    fn merge_with(&mut self, list: ProtoAttrList) -> Result<()> {
        for attr in list.attrs {
            match attr {
                ProtoAttr::Tag(tag) => {
                    self.tag = Some(tag);
                }
                ProtoAttr::Packed => {
                    self.packed = true;
                }
                ProtoAttr::Required => {
                    self.required = true;
                }
                ProtoAttr::Optional => {
                    self.optional = true;
                }
                ProtoAttr::Default(value) => {
                    self.default = Some(value);
                }
                ProtoAttr::Oneof(name) => {
                    self.oneof = Some(name);
                }
                ProtoAttr::Map => {
                    self.map = true;
                }
                ProtoAttr::WireType(wire_type) => {
                    self.wire_type = Some(wire_type);
                }
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.required && self.optional {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "Field cannot be both required and optional",
            ));
        }

        if self.packed && self.map {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "Field cannot be both packed and map",
            ));
        }

        if self.oneof.is_some() && self.packed {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "Oneof fields cannot be packed",
            ));
        }

        Ok(())
    }
}

struct ProtoAttrList {
    attrs: Vec<ProtoAttr>,
}

impl Parse for ProtoAttrList {
    fn parse(input: ParseStream) -> Result<Self> {
        let attrs = Punctuated::<ProtoAttr, Token![,]>::parse_terminated(input)?;
        Ok(ProtoAttrList {
            attrs: attrs.into_iter().collect(),
        })
    }
}

enum ProtoAttr {
    Tag(u32),

    Packed,

    Required,

    Optional,

    Default(String),

    Oneof(String),

    Map,

    WireType(String),
}

impl Parse for ProtoAttr {
    fn parse(input: ParseStream) -> Result<Self> {
        let ident: Ident = input.parse()?;
        let name = ident.to_string();

        match name.as_str() {
            "tag" => {
                input.parse::<Token![=]>()?;
                let lit: Lit = input.parse()?;
                if let Lit::Int(int_lit) = lit {
                    Ok(ProtoAttr::Tag(int_lit.base10_parse()?))
                } else {
                    Err(syn::Error::new_spanned(
                        lit,
                        "Expected integer literal for tag",
                    ))
                }
            }
            "packed" => Ok(ProtoAttr::Packed),
            "required" => Ok(ProtoAttr::Required),
            "optional" => Ok(ProtoAttr::Optional),
            "map" => Ok(ProtoAttr::Map),
            "default" => {
                input.parse::<Token![=]>()?;
                let lit: Lit = input.parse()?;
                match lit {
                    Lit::Str(s) => Ok(ProtoAttr::Default(s.value())),
                    Lit::Int(i) => Ok(ProtoAttr::Default(i.to_string())),
                    Lit::Float(f) => Ok(ProtoAttr::Default(f.to_string())),
                    Lit::Bool(b) => Ok(ProtoAttr::Default(b.value.to_string())),
                    _ => Err(syn::Error::new_spanned(lit, "Invalid default value")),
                }
            }
            "oneof" => {
                if input.peek(Token![=]) {
                    input.parse::<Token![=]>()?;
                    let lit: Lit = input.parse()?;
                    if let Lit::Str(str_lit) = lit {
                        Ok(ProtoAttr::Oneof(str_lit.value()))
                    } else {
                        Err(syn::Error::new_spanned(
                            lit,
                            "Expected string literal for oneof",
                        ))
                    }
                } else {
                    Ok(ProtoAttr::Oneof(String::new()))
                }
            }
            "wire_type" => {
                input.parse::<Token![=]>()?;
                let lit: Lit = input.parse()?;
                if let Lit::Str(str_lit) = lit {
                    Ok(ProtoAttr::WireType(str_lit.value()))
                } else {
                    Err(syn::Error::new_spanned(
                        lit,
                        "Expected string literal for wire_type",
                    ))
                }
            }
            _ => Err(syn::Error::new_spanned(
                ident,
                format!("Unknown proto attribute: {}", name),
            )),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProtoMessageAttrs {
    pub syntax: Option<String>,

    pub preserve_unknown: bool,
}

impl ProtoMessageAttrs {
    pub fn from_derive_input(input: &syn::DeriveInput) -> Result<Self> {
        let mut attrs = ProtoMessageAttrs::default();

        for attr in &input.attrs {
            if attr.path().is_ident("proto") {
                attrs.merge_with(attr.parse_args::<ProtoMessageAttrList>()?)?;
            }
        }

        Ok(attrs)
    }

    fn merge_with(&mut self, list: ProtoMessageAttrList) -> Result<()> {
        for attr in list.attrs {
            match attr {
                ProtoMessageAttr::Syntax(syntax) => {
                    self.syntax = Some(syntax);
                }
                ProtoMessageAttr::PreserveUnknown => {
                    self.preserve_unknown = true;
                }
            }
        }
        Ok(())
    }
}

struct ProtoMessageAttrList {
    attrs: Vec<ProtoMessageAttr>,
}

impl Parse for ProtoMessageAttrList {
    fn parse(input: ParseStream) -> Result<Self> {
        let attrs = Punctuated::<ProtoMessageAttr, Token![,]>::parse_terminated(input)?;
        Ok(ProtoMessageAttrList {
            attrs: attrs.into_iter().collect(),
        })
    }
}

enum ProtoMessageAttr {
    Syntax(String),

    PreserveUnknown,
}

impl Parse for ProtoMessageAttr {
    fn parse(input: ParseStream) -> Result<Self> {
        let ident: Ident = input.parse()?;
        let name = ident.to_string();

        match name.as_str() {
            "syntax" => {
                input.parse::<Token![=]>()?;
                let lit: Lit = input.parse()?;
                if let Lit::Str(str_lit) = lit {
                    Ok(ProtoMessageAttr::Syntax(str_lit.value()))
                } else {
                    Err(syn::Error::new_spanned(
                        lit,
                        "Expected string literal for syntax",
                    ))
                }
            }
            "preserve_unknown" => Ok(ProtoMessageAttr::PreserveUnknown),
            _ => Err(syn::Error::new_spanned(
                ident,
                format!("Unknown message-level proto attribute: {}", name),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn test_parse_tag() {
        let field: Field = parse_quote! {
            #[proto(tag = 1)]
            field: u32
        };
        let attrs = ProtoFieldAttrs::from_field(&field).unwrap();
        assert_eq!(attrs.tag, Some(1));
    }

    #[test]
    fn test_parse_multiple_attrs() {
        let field: Field = parse_quote! {
            #[proto(tag = 2, packed)]
            field: Vec<u32>
        };
        let attrs = ProtoFieldAttrs::from_field(&field).unwrap();
        assert_eq!(attrs.tag, Some(2));
        assert!(attrs.packed);
    }

    #[test]
    fn test_parse_default() {
        let field: Field = parse_quote! {
            #[proto(tag = 3, default = "42")]
            field: i32
        };
        let attrs = ProtoFieldAttrs::from_field(&field).unwrap();
        assert_eq!(attrs.tag, Some(3));
        assert_eq!(attrs.default, Some("42".to_string()));
    }

    #[test]
    fn test_parse_oneof() {
        let field: Field = parse_quote! {
            #[proto(tag = 4, oneof = "my_oneof")]
            field: String
        };
        let attrs = ProtoFieldAttrs::from_field(&field).unwrap();
        assert_eq!(attrs.tag, Some(4));
        assert_eq!(attrs.oneof, Some("my_oneof".to_string()));
    }
}
