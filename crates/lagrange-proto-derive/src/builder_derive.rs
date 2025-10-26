use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, FieldsNamed, GenericArgument, PathArguments, Result, Type};

/// Information about a field for builder generation
struct BuilderFieldInfo {
    name: syn::Ident,
    param_ty: Type,
    is_option: bool,
}

/// Extract the inner type from Option<T>, Vec<T>, etc.
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

/// Check if a type is Option<T>
fn is_option(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            return segment.ident == "Option";
        }
    }
    false
}

/// Generate builder method for a single field
fn generate_builder_method(field: &BuilderFieldInfo) -> TokenStream {
    let name = &field.name;
    let param_ty = &field.param_ty;

    // Create method name with "with_" prefix
    let method_name = syn::Ident::new(&format!("with_{}", name), name.span());

    if field.is_option {
        // For Option<T> fields, take T and wrap in Some()
        quote! {
            pub fn #method_name(mut self, #name: #param_ty) -> Self {
                self.#name = Some(#name);
                self
            }
        }
    } else {
        // For other fields, just set the value
        quote! {
            pub fn #method_name(mut self, #name: #param_ty) -> Self {
                self.#name = #name;
                self
            }
        }
    }
}

/// Extract field information for builder generation
fn extract_builder_fields(fields: &FieldsNamed) -> Vec<BuilderFieldInfo> {
    fields
        .named
        .iter()
        .filter_map(|field| {
            let field_name = field.ident.as_ref()?.clone();

            // Skip _unknown_fields
            if field_name == "_unknown_fields" {
                return None;
            }

            let field_ty = field.ty.clone();
            let is_option = is_option(&field_ty);

            // For Option<T>, the parameter type is T
            // For other types, the parameter type is the same as the field type
            let param_ty = if is_option {
                extract_inner_type(&field_ty).unwrap_or_else(|| field_ty.clone())
            } else {
                field_ty.clone()
            };

            Some(BuilderFieldInfo {
                name: field_name,
                param_ty,
                is_option,
            })
        })
        .collect()
}

/// Main expansion function for ProtoBuilder derive macro
pub fn expand_derive_proto_builder(input: DeriveInput) -> Result<TokenStream> {
    let name = &input.ident;

    // Only support structs with named fields
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => fields,
            _ => {
                return Err(syn::Error::new_spanned(
                    input,
                    "ProtoBuilder only supports structs with named fields",
                ))
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "ProtoBuilder can only be derived for structs",
            ))
        }
    };

    let builder_fields = extract_builder_fields(fields);
    let builder_methods = builder_fields.iter().map(generate_builder_method);

    // Generate the impl block with new() and all builder methods
    let expanded = quote! {
        impl #name {
            /// Create a new instance with default values
            pub fn new() -> Self {
                Self::default()
            }

            #(#builder_methods)*
        }
    };

    Ok(expanded)
}
