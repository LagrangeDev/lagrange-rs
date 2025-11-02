use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    Ident, Result, Token, Visibility,
};
use walkdir::WalkDir;

use crate::service_parser;

struct AutoReexportInput {
    modules: Vec<ModuleDecl>,
}

struct ModuleDecl {
    visibility: Visibility,
    name: Ident,
}

impl Parse for AutoReexportInput {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut modules = Vec::new();

        while !input.is_empty() {
            let visibility: Visibility = input.parse()?;
            let _mod_token: Token![mod] = input.parse()?;
            let name: Ident = input.parse()?;
            let _semi: Token![;] = input.parse()?;

            modules.push(ModuleDecl {
                visibility,
                name,
            });
        }

        Ok(AutoReexportInput { modules })
    }
}

pub fn auto_reexport_impl(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as AutoReexportInput);

    let mut output = quote! {};
    let mut reexports = Vec::new();

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR not set");

    for module_decl in &input.modules {
        let vis = &module_decl.visibility;
        let mod_name = &module_decl.name;

        output = quote! {
            #output
            #vis mod #mod_name;
        };

        let items = find_public_items(&manifest_dir, &mod_name.to_string());

        if !items.is_empty() {
            reexports.push(quote! {
                #vis use #mod_name::{
                    #(#items),*
                };
            });
        }
    }

    output = quote! {
        #output

        #(#reexports)*
    };

    output.into()
}

fn find_public_items(manifest_dir: &str, module_name: &str) -> Vec<Ident> {
    let search_patterns = vec![
        ("src", format!("{}/src", manifest_dir)),
        ("src/internal", format!("{}/src/internal", manifest_dir)),
        ("src/internal/services", format!("{}/src/internal/services", manifest_dir)),
        ("src/internal/services/login", format!("{}/src/internal/services/login", manifest_dir)),
        ("src/internal/services/system", format!("{}/src/internal/services/system", manifest_dir)),
    ];

    for (_, base_path) in &search_patterns {
        let file_path = format!("{}/{}.rs", base_path, module_name);
        if std::path::Path::new(&file_path).is_file() {
            let (items, contains_auto_reexport) = parse_file_for_public_items(&file_path);

            if !contains_auto_reexport && !items.is_empty() {
                return items;
            }

            if contains_auto_reexport {
                let dir_path = format!("{}/{}", base_path, module_name);
                if std::path::Path::new(&dir_path).is_dir() {
                    return scan_directory(&dir_path);
                }
            }

            if !items.is_empty() {
                return items;
            }
        }

        let mod_file_path = format!("{}/{}/mod.rs", base_path, module_name);
        if std::path::Path::new(&mod_file_path).is_file() {
            let (items, contains_auto_reexport) = parse_file_for_public_items(&mod_file_path);

            if !contains_auto_reexport && !items.is_empty() {
                return items;
            }

            let dir_path = format!("{}/{}", base_path, module_name);
            if contains_auto_reexport && std::path::Path::new(&dir_path).is_dir() {
                return scan_directory(&dir_path);
            }

            if !items.is_empty() {
                return items;
            }
        }
    }

    Vec::new()
}

fn scan_directory(dir_path: &str) -> Vec<Ident> {
    let mut items = Vec::new();

    if !std::path::Path::new(dir_path).is_dir() {
        return items;
    }

    for entry in WalkDir::new(dir_path)
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();

        if !path.is_file() || path.extension().map(|e| e != "rs").unwrap_or(true) {
            continue;
        }

        if path.file_name().map(|n| n == "mod.rs").unwrap_or(false) {
            continue;
        }

        let (file_items, _) = parse_file_for_public_items(path.to_str().unwrap());
        items.extend(file_items);
    }

    items
}

fn parse_file_for_public_items(file_path: &str) -> (Vec<Ident>, bool) {
    let mut items = Vec::new();
    let mut contains_auto_reexport = false;

    let content = match std::fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return (items, false),
    };

    let syntax_tree = match syn::parse_file(&content) {
        Ok(tree) => tree,
        Err(_) => return (items, false),
    };

    for item in syntax_tree.items {
        match item {
            syn::Item::Struct(s) => {
                if matches!(s.vis, Visibility::Public(_)) {
                    items.push(s.ident);
                }
            }
            syn::Item::Enum(e) => {
                if matches!(e.vis, Visibility::Public(_)) {
                    items.push(e.ident);
                }
            }
            syn::Item::Type(t) => {
                if matches!(t.vis, Visibility::Public(_)) {
                    items.push(t.ident);
                }
            }
            syn::Item::Fn(f) => {
                if matches!(f.vis, Visibility::Public(_)) {
                    items.push(f.sig.ident);
                }
            }
            syn::Item::Const(c) => {
                if matches!(c.vis, Visibility::Public(_)) {
                    items.push(c.ident);
                }
            }
            syn::Item::Static(s) => {
                if matches!(s.vis, Visibility::Public(_)) {
                    items.push(s.ident);
                }
            }
            syn::Item::Trait(t) => {
                if matches!(t.vis, Visibility::Public(_)) {
                    items.push(t.ident);
                }
            }
            syn::Item::Use(u) => {
                if matches!(u.vis, Visibility::Public(_)) {
                    extract_use_items(&u.tree, &mut items);
                }
            }
            syn::Item::Macro(m) => {
                if let Some(ident) = m.mac.path.get_ident() {
                    if ident == "auto_reexport" {
                        contains_auto_reexport = true;
                    } else if ident == "define_service" {
                        items.extend(extract_define_service_types(m.mac.tokens.clone()));
                    }
                }
            }
            _ => {}
        }
    }

    (items, contains_auto_reexport)
}

fn extract_use_items(tree: &syn::UseTree, items: &mut Vec<Ident>) {
    match tree {
        syn::UseTree::Name(name) => {
            items.push(name.ident.clone());
        }
        syn::UseTree::Rename(rename) => {
            items.push(rename.rename.clone());
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                extract_use_items(item, items);
            }
        }
        syn::UseTree::Glob(_) => {}
        syn::UseTree::Path(path) => {
            extract_use_items(&path.tree, items);
        }
    }
}

fn extract_define_service_types(tokens: proc_macro2::TokenStream) -> Vec<Ident> {
    match service_parser::parse_service_tokens(tokens) {
        Ok(service_def) => service_parser::extract_generated_types(&service_def),
        Err(_) => Vec::new(),
    }
}
