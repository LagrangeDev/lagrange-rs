use syn::Path;

/// Validates a path has proper structure (not empty, has segments)
pub(crate) fn validate_path_structure(path: &Path, param_name: &str) -> syn::Result<()> {
    if path.segments.is_empty() {
        return Err(syn::Error::new_spanned(
            path,
            format!("Invalid path for {}: path cannot be empty", param_name),
        ));
    }
    Ok(())
}

/// Calculates Levenshtein distance for "did you mean" suggestions
pub(crate) fn levenshtein_distance(a: &str, b: &str) -> usize {
    let len_a = a.chars().count();
    let len_b = b.chars().count();
    if len_a == 0 {
        return len_b;
    }
    if len_b == 0 {
        return len_a;
    }

    let mut matrix = vec![vec![0; len_b + 1]; len_a + 1];

    for (i, row) in matrix.iter_mut().enumerate().take(len_a + 1) {
        row[0] = i;
    }
    for j in 0..=len_b {
        matrix[0][j] = j;
    }

    for (i, ca) in a.chars().enumerate() {
        for (j, cb) in b.chars().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            matrix[i + 1][j + 1] = (matrix[i][j + 1] + 1)
                .min(matrix[i + 1][j] + 1)
                .min(matrix[i][j] + cost);
        }
    }

    matrix[len_a][len_b]
}

/// Find the closest match from a list of valid options
pub(crate) fn suggest_closest_match(input: &str, valid_options: &[&str]) -> Option<String> {
    let mut best_match = None;
    let mut best_distance = usize::MAX;

    for option in valid_options {
        let distance = levenshtein_distance(input, option);
        if distance < best_distance && distance <= 2 {
            best_distance = distance;
            best_match = Some(option.to_string());
        }
    }

    best_match
}
