// ============================================================
// サイト名の正規化
// ============================================================

/// サイト名の指定を、saltに使う形（ホスト名）へ揃える。
///
/// `https://GitHub.com/login` と `github.com` のように表記が違うだけの指定から
/// 別のパスワードが生成されるのを防ぐため、次の順で不要な部分を取り除く。
///
/// 1. スキーム（`https://` など）と、スキーム付きの場合のユーザー情報（`user@`）
/// 2. パス・クエリ・フラグメント
/// 3. ポート番号
/// 4. 大文字（小文字に揃える）、末尾の `.`、先頭の `www.`
///
/// サブドメインの統合（`accounts.google.com` → `google.com`）は行わない。
/// 統合にはPublic Suffix Listが必要で、リストの更新によって将来の結果が
/// 変わりうるため、決定論的な生成とは相性が悪い。
pub fn normalize(input: &str) -> String {
    let s = input.trim();
    let (has_scheme, s) = match s.split_once("://") {
        Some((_, rest)) => (true, rest),
        None => (false, s),
    };
    let s = s.split(['/', '?', '#']).next().unwrap_or("");
    // スキームのない指定では `@` を含む名前（メールアドレスなど）をそのまま残す
    let s = if has_scheme {
        s.rsplit_once('@').map_or(s, |(_, host)| host)
    } else {
        s
    };
    let s = strip_port(s).to_lowercase();
    let s = s.trim_end_matches('.');
    s.strip_prefix("www.").unwrap_or(s).to_string()
}

fn strip_port(host: &str) -> &str {
    // IPv6リテラル（[::1]:8080）は括弧の中にも `:` があるため、括弧までを残す
    if host.starts_with('[') {
        return match host.find(']') {
            Some(end) => &host[..=end],
            None => host,
        };
    }
    match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_host_is_unchanged() {
        assert_eq!(normalize("github.com"), "github.com");
        assert_eq!(normalize("bank.example.com"), "bank.example.com");
    }

    #[test]
    fn test_url_is_reduced_to_host() {
        assert_eq!(normalize("https://github.com/login?x=1#top"), "github.com");
        assert_eq!(normalize("http://github.com"), "github.com");
        assert_eq!(normalize("github.com/login"), "github.com");
        assert_eq!(normalize("https://user:pw@github.com/"), "github.com");
    }

    #[test]
    fn test_case_www_port_and_trailing_dot() {
        assert_eq!(normalize("GitHub.com"), "github.com");
        assert_eq!(normalize("www.github.com:443/"), "github.com");
        assert_eq!(normalize("github.com."), "github.com");
        assert_eq!(normalize("  github.com  "), "github.com");
    }

    #[test]
    fn test_subdomain_is_kept() {
        assert_eq!(normalize("accounts.google.com"), "accounts.google.com");
    }

    #[test]
    fn test_ipv6_literal() {
        assert_eq!(normalize("http://[::1]:8080/admin"), "[::1]");
    }

    #[test]
    fn test_at_sign_without_scheme_is_kept() {
        assert_eq!(normalize("me@example.com"), "me@example.com");
    }

    #[test]
    fn test_non_numeric_suffix_is_not_a_port() {
        assert_eq!(normalize("github.com:work"), "github.com:work");
    }

    #[test]
    fn test_empty() {
        assert_eq!(normalize(""), "");
        assert_eq!(normalize("https://"), "");
    }
}
