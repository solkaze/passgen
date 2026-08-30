// ============================================================
// クリップボード処理
// ============================================================

#[cfg(unix)]
pub fn copy_to_clipboard(password: &str) {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let commands: &[(&str, &[&str])] = &[
        ("clip.exe", &[]),
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
    ];
    for (cmd, args) in commands {
        let result = Command::new(cmd).args(*args).stdin(Stdio::piped()).spawn();
        if let Ok(mut child) = result {
            if let Some(stdin) = child.stdin.take() {
                let mut stdin = stdin;
                let _ = stdin.write_all(password.as_bytes());
            }
            if child.wait().map(|s| s.success()).unwrap_or(false) {
                eprintln!("クリップボードにコピーしました。({} を使用)", cmd);
                return;
            }
        }
    }
    eprintln!("クリップボードへのコピーに失敗しました。clip.exe / wl-copy / xclip / xsel のいずれかが必要です。");
}

#[cfg(windows)]
pub fn copy_to_clipboard(password: &str) {
    use arboard::Clipboard;
    match Clipboard::new().and_then(|mut cb| cb.set_text(password)) {
        Ok(_) => eprintln!("クリップボードにコピーしました。"),
        Err(e) => eprintln!("クリップボードへのコピーに失敗しました: {}", e),
    }
}
