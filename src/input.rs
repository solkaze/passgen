use std::fs;
use std::io::Write;

#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::io::FromRawFd;
#[cfg(unix)]
use termios::{tcsetattr, Termios, ECHO, ECHONL, ICANON, TCSAFLUSH};

// ============================================================
// コアパスワード入力
// ============================================================

#[cfg(unix)]
pub fn prompt_masked(prompt: &str) -> String {
    let stdin_fd = 0;
    let mut termios = Termios::from_fd(stdin_fd).expect("termios の取得に失敗しました");
    let original = termios;
    termios.c_lflag &= !(ECHO | ECHONL | ICANON);
    tcsetattr(stdin_fd, TCSAFLUSH, &termios).expect("termios の設定に失敗しました");

    let tty_fd = unsafe { libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR) };
    if tty_fd < 0 {
        eprintln!("エラー: /dev/tty を開けませんでした");
        std::process::exit(1);
    }
    let mut tty = unsafe { fs::File::from_raw_fd(tty_fd) };

    write!(tty, "{}", prompt).unwrap();
    tty.flush().unwrap();

    let mut password = String::new();
    let mut buf = [0u8; 1];
    loop {
        tty.read_exact(&mut buf)
            .expect("入力の読み込みに失敗しました");
        match buf[0] {
            b'\n' | b'\r' => {
                writeln!(tty).unwrap();
                tty.flush().unwrap();
                break;
            }
            127 | 8 => {
                if !password.is_empty() {
                    password.pop();
                    write!(tty, "\x08 \x08").unwrap();
                    tty.flush().unwrap();
                }
            }
            c if c >= 0x20 => {
                password.push(c as char);
                write!(tty, "*").unwrap();
                tty.flush().unwrap();
            }
            _ => {}
        }
    }
    tcsetattr(stdin_fd, TCSAFLUSH, &original).expect("termios の復元に失敗しました");
    password
}

#[cfg(windows)]
pub fn prompt_masked(prompt: &str) -> String {
    rpassword::prompt_password(prompt).expect("入力エラー")
}
