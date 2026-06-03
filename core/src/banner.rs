//! ASCII banner rendering for Tuora startup

use std::io::{self, Write};

const BANNER: &str = r#"████████╗██╗   ██╗ ██████╗ ██████╗  █████╗
╚══██╔══╝██║   ██║██╔═══██╗██╔══██╗██╔══██╗
   ██║   ██║   ██║██║   ██║██████╔╝███████║
   ██║   ██║   ██║██║   ██║██╔══██╗██╔══██║
   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║
   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝"#;

/// Print the Tuora ASCII banner with block-style lettering
pub fn print_banner() {
    let mut stdout = io::stdout();
    let lines: Vec<&str> = BANNER.lines().collect();
    let height = lines.len();

    // Print shadow on fresh lines, clearing each line to avoid trailing overlap.
    let _ = writeln!(stdout);
    for line in &lines {
        let _ = write!(stdout, "\r\x1b[2K\x1b[2m\x1b[36m {}\x1b[0m\n", line);
    }

    // Move cursor back up to draw the main banner on top of the shadow.
    let _ = write!(stdout, "\x1b[{}A\r", height);

    for line in &lines {
        let _ = write!(stdout, "\r\x1b[2K\x1b[1m\x1b[36m{}\x1b[0m\n", line);
    }
    let _ = stdout.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_banner_does_not_panic() {
        // Just verify the banner renders without crashing
        print_banner();
    }
}
