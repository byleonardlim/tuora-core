//! Animated progress indicator for scan stages

use std::io::{self, Write};
use std::time::Duration;
use tokio::time::sleep;

fn to_single_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Animated progress renderer
pub struct Progress;

impl Progress {
    /// Show an animated spinner with message, execute the async task, then show completion
    pub async fn run<F, Fut, T, C>(message: &str, task: F, on_complete: C) -> T
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
        C: FnOnce(&T) -> Option<String>,
    {
        let message = to_single_line(message);
        let spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let mut stdout = io::stdout();
        let mut i = 0;

        // Print initial state
        let _ = write!(
            stdout,
            "\r\x1b[2K  {}\x1b[90mtuora\x1b[0m {}...",
            spinner_chars[0], message
        );
        let _ = stdout.flush();

        // Spawn the actual work
        let work = task();
        tokio::pin!(work);

        // Animate spinner while work is pending
        loop {
            tokio::select! {
                result = &mut work => {
                    let detail = on_complete(&result)
                        .map(|d| to_single_line(&d))
                        .unwrap_or_default();
                    // Clear the spinner line and print success
                    let _ = write!(
                        stdout,
                        "\r\x1b[2K  \x1b[90mtuora\x1b[0m {}... \x1b[32m✓\x1b[0m{}{}\n",
                        message,
                        if detail.is_empty() { "" } else { " " },
                        detail,
                    );
                    let _ = stdout.flush();
                    return result;
                }
                _ = sleep(Duration::from_millis(80)) => {
                    i = (i + 1) % spinner_chars.len();
                    let _ = write!(
                        stdout,
                        "\r\x1b[2K  {}\x1b[90mtuora\x1b[0m {}...",
                        spinner_chars[i],
                        message
                    );
                    let _ = stdout.flush();
                }
            }
        }
    }

    /// Print a simple status line (non-animated)
    pub fn status(message: &str) {
        let message = to_single_line(message);
        println!("  \x1b[90mtuora\x1b[0m {}", message);
    }
}
