// SPDX-License-Identifier: MIT
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

pub fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

pub fn finish(pb: &ProgressBar, msg: &str) {
    pb.set_style(ProgressStyle::with_template("✓ {msg}").unwrap());
    pb.finish_with_message(msg.to_string());
}

#[allow(dead_code)]
pub fn fail(pb: &ProgressBar, msg: &str) {
    pb.set_style(ProgressStyle::with_template("✗ {msg}").unwrap());
    pb.finish_with_message(msg.to_string());
}
