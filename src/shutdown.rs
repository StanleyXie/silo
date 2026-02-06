//! Graceful shutdown handling with session draining
//!
//! This module provides functionality for gracefully stopping Silo services
//! while ensuring active Terraform sessions are properly completed.

use crate::backend::StorageBackend;
use log::{error, info, warn};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Information about an active session
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: String,
    pub workspace: String,
    pub operation: String,
    pub identity: String,
    pub elapsed_secs: u64,
}

/// Result of session draining
#[derive(Debug)]
pub enum DrainResult {
    /// All sessions completed naturally
    AllSessionsCompleted,
    /// Timeout reached with sessions still active
    TimeoutWithSessions(Vec<SessionInfo>),
    /// Forced shutdown requested
    ForcedShutdown,
    /// No sessions were active
    NoSessions,
}

/// Manages graceful shutdown with session awareness
pub struct GracefulShutdown {
    storage: Arc<dyn StorageBackend>,
    timeout: Duration,
}

impl GracefulShutdown {
    pub fn new(storage: Arc<dyn StorageBackend>, timeout_secs: u64) -> Self {
        Self {
            storage,
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// Get list of currently active sessions
    pub async fn get_active_sessions(&self) -> Vec<SessionInfo> {
        let mut sessions = Vec::new();

        match self.storage.list("secret/silo/sessions/").await {
            Ok(keys) => {
                for key in keys {
                    let path = format!("secret/silo/sessions/{}", key);
                    if let Ok(Some(data)) = self.storage.get(&path).await {
                        if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&data) {
                            let session_id = key.clone();
                            let workspace = meta
                                .get("workspace")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            let operation = meta
                                .get("project_instance")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            let identity = meta
                                .get("identity")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();

                            // Calculate elapsed time
                            let elapsed_secs = if let Some(start_str) =
                                meta.get("start_time").and_then(|v| v.as_str())
                            {
                                if let Ok(start) = chrono::DateTime::parse_from_rfc3339(start_str) {
                                    (chrono::Utc::now() - start.with_timezone(&chrono::Utc))
                                        .num_seconds()
                                        .max(0) as u64
                                } else {
                                    0
                                }
                            } else {
                                0
                            };

                            sessions.push(SessionInfo {
                                session_id,
                                workspace,
                                operation,
                                identity,
                                elapsed_secs,
                            });
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to list sessions: {}", e);
            }
        }

        sessions
    }

    /// Wait for all sessions to complete, with timeout
    pub async fn drain_sessions(&self) -> DrainResult {
        let start = Instant::now();
        let poll_interval = Duration::from_secs(2);

        loop {
            let sessions = self.get_active_sessions().await;

            if sessions.is_empty() {
                if start.elapsed() < Duration::from_secs(1) {
                    return DrainResult::NoSessions;
                }
                return DrainResult::AllSessionsCompleted;
            }

            if start.elapsed() >= self.timeout {
                return DrainResult::TimeoutWithSessions(sessions);
            }

            // Log waiting status
            info!(
                "Waiting for {} active session(s) to complete...",
                sessions.len()
            );

            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Send SIGTERM and wait for process to terminate
    pub fn stop_process_gracefully(pid: u32, wait_timeout: Duration) -> bool {
        #[cfg(unix)]
        {
            use std::process::Command;

            // Send SIGTERM
            let _ = Command::new("kill")
                .arg("-SIGTERM")
                .arg(pid.to_string())
                .status();

            // Wait for process to exit
            let start = Instant::now();
            let poll_interval = Duration::from_millis(200);

            while start.elapsed() < wait_timeout {
                // Check if process is still running
                let running = Command::new("kill")
                    .arg("-0")
                    .arg(pid.to_string())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);

                if !running {
                    return true; // Process terminated
                }

                std::thread::sleep(poll_interval);
            }

            // Timeout - force kill
            warn!(
                "Process {} did not terminate gracefully, sending SIGKILL",
                pid
            );
            let _ = Command::new("kill")
                .arg("-SIGKILL")
                .arg(pid.to_string())
                .status();

            false
        }

        #[cfg(windows)]
        {
            use std::process::Command;

            let _ = Command::new("taskkill")
                .arg("/F")
                .arg("/PID")
                .arg(pid.to_string())
                .status();

            true
        }
    }
}

/// Print active sessions in a user-friendly format
pub fn print_sessions(sessions: &[SessionInfo]) {
    for session in sessions {
        let elapsed = format_duration(session.elapsed_secs);
        println!(
            "   - {} (workspace: {}, user: {}, {})",
            session.operation, session.workspace, session.identity, elapsed
        );
    }
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s elapsed", secs)
    } else if secs < 3600 {
        format!("{}m {}s elapsed", secs / 60, secs % 60)
    } else {
        format!("{}h {}m elapsed", secs / 3600, (secs % 3600) / 60)
    }
}
