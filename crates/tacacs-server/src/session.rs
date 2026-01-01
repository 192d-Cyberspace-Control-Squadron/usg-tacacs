// SPDX-License-Identifier: AGPL-3.0-only
use std::collections::HashSet;

#[derive(Debug, Default)]
pub struct SingleConnectState {
    pub user: Option<String>,
    pub active: bool,
    pub locked: bool,
    pub session: Option<u32>,
}

impl SingleConnectState {
    pub fn reset(&mut self) {
        self.user = None;
        self.active = false;
        self.locked = false;
        self.session = None;
    }

    pub fn activate(&mut self, user: String, session: u32) {
        self.user = Some(user);
        self.active = true;
        self.locked = true;
        self.session = Some(session);
    }
}

/// Tracks active accounting task_ids per connection to enforce RFC 8907:
/// "Clients MUST NOT reuse a task_id in a start record until it has sent
/// a stop record for that task_id."
#[derive(Debug, Default)]
pub struct TaskIdTracker {
    /// Set of task_ids that have received a START but not yet a STOP.
    active: HashSet<u32>,
}

impl TaskIdTracker {
    /// Record a START accounting event. Returns an error message if the
    /// task_id is already active (reuse violation per RFC 8907).
    pub fn start(&mut self, task_id: u32) -> Result<(), &'static str> {
        if self.active.contains(&task_id) {
            return Err(
                "task_id reuse: start record received for already-active task_id (RFC 8907 violation)",
            );
        }
        self.active.insert(task_id);
        Ok(())
    }

    /// Record a STOP accounting event. Returns an error message if no
    /// matching START was previously received.
    pub fn stop(&mut self, task_id: u32) -> Result<(), &'static str> {
        if !self.active.remove(&task_id) {
            // RFC 8907 says start and stop must match, but we issue a warning
            // rather than error since some NADs may send orphan stops.
            return Err("task_id mismatch: stop record for unknown task_id");
        }
        Ok(())
    }

    /// Record a WATCHDOG accounting event. The task_id must be active.
    pub fn watchdog(&mut self, task_id: u32) -> Result<(), &'static str> {
        if !self.active.contains(&task_id) {
            return Err("task_id mismatch: watchdog record for unknown task_id");
        }
        Ok(())
    }
}
