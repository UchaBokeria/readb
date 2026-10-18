//! Bounded automatic restoration of already-recorded peers. No new authority.
use crate::{
    network::{Kernel, Manager},
    policy::Res,
};
use serde_json::{Value, json};
pub struct Recovery {
    due: u64,
    last: Option<u64>,
    earliest: u64,
    failures: u8,
    delay: u64,
    error: Option<String>,
    remaining: usize,
}
impl Recovery {
    pub fn new(now: u64) -> Self {
        Self {
            due: now,
            last: None,
            earliest: now,
            failures: 0,
            delay: 30000,
            error: None,
            remaining: 0,
        }
    }
    pub fn tick(
        &mut self,
        now: u64,
        event: bool,
        manager: &mut Manager,
        kernel: &mut impl Kernel,
    ) -> Option<Res<()>> {
        if event {
            self.due = self.due.min(now.max(self.earliest));
        }
        if now < self.due || now < self.earliest {
            return None;
        }
        self.last = Some(now);
        self.earliest = now.saturating_add(2000);
        let result = manager.restore_up_to(0, kernel, 1);
        match &result {
            Ok(remaining) => {
                self.failures = 0;
                self.error = None;
                self.remaining = *remaining;
                self.delay = if *remaining > 0 { 2000 } else { 30000 };
            }
            Err(error) => {
                self.failures = self.failures.saturating_add(1);
                self.error = Some(error.clone());
                self.delay =
                    (5000u64 << u32::from(self.failures.saturating_sub(1).min(4))).min(60000);
            }
        }
        self.due = now.saturating_add(self.delay);
        Some(result.map(|_| ()))
    }
    /// Runtime calls this after the bounded kernel work, so retries wait from
    /// completion rather than immediately retrying an already-slow request.
    pub fn completed_at(&mut self, now: u64) {
        self.earliest = now.saturating_add(2000);
        self.due = now.saturating_add(self.delay);
    }
    pub fn status(&self, now: u64) -> Value {
        json!({"last_attempt_ms":self.last,"next_check_in_ms":self.due.saturating_sub(now),"failures":self.failures,"last_error":self.error,"remaining":self.remaining})
    }
}
