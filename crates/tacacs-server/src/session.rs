// SPDX-License-Identifier: AGPL-3.0-only

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
