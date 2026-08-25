//! Unit-cost hierarchical DRR: User → Key → Base Session → Agent → FIFO.

use std::collections::{BTreeMap, VecDeque};

use gateway_domain::{AgentId, PlatformKeyId, RequestId, SessionId, UserId};

use crate::ScheduleEntry;

#[derive(Debug, Default)]
pub(crate) struct FairQueue {
    users: BTreeMap<UserId, UserNode>,
    ring: VecDeque<UserId>,
    len: usize,
}

impl FairQueue {
    pub(crate) fn push(&mut self, entry: ScheduleEntry) {
        let user_id = entry.owner_user_id.clone();
        if !self.users.contains_key(&user_id) {
            self.users.insert(user_id.clone(), UserNode::default());
            self.ring.push_back(user_id.clone());
        }
        if let Some(user) = self.users.get_mut(&user_id) {
            user.push(entry);
            self.len += 1;
        }
    }

    pub(crate) fn pop_runnable(&mut self, mut runnable: impl FnMut(&ScheduleEntry) -> bool) -> Option<ScheduleEntry> {
        let turns = self.ring.len();
        for _ in 0..turns {
            let user_id = self.ring.pop_front()?;
            let entry = self
                .users
                .get_mut(&user_id)
                .and_then(|user| user.pop_runnable(&mut runnable));
            if self.users.get(&user_id).is_some_and(UserNode::is_empty) {
                self.users.remove(&user_id);
            } else {
                self.ring.push_back(user_id);
            }
            if entry.is_some() {
                self.len = self.len.saturating_sub(1);
                return entry;
            }
        }
        None
    }

    pub(crate) fn remove(&mut self, request_id: &RequestId) -> Option<ScheduleEntry> {
        let user_ids = self.ring.iter().cloned().collect::<Vec<_>>();
        for user_id in user_ids {
            let entry = self.users.get_mut(&user_id).and_then(|user| user.remove(request_id));
            if self.users.get(&user_id).is_some_and(UserNode::is_empty) {
                self.users.remove(&user_id);
                self.ring.retain(|candidate| candidate != &user_id);
            }
            if entry.is_some() {
                self.len = self.len.saturating_sub(1);
                return entry;
            }
        }
        None
    }

    pub(crate) fn drain(&mut self) -> Vec<ScheduleEntry> {
        let mut entries = Vec::with_capacity(self.len);
        while let Some(entry) = self.pop_runnable(|_| true) {
            entries.push(entry);
        }
        entries
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

#[derive(Debug, Default)]
struct UserNode {
    keys: BTreeMap<PlatformKeyId, KeyNode>,
    ring: VecDeque<PlatformKeyId>,
}

impl UserNode {
    fn push(&mut self, entry: ScheduleEntry) {
        let key = entry.platform_key_id.clone();
        if !self.keys.contains_key(&key) {
            self.keys.insert(key.clone(), KeyNode::default());
            self.ring.push_back(key.clone());
        }
        if let Some(node) = self.keys.get_mut(&key) {
            node.push(entry);
        }
    }

    fn pop_runnable(&mut self, runnable: &mut impl FnMut(&ScheduleEntry) -> bool) -> Option<ScheduleEntry> {
        let turns = self.ring.len();
        for _ in 0..turns {
            let key = self.ring.pop_front()?;
            let entry = self.keys.get_mut(&key).and_then(|node| node.pop_runnable(runnable));
            if self.keys.get(&key).is_some_and(KeyNode::is_empty) {
                self.keys.remove(&key);
            } else {
                self.ring.push_back(key);
            }
            if entry.is_some() {
                return entry;
            }
        }
        None
    }

    fn remove(&mut self, request_id: &RequestId) -> Option<ScheduleEntry> {
        remove_from_children(
            &mut self.keys,
            &mut self.ring,
            request_id,
            KeyNode::remove,
            KeyNode::is_empty,
        )
    }

    fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[derive(Debug, Default)]
struct KeyNode {
    sessions: BTreeMap<SessionId, SessionNode>,
    ring: VecDeque<SessionId>,
}

impl KeyNode {
    fn push(&mut self, entry: ScheduleEntry) {
        let session = entry.base_session_id.clone();
        if !self.sessions.contains_key(&session) {
            self.sessions.insert(session.clone(), SessionNode::default());
            self.ring.push_back(session.clone());
        }
        if let Some(node) = self.sessions.get_mut(&session) {
            node.push(entry);
        }
    }

    fn pop_runnable(&mut self, runnable: &mut impl FnMut(&ScheduleEntry) -> bool) -> Option<ScheduleEntry> {
        let turns = self.ring.len();
        for _ in 0..turns {
            let session = self.ring.pop_front()?;
            let entry = self
                .sessions
                .get_mut(&session)
                .and_then(|node| node.pop_runnable(runnable));
            if self.sessions.get(&session).is_some_and(SessionNode::is_empty) {
                self.sessions.remove(&session);
            } else {
                self.ring.push_back(session);
            }
            if entry.is_some() {
                return entry;
            }
        }
        None
    }

    fn remove(&mut self, request_id: &RequestId) -> Option<ScheduleEntry> {
        remove_from_children(
            &mut self.sessions,
            &mut self.ring,
            request_id,
            SessionNode::remove,
            SessionNode::is_empty,
        )
    }

    fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[derive(Debug, Default)]
struct SessionNode {
    agents: BTreeMap<AgentId, AgentNode>,
    ring: VecDeque<AgentId>,
}

impl SessionNode {
    fn push(&mut self, entry: ScheduleEntry) {
        let agent = entry.agent_id.clone();
        if !self.agents.contains_key(&agent) {
            self.agents.insert(agent.clone(), AgentNode::default());
            self.ring.push_back(agent.clone());
        }
        if let Some(node) = self.agents.get_mut(&agent) {
            node.entries.push_back(entry);
        }
    }

    fn pop_runnable(&mut self, runnable: &mut impl FnMut(&ScheduleEntry) -> bool) -> Option<ScheduleEntry> {
        let turns = self.ring.len();
        for _ in 0..turns {
            let agent = self.ring.pop_front()?;
            let entry = self.agents.get_mut(&agent).and_then(|node| node.pop_runnable(runnable));
            if self.agents.get(&agent).is_some_and(AgentNode::is_empty) {
                self.agents.remove(&agent);
            } else {
                self.ring.push_back(agent);
            }
            if entry.is_some() {
                return entry;
            }
        }
        None
    }

    fn remove(&mut self, request_id: &RequestId) -> Option<ScheduleEntry> {
        remove_from_children(
            &mut self.agents,
            &mut self.ring,
            request_id,
            AgentNode::remove,
            AgentNode::is_empty,
        )
    }

    fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }
}

#[derive(Debug, Default)]
struct AgentNode {
    entries: VecDeque<ScheduleEntry>,
}

impl AgentNode {
    fn pop_runnable(&mut self, runnable: &mut impl FnMut(&ScheduleEntry) -> bool) -> Option<ScheduleEntry> {
        if self.entries.front().is_some_and(runnable) {
            self.entries.pop_front()
        } else {
            None
        }
    }

    fn remove(&mut self, request_id: &RequestId) -> Option<ScheduleEntry> {
        let index = self.entries.iter().position(|entry| &entry.request_id == request_id)?;
        self.entries.remove(index)
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn remove_from_children<K: Clone + Ord, V>(
    children: &mut BTreeMap<K, V>,
    ring: &mut VecDeque<K>,
    request_id: &RequestId,
    remove: impl Fn(&mut V, &RequestId) -> Option<ScheduleEntry>,
    is_empty: impl Fn(&V) -> bool,
) -> Option<ScheduleEntry> {
    let keys = ring.iter().cloned().collect::<Vec<_>>();
    for key in keys {
        let entry = children.get_mut(&key).and_then(|node| remove(node, request_id));
        if children.get(&key).is_some_and(&is_empty) {
            children.remove(&key);
            ring.retain(|candidate| candidate != &key);
        }
        if entry.is_some() {
            return entry;
        }
    }
    None
}
