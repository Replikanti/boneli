//! [`MemoryForge`]: the `Forge` port in memory.

use std::collections::VecDeque;
use std::sync::Mutex;

use boneli_app::{Forge, ForgeRef, JobFailure, PullRequest};
use boneli_domain::Ticket;

use crate::{Response, ScriptedFailure, lock};

/// Scripted outcomes of a [`MemoryForge`], one queue per operation, used
/// front to back. `Answer(())` succeeds with the next reference; an empty
/// queue also succeeds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ForgeScript {
    /// Outcomes of `post_questions`.
    pub post_questions: Vec<Response<()>>,
    /// Outcomes of `open_pull_request`.
    pub open_pull_request: Vec<Response<()>>,
}

/// One request a [`MemoryForge`] received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForgeRequest {
    /// A `post_questions` call.
    PostQuestions {
        /// The ticket.
        ticket: Ticket,
        /// The questions.
        questions: Vec<String>,
    },
    /// An `open_pull_request` call.
    OpenPullRequest(Box<PullRequest>),
}

#[derive(Debug, Default)]
struct State {
    post_questions: VecDeque<Response<()>>,
    open_pull_request: VecDeque<Response<()>>,
    /// The number of the next reference; one counter for comments and pull
    /// requests, starting at 1.
    next: u64,
    requests: Vec<ForgeRequest>,
}

/// A `Forge` that issues `comment-<n>` and `pull-<n>` from one counter
/// starting at 1, fails where its [`ForgeScript`] says so, and records every
/// request.
#[derive(Debug, Default)]
pub struct MemoryForge {
    state: Mutex<State>,
}

impl MemoryForge {
    /// A forge on which every call succeeds.
    pub fn new() -> MemoryForge {
        MemoryForge::scripted(ForgeScript::default())
    }

    /// A forge that follows `script`.
    pub fn scripted(script: ForgeScript) -> MemoryForge {
        MemoryForge {
            state: Mutex::new(State {
                post_questions: script.post_questions.into(),
                open_pull_request: script.open_pull_request.into(),
                next: 1,
                requests: Vec::new(),
            }),
        }
    }

    /// Every request received so far, in order.
    pub fn requests(&self) -> Vec<ForgeRequest> {
        lock(&self.state).requests.clone()
    }

    /// Records the request, then fails as scripted or issues
    /// `<prefix>-<n>`.
    fn call(&self, request: ForgeRequest, prefix: &str) -> Result<ForgeRef, JobFailure> {
        let mut state = lock(&self.state);
        let step = match &request {
            ForgeRequest::PostQuestions { .. } => state.post_questions.pop_front(),
            ForgeRequest::OpenPullRequest(_) => state.open_pull_request.pop_front(),
        };
        state.requests.push(request);
        if let Some(Response::Fail(failure)) = step {
            return Err(ScriptedFailure::to_failure(&failure));
        }
        let n = state.next;
        state.next = n.saturating_add(1);
        ForgeRef::parse(&format!("{prefix}-{n}"))
            .ok_or_else(|| JobFailure::new("the forge issued a blank reference", "", 0))
    }
}

impl Forge for MemoryForge {
    fn post_questions(
        &self,
        ticket: &Ticket,
        questions: &[String],
    ) -> Result<ForgeRef, JobFailure> {
        let request = ForgeRequest::PostQuestions {
            ticket: ticket.clone(),
            questions: questions.to_vec(),
        };
        self.call(request, "comment")
    }

    fn open_pull_request(&self, request: &PullRequest) -> Result<ForgeRef, JobFailure> {
        self.call(
            ForgeRequest::OpenPullRequest(Box::new(request.clone())),
            "pull",
        )
    }
}
