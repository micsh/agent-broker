use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;

/// Per-project token-bucket rate limiter. Keyed by project name.
pub struct ProjectRateLimiter {
    inner: DefaultKeyedRateLimiter<String>,
}

impl ProjectRateLimiter {
    pub fn new(rps: u32) -> Self {
        let quota = Quota::per_second(
            NonZeroU32::new(rps.max(1)).expect("rps must be > 0"),
        );
        Self { inner: RateLimiter::keyed(quota) }
    }

    /// Returns true if the request is allowed, false if rate-limited.
    pub fn check(&self, project: &str) -> bool {
        self.inner.check_key(&project.to_string()).is_ok()
    }
}

/// Tower middleware: rate-limits by X-Project header value.
/// Exempt routes (health, register, read-only) must NOT have this layer applied.
/// Returns 429 with Retry-After: 1 header if limit exceeded.
/// Requests with no or empty X-Project pass through unthrottled (auth will reject them downstream).
pub async fn rate_limit_middleware(
    axum::extract::State(state): axum::extract::State<Arc<crate::api::routes::AppState>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let project = request
        .headers()
        .get("x-project")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !project.is_empty() && !state.rate_limiter.check(project) {
        tracing::debug!("Rate limit exceeded for project '{}'", project);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, "1")],
            "Rate limit exceeded — retry after 1 second",
        )
            .into_response();
    }

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_allows_first_then_blocks() {
        // rps=1: the first call must succeed, the second (in the same second) must fail.
        // This simulates the WS path: over-limit stanza receives an error frame, not delivery.
        let limiter = ProjectRateLimiter::new(1);
        assert!(limiter.check("proj-a"), "first request must be allowed");
        assert!(!limiter.check("proj-a"), "second request in same second must be rate-limited");
    }

    #[test]
    fn rate_limiter_buckets_are_per_project() {
        // Each project has its own independent quota bucket.
        let limiter = ProjectRateLimiter::new(1);
        assert!(limiter.check("proj-a"), "proj-a first request allowed");
        assert!(!limiter.check("proj-a"), "proj-a second request blocked");
        // proj-b has a fresh bucket — must not be affected by proj-a exhaustion
        assert!(limiter.check("proj-b"), "proj-b first request must be allowed independently");
    }
}
