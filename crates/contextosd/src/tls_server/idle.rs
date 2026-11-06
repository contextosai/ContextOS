//! Closing a connection that sends no request.
//!
//! hyper's HTTP/1.1 header-read timeout starts at a request's first byte, so a client
//! that connects and sends nothing, or idles on a kept-alive connection, would hold its
//! connection slot forever. Each connection's requests are tracked here: when none is
//! in progress (its response fully sent) for the idle limit, the connection is closed.
//! A request being served, or a response still streaming, is never cut off.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::{Request, Response};
use tokio::time::Instant;
use tower::Service;

/// Requests in progress on one connection, and when the last one ended.
#[derive(Debug)]
pub(super) struct Activity {
    in_flight: AtomicUsize,
    last: Mutex<Instant>,
}

impl Activity {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            in_flight: AtomicUsize::new(0),
            last: Mutex::new(Instant::now()),
        })
    }

    fn begin(self: &Arc<Self>) -> InFlight {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        InFlight(self.clone())
    }

    fn last(&self) -> Instant {
        *self.last.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Resolves once no request has been in progress for `limit`.
    pub(super) async fn idle(&self, limit: Duration) {
        loop {
            let wake = if self.in_flight.load(Ordering::SeqCst) > 0 {
                Instant::now() + limit
            } else {
                let deadline = self.last() + limit;
                if deadline <= Instant::now() {
                    return;
                }
                deadline
            };
            tokio::time::sleep_until(wake).await;
            if self.in_flight.load(Ordering::SeqCst) == 0 && self.last() + limit <= Instant::now() {
                return;
            }
        }
    }
}

/// One request in progress, until its response body is done (or dropped).
struct InFlight(Arc<Activity>);

impl Drop for InFlight {
    fn drop(&mut self) {
        *self.0.last.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A response body that keeps its request counted as in progress until it is sent.
struct Tracked {
    inner: Body,
    _in_flight: InFlight,
}

impl http_body::Body for Tracked {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, axum::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// `app` with each request counted on `activity`.
#[derive(Clone)]
pub(super) struct Counted {
    pub(super) app: axum::Router,
    pub(super) activity: Arc<Activity>,
}

impl<B> Service<Request<B>> for Counted
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<axum::BoxError>,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Response<Body>, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Service::<Request<B>>::poll_ready(&mut self.app, cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let in_flight = self.activity.begin();
        let response = self.app.call(request);
        Box::pin(async move {
            let response = response.await?;
            Ok(response.map(|inner| {
                Body::new(Tracked {
                    inner,
                    _in_flight: in_flight,
                })
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn idle_waits_for_requests_in_progress() {
        let activity = Activity::new();
        let limit = Duration::from_millis(200);
        let request = activity.begin();
        let idle = tokio::spawn({
            let activity = activity.clone();
            async move { activity.idle(limit).await }
        });
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(!idle.is_finished(), "a request in progress keeps the connection");
        drop(request);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!idle.is_finished(), "the limit counts from the last request's end");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(idle.is_finished(), "idle past the limit after the last request");
    }
}
