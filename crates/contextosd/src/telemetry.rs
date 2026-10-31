//! Structured logs and optional OpenTelemetry trace export.
//!
//! Logs are JSON on stdout, filtered by `RUST_LOG` (default `info`). With the `otlp` feature, setting
//! `OTEL_EXPORTER_OTLP_ENDPOINT` (or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) also exports
//! spans over OTLP/HTTP, configured by the standard `OTEL_*` variables, and incoming
//! W3C `traceparent` headers become the parent of each request span, so a dispatch
//! appears inside the caller's distributed trace.

use axum::http as http_types;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Flushes exported spans on shutdown.
#[must_use]
#[derive(Debug)]
pub struct Telemetry {
    #[cfg(feature = "otlp")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl Telemetry {
    #[cfg_attr(not(feature = "otlp"), allow(clippy::unused_async))]
    pub async fn shutdown(self) {
        #[cfg(feature = "otlp")]
        if let Some(provider) = self.provider {
            let _ = tokio::task::spawn_blocking(move || provider.shutdown()).await;
        }
    }
}

/// Installs the global subscriber, exporting traces when the `OTEL_*` endpoint
/// variables are set. Call once, inside the Tokio runtime.
pub fn init() -> Result<Telemetry, String> {
    init_with(None)
}

/// As [`init`], exporting to `otlp_traces_url` (a full `/v1/traces` URL) when given.
pub fn init_with(otlp_traces_url: Option<&str>) -> Result<Telemetry, String> {
    let registry = tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().json());
    #[cfg(feature = "otlp")]
    {
        let provider = otlp::provider(otlp_traces_url)?;
        let layer = provider.as_ref().map(|p| {
            use opentelemetry::trace::TracerProvider as _;
            tracing_opentelemetry::layer().with_tracer(p.tracer("contextosd"))
        });
        registry.with(layer).try_init().map_err(|e| e.to_string())?;
        Ok(Telemetry { provider })
    }
    #[cfg(not(feature = "otlp"))]
    {
        let _ = otlp_traces_url;
        registry.try_init().map_err(|e| e.to_string())?;
        Ok(Telemetry {})
    }
}

/// Makes the caller's W3C trace context, if any, the parent of `span`.
#[cfg_attr(not(feature = "otlp"), allow(unused_variables))]
pub fn link_parent(span: &tracing::Span, headers: &http_types::HeaderMap) {
    #[cfg(feature = "otlp")]
    {
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;
        let parent = opentelemetry::global::get_text_map_propagator(|p| {
            p.extract(&opentelemetry_http::HeaderExtractor(headers))
        });
        let _ = span.set_parent(parent);
    }
}

#[cfg(feature = "otlp")]
mod otlp {
    use std::time::Duration;

    use bytes::Bytes;
    use opentelemetry_http::{HttpClient, HttpError, Request, Response};
    use opentelemetry_otlp::{SpanExporter, WithHttpConfig as _};
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use opentelemetry_sdk::trace::SdkTracerProvider;

    const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

    /// Sends exports through the server's rustls `reqwest` client. The batch
    /// processor may poll exports outside Tokio, so requests run on the runtime.
    #[derive(Debug)]
    struct ExportClient {
        inner: reqwest::Client,
        runtime: tokio::runtime::Handle,
    }

    #[async_trait::async_trait]
    impl HttpClient for ExportClient {
        async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
            let inner = self.inner.clone();
            self.runtime
                .spawn(async move {
                    let response = inner.execute(reqwest::Request::try_from(request)?).await?;
                    let (status, headers) = (response.status(), response.headers().clone());
                    if response.content_length().is_some_and(|n| n > MAX_RESPONSE_BYTES as u64) {
                        return Err("otlp response too large".into());
                    }
                    let body = response.bytes().await?;
                    let mut out = Response::builder().status(status).body(body)?;
                    *out.headers_mut() = headers;
                    Ok(out)
                })
                .await?
        }
    }

    fn configured() -> bool {
        ["OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"]
            .iter()
            .any(|var| std::env::var_os(var).is_some_and(|v| !v.is_empty()))
    }

    pub(super) fn provider(endpoint: Option<&str>) -> Result<Option<SdkTracerProvider>, String> {
        if endpoint.is_none() && !configured() {
            return Ok(None);
        }
        let client = ExportClient {
            inner: contextos_adapters::tls::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(|e| e.to_string())?,
            runtime: tokio::runtime::Handle::try_current().map_err(|e| e.to_string())?,
        };
        let mut builder = SpanExporter::builder().with_http().with_http_client(client);
        if let Some(endpoint) = endpoint {
            use opentelemetry_otlp::WithExportConfig as _;
            builder = builder.with_endpoint(endpoint);
        }
        let exporter = builder.build().map_err(|e| format!("otlp exporter: {e}"))?;
        let mut resource = Resource::builder();
        if std::env::var_os("OTEL_SERVICE_NAME").is_none() {
            resource = resource.with_service_name("contextosd");
        }
        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
        Ok(Some(
            SdkTracerProvider::builder()
                .with_resource(resource.build())
                .with_batch_exporter(exporter)
                .build(),
        ))
    }
}
