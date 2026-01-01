// SPDX-License-Identifier: AGPL-3.0-only
//! OpenTelemetry configuration for distributed tracing.

use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource,
    runtime::Tokio,
    trace::{RandomIdGenerator, Sampler, TracerProvider as SdkTracerProvider},
};
use tracing::Subscriber;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::registry::LookupSpan;

/// OpenTelemetry configuration options.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// OTLP endpoint URL (e.g., "http://jaeger:4317").
    pub otlp_endpoint: String,
    /// Service name for traces.
    pub service_name: String,
    /// Location identifier for resource attributes.
    pub location: Option<String>,
}

impl TelemetryConfig {
    /// Create a new telemetry configuration.
    pub fn new(otlp_endpoint: String, service_name: String, location: Option<String>) -> Self {
        Self {
            otlp_endpoint,
            service_name,
            location,
        }
    }
}

/// Initialize OpenTelemetry with OTLP exporter.
///
/// Returns a tracing layer that can be added to the subscriber.
pub fn init_telemetry<S>(config: &TelemetryConfig) -> anyhow::Result<OpenTelemetryLayer<S, opentelemetry_sdk::trace::Tracer>>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    // Build resource attributes
    let mut resource_attrs = vec![
        opentelemetry::KeyValue::new("service.name", config.service_name.clone()),
    ];

    if let Some(location) = &config.location {
        resource_attrs.push(opentelemetry::KeyValue::new("location", location.clone()));
    }

    let resource = Resource::new(resource_attrs);

    // Configure OTLP exporter
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&config.otlp_endpoint)
        .build()?;

    // Build tracer provider
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter, Tokio)
        .with_sampler(Sampler::AlwaysOn)
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource)
        .build();

    let tracer = provider.tracer("tacacs-server");

    // Register the provider globally so it can be shut down later
    opentelemetry::global::set_tracer_provider(provider);

    // Create tracing layer
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);

    Ok(layer)
}

/// Shutdown OpenTelemetry, flushing any pending traces.
pub fn shutdown_telemetry() {
    opentelemetry::global::shutdown_tracer_provider();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_config_new() {
        let config = TelemetryConfig::new(
            "http://localhost:4317".to_string(),
            "test-service".to_string(),
            Some("NYC01".to_string()),
        );

        assert_eq!(config.otlp_endpoint, "http://localhost:4317");
        assert_eq!(config.service_name, "test-service");
        assert_eq!(config.location, Some("NYC01".to_string()));
    }

    #[test]
    fn test_telemetry_config_without_location() {
        let config = TelemetryConfig::new(
            "http://jaeger:4317".to_string(),
            "tacacs-server".to_string(),
            None,
        );

        assert_eq!(config.location, None);
    }
}
