use axum_server::tls_rustls::RustlsConfig;
use config::{Config, ConfigError, Environment, File, FileFormat};
use jiff::Span;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{debug, trace};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) enum CertType {
    PemFiles { cert: PathBuf, key: PathBuf },
    Adhoc,
}

impl CertType {
    pub(crate) async fn to_rustlsconfig(&self, fqdn: &Option<String>) -> RustlsConfig {
        trace!("Converting CertType to RustlsConfig");
        match self {
            CertType::PemFiles{cert, key} => {
                debug!(?cert, ?key, "Loading PEM files for TLS");
                RustlsConfig::from_pem_file(cert, key)
                    .await
                    .unwrap()
            }
            CertType::Adhoc => CertType::generate_adhoc(fqdn).await,
        }
    }

    async fn generate_adhoc(fqdn: &Option<String>) -> RustlsConfig {
        trace!("Generating ad-hoc TLS certificate");
        let mut domains = vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ];
        if let Some(fqdn) = fqdn {
            debug!(%fqdn, "Adding FQDN to ad-hoc cert domains");
            domains.push(fqdn.clone())
        }

        let CertifiedKey { cert, signing_key } = generate_simple_self_signed(domains).unwrap();

        RustlsConfig::from_pem(
            cert.pem().into_bytes(),
            signing_key.serialize_pem().into_bytes(),
        )
        .await
        .unwrap()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct Settings {
    pub storage_path: PathBuf,
    pub tls_config: CertType,
    pub bind_http: Option<SocketAddr>,
    pub bind_https: SocketAddr,
    pub upload_size_limit: usize,
    pub max_file_age: Span,
    pub min_file_age: Span,
    pub fqdn: Option<String>,
    pub favicon: Option<PathBuf>,
}

impl Settings {
    pub(crate) fn new() -> Result<Self, ConfigError> {
        trace!("Loading settings from config files and environment");
        let run_mode = std::env::var("RUN_MODE").unwrap_or_else(|_| "development".into());
        let s = Config::builder()
            .add_source(File::from_str(
                include_str!("default.toml"),
                FileFormat::Toml,
            ))
            .add_source(File::with_name("config").required(false))
            .add_source(File::with_name(run_mode.as_str()).required(false))
            .add_source(File::with_name("local").required(false))
            .add_source(Environment::with_prefix("CABINET"))
            .build()?;
        let settings: Settings = s.try_deserialize()?;
        debug!(settings = ?settings, "Settings loaded");
        Ok(settings)
    }

    pub(crate) fn fqdn_https(&self) -> String {
        trace!("Resolving FQDN for HTTPS");
        match self.fqdn {
            Some(ref fqdn) => fqdn.clone(),
            None => self.bind_https.to_string(),
        }
    }
}
