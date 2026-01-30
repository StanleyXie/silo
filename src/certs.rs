use log::info;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, SanType, IsCa, BasicConstraints};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Default certificate directory under user's home
pub fn default_certs_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".silo")
        .join("certs")
}

/// Check if all required certificates exist
pub fn certs_exist(certs_dir: &Path) -> bool {
    let required = [
        "server.crt",
        "server.key",
        "internal/ca.crt",
        "internal/ca.key",
        "internal/control.crt",
        "internal/control.key",
        "internal/gateway.crt",
        "internal/gateway.key",
    ];

    required.iter().all(|f| certs_dir.join(f).exists())
}

/// Generate all required certificates for Silo
pub fn generate_certs(certs_dir: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Generating certificates in {:?}", certs_dir);

    // Create directories
    fs::create_dir_all(certs_dir.join("internal"))?;

    // 1. Generate Internal CA
    let(ca_key, ca_cert, ca_params) = generate_ca()?;
    write_cert_and_key(
        &ca_cert,
        &ca_key,
        &certs_dir.join("internal/ca.crt"),
        &certs_dir.join("internal/ca.key"),
    )?;
    info!("Generated Internal CA");

    let ca_issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);

    // 2. Generate Server Certificate (for Gateway TLS)
    let (server_key, server_cert) = generate_server_cert(&ca_issuer)?;
    write_cert_and_key(
        &server_cert,
        &server_key,
        &certs_dir.join("server.crt"),
        &certs_dir.join("server.key"),
    )?;
    info!("Generated Server Certificate");

    // 3. Generate Control Plane Certificate
    let (control_key, control_cert) = generate_control_cert(&ca_issuer)?;
    write_cert_and_key(
        &control_cert,
        &control_key,
        &certs_dir.join("internal/control.crt"),
        &certs_dir.join("internal/control.key"),
    )?;
    info!("Generated Control Plane Certificate");

    // 4. Generate Gateway Client Certificate
    let (gateway_key, gateway_cert) = generate_gateway_cert(&ca_issuer)?;
    write_cert_and_key(
        &gateway_cert,
        &gateway_key,
        &certs_dir.join("internal/gateway.crt"),
        &certs_dir.join("internal/gateway.key"),
    )?;
    info!("Generated Gateway Client Certificate");

    info!("All certificates generated successfully in {:?}", certs_dir);
    Ok(())
}

fn generate_ca() -> Result<(KeyPair, Certificate, CertificateParams), rcgen::Error> {
    let mut params = CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "Silo Internal CA");

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    Ok((key_pair, cert, params))
}

fn generate_server_cert(issuer: &rcgen::Issuer<'_, impl rcgen::SigningKey>) -> Result<(KeyPair, Certificate), rcgen::Error> {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().unwrap()),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, issuer)?;
    Ok((key_pair, cert))
}

fn generate_control_cert(issuer: &rcgen::Issuer<'_, impl rcgen::SigningKey>) -> Result<(KeyPair, Certificate), rcgen::Error> {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "control-plane.silo.internal");
    params.subject_alt_names = vec![
        SanType::DnsName("control-plane.silo.internal".try_into().unwrap()),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, issuer)?;
    Ok((key_pair, cert))
}

fn generate_gateway_cert(issuer: &rcgen::Issuer<'_, impl rcgen::SigningKey>) -> Result<(KeyPair, Certificate), rcgen::Error> {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "gateway.silo.internal");
    params.subject_alt_names = vec![SanType::DnsName(
        "gateway.silo.internal".try_into().unwrap(),
    )];

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, issuer)?;
    Ok((key_pair, cert))
}

fn write_cert_and_key(
    cert: &Certificate,
    key_pair: &KeyPair,
    cert_path: &Path,
    key_path: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Write certificate
    let mut cert_file = File::create(cert_path)?;
    cert_file.write_all(cert.pem().as_bytes())?;

    // Write private key
    let mut key_file = File::create(key_path)?;
    key_file.write_all(key_pair.serialize_pem().as_bytes())?;

    Ok(())
}

/// Get resolved certificate paths, generating certs if needed
pub fn resolve_cert_paths(
    config_certs_dir: Option<&str>,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let certs_dir = config_certs_dir
        .map(PathBuf::from)
        .unwrap_or_else(default_certs_dir);

    if !certs_exist(&certs_dir) {
        info!(
            "Certificates not found in {:?}, generating...",
            certs_dir
        );
        generate_certs(&certs_dir)?;
    } else {
        info!("Using existing certificates from {:?}", certs_dir);
    }

    Ok(certs_dir)
}

/// Generate a dynamic user certificate signed by the internal CA
pub fn generate_dynamic_user_cert(
    certs_dir: &Path,
    username: &str,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    let ca_key_pem = fs::read_to_string(certs_dir.join("internal/ca.key"))?;
    let ca_key = KeyPair::from_pem(&ca_key_pem)?;
    
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.distinguished_name.push(DnType::CommonName, "Silo Internal CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);

    let mut user_params = CertificateParams::default();
    user_params.distinguished_name = DistinguishedName::new();
    user_params.distinguished_name.push(DnType::CommonName, username);
    user_params.subject_alt_names = vec![SanType::DnsName(username.to_string().try_into().unwrap())];

    let user_key = KeyPair::generate()?;
    let user_cert = user_params.signed_by(&user_key, &issuer)?;
    
    Ok((user_cert.pem(), user_key.serialize_pem()))
}
