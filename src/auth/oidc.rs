use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use log::info;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// JWKS (JSON Web Key Set) structure
#[derive(Debug, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    pub alg: Option<String>,
    pub n: Option<String>, // RSA modulus
    pub e: Option<String>, // RSA exponent
}

/// Standard OIDC claims
#[derive(Debug, Serialize, Deserialize)]
pub struct OidcClaims {
    pub sub: String,         // Subject (user identifier)
    pub iss: String,         // Issuer
    pub aud: Option<String>, // Audience (may be array in some providers)
    pub exp: i64,            // Expiration time
    pub iat: i64,            // Issued at

    // GitHub Actions specific claims
    #[serde(default)]
    pub actor: Option<String>, // GitHub username
    #[serde(default)]
    pub repository: Option<String>, // e.g., "owner/repo"
    #[serde(default)]
    pub workflow: Option<String>, // Workflow name
    #[serde(default)]
    pub run_id: Option<String>, // Workflow run ID
}

/// OIDC Authenticator with JWKS caching
pub struct OidcAuthenticator {
    issuer: String,
    jwks_uri: String,
    audience: Option<String>,
    jwks_cache: Arc<RwLock<Option<Jwks>>>,
}

impl OidcAuthenticator {
    pub fn new(issuer: String, jwks_uri: String, audience: Option<String>) -> Self {
        Self {
            issuer,
            jwks_uri,
            audience,
            jwks_cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Fetch JWKS from the provider (with caching)
    async fn fetch_jwks(&self) -> Result<Jwks, String> {
        // Check cache first
        {
            let cache = self.jwks_cache.read().await;
            if let Some(ref jwks) = *cache {
                return Ok(Jwks {
                    keys: jwks.keys.clone(),
                });
            }
        }

        // Fetch from remote
        info!("[OIDC] Fetching JWKS from {}", self.jwks_uri);
        let client = reqwest::Client::new();
        let response = client
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| format!("JWKS fetch failed: {}", e))?;

        let jwks: Jwks = response
            .json()
            .await
            .map_err(|e| format!("JWKS parse failed: {}", e))?;

        // Update cache
        {
            let mut cache = self.jwks_cache.write().await;
            *cache = Some(Jwks {
                keys: jwks.keys.clone(),
            });
        }

        Ok(jwks)
    }

    /// Find the appropriate decoding key from JWKS
    fn find_key<'a>(&self, jwks: &'a Jwks, kid: Option<&str>) -> Option<&'a Jwk> {
        if let Some(kid) = kid {
            jwks.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
        } else {
            // If no kid in token, try the first RSA key
            jwks.keys.iter().find(|k| k.kty == "RSA")
        }
    }

    /// Validate a JWT token and extract the identity
    pub async fn validate_token(&self, token: &str) -> Result<String, String> {
        // Decode header to get kid
        let header = decode_header(token).map_err(|e| format!("Invalid JWT header: {}", e))?;

        // Fetch JWKS
        let jwks = self.fetch_jwks().await?;

        // Find the key
        let jwk = self
            .find_key(&jwks, header.kid.as_deref())
            .ok_or_else(|| "No matching key found in JWKS".to_string())?;

        // Build decoding key from JWK
        let n = jwk.n.as_ref().ok_or("Missing 'n' in JWK")?;
        let e = jwk.e.as_ref().ok_or("Missing 'e' in JWK")?;

        let decoding_key = DecodingKey::from_rsa_components(n, e)
            .map_err(|e| format!("Invalid RSA components: {}", e))?;

        // Configure validation
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);

        if let Some(ref aud) = self.audience {
            validation.set_audience(&[aud]);
        } else {
            validation.validate_aud = false;
        }

        // Decode and validate
        let token_data = decode::<OidcClaims>(token, &decoding_key, &validation)
            .map_err(|e| format!("JWT validation failed: {}", e))?;

        let claims = token_data.claims;

        // Extract identity - prefer actor (GitHub username) over sub
        let identity = claims.actor.clone().unwrap_or_else(|| claims.sub.clone());

        info!(
            "[OIDC] Token validated for identity: {} (iss: {}, repo: {:?})",
            identity, claims.iss, claims.repository
        );

        Ok(identity)
    }

    /// Invalidate the JWKS cache (useful for key rotation)
    pub async fn invalidate_cache(&self) {
        let mut cache = self.jwks_cache.write().await;
        *cache = None;
        info!("[OIDC] JWKS cache invalidated");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claims_deserialize() {
        let json = r#"{
            "sub": "repo:owner/repo:ref:refs/heads/main",
            "iss": "https://token.actions.githubusercontent.com",
            "aud": "silo.internal",
            "exp": 1800000000,
            "iat": 1700000000,
            "actor": "github-user"
        }"#;

        let claims: OidcClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.actor, Some("github-user".to_string()));
    }
}
