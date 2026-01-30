use crate::config::NativeAuthConfig;
use bcrypt::verify;
use log::{info, warn};

#[derive(Clone)]
pub struct NativeIdentityService {
    pub config: NativeAuthConfig,
}

impl NativeIdentityService {
    pub fn new(config: NativeAuthConfig) -> Self {
        Self { config }
    }

    pub fn validate(&self, username: &str, password: &str) -> Option<Vec<String>> {
        if !self.config.enabled {
            return None;
        }

        for user in &self.config.users {
            if user.username == username {
                match verify(password, &user.password_hash) {
                    Ok(valid) => {
                        if valid {
                            info!("Native auth successful for user: {}", username);
                            return Some(user.roles.clone());
                        } else {
                            warn!(
                                "Native auth failed for user: {} (invalid password)",
                                username
                            );
                        }
                    }
                    Err(e) => {
                        warn!("Native auth error for user {}: {}", username, e);
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use bcrypt::{hash, DEFAULT_COST};

    #[test]
    fn generate_default_hash() {
        let password = "silo123";
        let hashed = hash(password, DEFAULT_COST).unwrap();
        println!("Generated Hash for '{}': {}", password, hashed);
    }
}
