    use super::*;
    use wiremock::matchers::{method, path, header};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use base64::{Engine as _, engine::general_purpose};
    use serde_json::json;

    #[tokio::test]
    async fn test_get_state_success() {
        let mock_server = MockServer::start().await;
        // ... (rest of function)
        let client = VaultClient::new(mock_server.uri(), "test-token".to_string());

        let state_data = b"some-terraform-state-content";
        let state_b64 = general_purpose::STANDARD.encode(state_data);
        
        // Vault KV v2 response structure
        let response_json = json!({
            "data": {
                "data": {
                    "value": state_b64
                }
            }
        });

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/myproject/state"))
            .and(header("X-Vault-Token", "test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_json))
            .mount(&mock_server)
            .await;

        let result = client.get("secret/myproject/state").await.unwrap();
        assert_eq!(result, Some(state_data.to_vec()));
    }

    #[tokio::test]
    async fn test_get_state_not_found() {
        let mock_server = MockServer::start().await;
        let client = VaultClient::new(mock_server.uri(), "test-token".to_string());

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/myproject/state"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let result = client.get("secret/myproject/state").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_put_state_success() {
        let mock_server = MockServer::start().await;
        let client = VaultClient::new(mock_server.uri(), "test-token".to_string());

        let state_data = b"new-state-data";
        // We expect the client to encode this in base64 inside the JSON body
        let state_b64 = general_purpose::STANDARD.encode(state_data);

        Mock::given(method("PUT"))
            .and(path("/v1/secret/data/myproject/state"))
            .and(header("X-Vault-Token", "test-token"))
            // We can verify the body JSON if needed, but for now just responding OK suffices
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = client.put("secret/myproject/state", state_data).await;
        assert!(result.is_ok());
    }

