use clap::{Parser, Subcommand};
use rand::Rng;
use std::io::{Read, Write}; // Add rand import

#[derive(Parser)]
#[command(name = "silo")]
#[command(about = "Silo CLI for Authentication and Governance", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verifies the CLI is installed and working
    SelfTest,
    /// Check server status and client context
    Status {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        endpoint: String,
    },
    /// Authenticate with Silo (OIDC)
    Login {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        endpoint: String,
    },
    /// Execute a command with Silo credentials injected
    Exec {
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match &cli.command {
        Commands::SelfTest => {
            println!("✅ Silo CLI Core is operational.");
        }
        Commands::Status { endpoint } => {
            println!("🔍 Checking Silo status...");

            // 1. Check Server Connectivity
            let url = format!("{}/health", endpoint);
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true) // For self-signed certs in dev
                .build()
                .unwrap();

            match client.get(&url).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        println!("   ✅ Server is REACHABLE at {}", endpoint);
                    } else {
                        println!("   ⚠️  Server is REACHABLE but returned: {}", resp.status());
                    }
                }
                Err(e) => {
                    println!("   ❌ Server is UNREACHABLE at {}: {}", url, e);
                    println!("      (Is the Silo Gateway running?)");
                }
            }

            // 2. Check Client Context
            let cert_dir = dirs::home_dir().unwrap().join(".silo/certs");
            if cert_dir.exists() {
                println!("   ✅ Client Context Found: {:?}", cert_dir);
                if cert_dir.join("internal/gateway.crt").exists() {
                    println!("      - Gateway Identity: [Request Certificate Present]");
                } else {
                    println!("      - Gateway Identity: [Missing]");
                }
            } else {
                println!("   ❌ No Client Context found (Run 'silo login')");
            }
        }
        Commands::Login { endpoint } => {
            println!("🚀 Login flow initiated for {}", endpoint);

            // 1. Setup Local Callback Listener
            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind random port");
            let port = listener.local_addr().unwrap().port();
            let redirect_uri = format!("http://127.0.0.1:{}", port);

            println!("👂 Callback listener started on port {}", port);

            // 2. Generate OIDC Params
            let client_id = "silo-cli";
            let state: String = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(16)
                .map(char::from)
                .collect();

            let login_url = format!(
                "{}/auth/login?client_id={}&redirect_uri={}&state={}&response_type=code",
                endpoint, client_id, redirect_uri, state
            );

            println!("🌍 Opening browser to: {}", login_url);
            if webbrowser::open(&login_url).is_err() {
                println!("❌ Failed to open browser. Please open this URL manually:");
                println!("{}", login_url);
            }

            // 3. Wait for Authorization Code
            println!("⏳ Waiting for authentication...");

            let mut code = String::new();

            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0; 1024];
                let _ = stream.read(&mut buffer).unwrap();

                let request = String::from_utf8_lossy(&buffer);
                // Parse "GET /?code=...&state=... HTTP/1.1"
                // Very naive parsing for MVP
                let first_line = request.lines().next().unwrap_or("");
                if let Some(query_start) = first_line.find('?') {
                    let query_end = first_line[query_start..]
                        .find(' ')
                        .unwrap_or(first_line.len() - query_start)
                        + query_start;
                    let query = &first_line[query_start + 1..query_end];

                    let params: std::collections::HashMap<String, String> =
                        url::form_urlencoded::parse(query.as_bytes())
                            .into_owned()
                            .collect();

                    if let Some(s) = params.get("state") {
                        if s != &state {
                            println!("❌ State mismatch! Possible CSRF attack.");
                            std::process::exit(1);
                        }
                    }

                    if let Some(c) = params.get("code") {
                        code = c.clone();
                    }
                }

                let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Login Successful</h1><p>You can close this window now.</p><script>window.close()</script>";
                stream.write_all(response.as_bytes()).unwrap();
                stream.flush().unwrap();
            }

            if code.is_empty() {
                println!("❌ Failed to capture authorization code.");
                std::process::exit(1);
            }

            println!("✅ Authorization Code captured: {}...", &code[0..4]);

            // 4. Exchange Code for Token
            println!("🔄 Exchanging code for token...");
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap();

            let params = [
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", &redirect_uri),
                ("client_id", client_id),
            ];

            // We use /auth/token endpoint
            let token_url = format!("{}/auth/token", endpoint);
            match client.post(&token_url).form(&params).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let body = resp.text().await.unwrap();
                        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
                        let access_token = json["access_token"].as_str().unwrap_or("");

                        println!("✅ Token Exchange Successful!");

                        // 5. Exchange Token for mTLS Certificates
                        println!("🔑 Exchanging token for personalized mTLS certificates...");
                        let exchange_url = format!("{}/auth/exchange", endpoint);
                        match client
                            .post(&exchange_url)
                            .header("Authorization", format!("Bearer {}", access_token))
                            .send()
                            .await
                        {
                            Ok(ex_resp) => {
                                if ex_resp.status().is_success() {
                                    let ex_body = ex_resp.text().await.unwrap();
                                    let cert_data: serde_json::Value =
                                        serde_json::from_str(&ex_body).unwrap();

                                    let cert_pem = cert_data["certificate"].as_str().unwrap_or("");
                                    let key_pem = cert_data["private_key"].as_str().unwrap_or("");
                                    let ca_pem = cert_data["ca"].as_str().unwrap_or("");
                                    let identity =
                                        cert_data["identity"].as_str().unwrap_or("unknown");

                                    // 6. Context Injection
                                    let home = dirs::home_dir().unwrap();
                                    let current_dir = home.join(".silo/certs/current");
                                    std::fs::create_dir_all(&current_dir)
                                        .expect("Failed to create current context dir");

                                    std::fs::write(current_dir.join("gateway.crt"), cert_pem)
                                        .expect("Failed to write cert");
                                    std::fs::write(current_dir.join("gateway.key"), key_pem)
                                        .expect("Failed to write key");
                                    std::fs::write(current_dir.join("ca.crt"), ca_pem)
                                        .expect("Failed to write CA");

                                    println!("✅ Login Successful!");
                                    println!("   Authenticated as: {}", identity);
                                    println!("   Active Context:   {:?}", current_dir);
                                    println!(
                                        "   \n   Use this path in backend.hcl for standard usage:"
                                    );
                                    println!("   client_certificate = \"~/.silo/certs/current/gateway.crt\"");
                                    println!("   client_key         = \"~/.silo/certs/current/gateway.key\"");
                                } else {
                                    println!(
                                        "❌ Certificate Exchange Failed: {}",
                                        ex_resp.status()
                                    );
                                    std::process::exit(1);
                                }
                            }
                            Err(e) => {
                                println!("❌ Network Error during exchange: {}", e);
                                std::process::exit(1);
                            }
                        }
                    } else {
                        println!("❌ Token Exchange Failed: {}", resp.status());
                        println!("   Body: {}", resp.text().await.unwrap_or_default());
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    println!("❌ Network Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Exec { args } => {
            if args.is_empty() {
                println!("❌ No command provided to exec.");
                std::process::exit(1);
            }

            // 1. Load Credentials (Prioritize Active Context)
            let cert_dir = dirs::home_dir().unwrap().join(".silo/certs");
            let mut crt_path = cert_dir.join("current/gateway.crt");
            let mut key_path = cert_dir.join("current/gateway.key");

            // Fallback to internal if current context is missing (Legacy/Bootstrap support)
            if !crt_path.exists() {
                crt_path = cert_dir.join("internal/gateway.crt");
                key_path = cert_dir.join("internal/gateway.key");
            }

            if !crt_path.exists() || !key_path.exists() {
                println!("❌ Error: Credentials not found. Run 'silo login' first.");
                std::process::exit(1);
            }

            let cert_content = std::fs::read_to_string(&crt_path).expect("Failed to read cert");
            let key_content = std::fs::read_to_string(&key_path).expect("Failed to read key");

            // 2. Prepare Command
            let cmd_name = &args[0];
            let cmd_args = &args[1..];

            println!("📦 Silo Exec: Injecting credentials for '{}'...", cmd_name);

            use std::os::unix::process::CommandExt;
            use std::process::Command;

            let mut command = Command::new(cmd_name);
            command.args(cmd_args);

            // 3. Inject Environment Variables for Terraform HTTP Backend
            // Note: These env vars are standard for the 'http' backend
            command.env("TF_HTTP_CLIENT_CERTIFICATE_PEM", cert_content);
            command.env("TF_HTTP_CLIENT_PRIVATE_KEY_PEM", key_content);

            // Optional: Set a flag so child processes know they are wrapped
            command.env("SILO_SESSION_ACTIVE", "true");

            // 4. Exec (Replace Process)
            let error = command.exec();

            // If we are here, exec failed
            eprintln!("❌ Failed to exec command: {}", error);
            std::process::exit(1);
        }
    }
}
