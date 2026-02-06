use clap::{Parser, Subcommand};
use dialoguer::Confirm;
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use silo::bootstrap::BootstrapManager;
use std::io::{Read, Write};
use std::path::Path;

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
    /// Initialize Silo setup (Configuration & Certificates)
    Init {
        /// Do not prompt for confirmation
        #[arg(long)]
        non_interactive: bool,

        /// Automatically install as a system service (Linux)
        #[arg(long)]
        service: bool,
    },
    /// Start the Silo environment
    Up {
        /// Run in background (detach)
        #[arg(short, long)]
        detach: bool,
        /// Use dev mode for Vault (ephemeral, no persistence)
        #[arg(long)]
        dev: bool,
        /// Use raft storage for Vault (HA cluster mode)
        #[arg(long)]
        raft: bool,
    },
    /// Stop the Silo environment gracefully
    Stop {
        /// Force stop even with active sessions
        #[arg(short, long)]
        force: bool,
    },
    /// Restart the Silo environment gracefully
    Restart {
        /// Force restart even with active sessions
        #[arg(short, long)]
        force: bool,
    },
    /// Stop and cleanup the Silo environment
    Down {
        /// Force stop even with active sessions
        #[arg(short, long)]
        force: bool,
    },
    /// Management of Silo as a system service
    Service {
        #[command(subcommand)]
        subcommand: ServiceCommands,
    },
    /// Setup Vault as OIDC Provider for Silo authentication
    SetupOidc {
        /// Vault address
        #[arg(long, default_value = "http://127.0.0.1:8200")]
        vault_addr: String,
        /// Vault token (root token for dev mode)
        #[arg(long, default_value = "root")]
        vault_token: String,
        /// Admin username to create
        #[arg(long, default_value = "admin")]
        username: String,
        /// Admin password (prompted if not provided)
        #[arg(long)]
        password: Option<String>,
        /// Silo callback URL for OIDC
        #[arg(long, default_value = "https://127.0.0.1:8443/auth/callback")]
        redirect_uri: String,
    },
    /// Print version information
    Version,
}


#[derive(Subcommand)]
enum ServiceCommands {
    /// Install Silo component as a systemd service
    Install {
        /// Component to install (control-plane, gateway, all)
        #[arg(long, default_value = "all")]
        component: String,
        /// User to run the service as
        #[arg(long, default_value = "root")]
        user: String,
    },
    /// Tail logs for a Silo component
    Logs {
        /// Component to tail (control-plane, gateway)
        #[arg(long, default_value = "gateway")]
        component: String,
    },
    /// Show status of Silo services
    Status,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Stop { force } => {
            handle_stop(*force).await;
        }
        Commands::Restart { force } => {
            handle_stop(*force).await;
            println!();
            // Restart defaults to file mode (persistent storage)
            handle_up(true, false, false).await;
        }
        Commands::Down { force } => {
            handle_stop(*force).await;
            // Additional cleanup could go here
        }
        Commands::SelfTest => {
            println!("✅ Silo CLI Core is operational.");
        }
        Commands::Status { endpoint } => {
            silo::banner::print_banner();
            println!("🔍 Checking Silo status...");

            // 1. Check Server Connectivity
            let url = format!("{}/health", endpoint);
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true) // For self-signed certs in dev
                .build()
                .unwrap();

            match client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    let json: serde_json::Value =
                        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);

                    if status.is_success() {
                        println!("   ✅ Server is HEALTHY at {}", endpoint);
                    } else {
                        println!("   ❌ Server is UNHEALTHY at {}", endpoint);
                        println!("      Status: {}", status);
                    }

                    if !json.is_null() {
                        if let Some(components) = json.get("components") {
                            println!("      Components:");
                            if let Some(obj) = components.as_object() {
                                for (name, stat) in obj {
                                    let icon = if stat == "UP" { "✅" } else { "❌" };
                                    println!("      - {}: {} {}", name, icon, stat);
                                }
                            }
                        }
                        if let Some(ver) = json.get("version") {
                            println!("      Version: {}", ver);
                        }
                    }
                }
                Err(_) => {
                    println!("   ❌ Server is UNREACHABLE at {}", endpoint);
                }
            }

            // 2. Check Local Process Status
            println!("\n💻 Local Process Management:");
            let manager = BootstrapManager::new("silo.yaml");

            let (v_status, v_pid) = manager.get_process_status("Vault", "vault.pid");
            let v_icon = if v_status == "RUNNING" { "✅" } else { "❌" };
            println!(
                "   {} Vault:       {:<10} (PID: {})",
                v_icon, v_status, v_pid
            );

            let (s_status, s_pid) = manager.get_process_status("Silo", "silo.pid");
            let s_icon = if s_status == "RUNNING" { "✅" } else { "❌" };
            println!(
                "   {} Silo Server: {:<10} (PID: {})",
                s_icon, s_status, s_pid
            );

            println!("\n⚙️ Systemd Services:");
            silo::service::show_status();

            // 3. Check Client Context
            println!("\n🔑 Client Context:");
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
                println!("❌ Error: No command provided to exec.");
                std::process::exit(1);
            }

            // 1. Resolve Credentials (Prioritize Active Context)
            let cert_dir = dirs::home_dir().unwrap().join(".silo/certs");
            let mut crt_path = cert_dir.join("current/gateway.crt");
            let mut key_path = cert_dir.join("current/gateway.key");

            // Fallback to internal if current context is missing (Bootstrap support)
            if !crt_path.exists() {
                crt_path = cert_dir.join("internal/gateway.crt");
                key_path = cert_dir.join("internal/gateway.key");
            }

            if !crt_path.exists() || !key_path.exists() {
                println!(
                    "❌ Error: Credentials not found. Run 'silo init' and 'silo login' first."
                );
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
            command.env("TF_HTTP_CLIENT_CERTIFICATE_PEM", cert_content);
            command.env("TF_HTTP_CLIENT_PRIVATE_KEY_PEM", key_content);
            command.env("SILO_SESSION_ACTIVE", "true");

            // 4. Exec (Replace Process)
            let error = command.exec();
            eprintln!("❌ Failed to exec command: {}", error);
            std::process::exit(1);
        }
        Commands::Init {
            non_interactive,
            service,
        } => {
            handle_init(*non_interactive, *service).await;
        }
        Commands::Up { detach, dev, raft } => {
            handle_up(*detach, *dev, *raft).await;
        }
        Commands::SetupOidc {
            vault_addr,
            vault_token,
            username,
            password,
            redirect_uri,
        } => {
            handle_setup_oidc(vault_addr, vault_token, username, password.clone(), redirect_uri).await;
        }
        Commands::Version => {
            silo::banner::print_banner();
            println!("Silo CLI v{}", env!("CARGO_PKG_VERSION"));
        }
        Commands::Service { subcommand } => match subcommand {
            ServiceCommands::Install { component, user } => {
                if let Err(e) = silo::service::install_service(component, user) {
                    println!("❌ Error: {}", e);
                    std::process::exit(1);
                }
            }
            ServiceCommands::Logs { component } => {
                silo::service::tail_logs(component);
            }
            ServiceCommands::Status => {
                silo::service::show_status();
            }
        },
    }
}

async fn handle_init(non_interactive: bool, service: bool) {
    silo::banner::print_banner();
    println!("🚀 Initializing Silo Setup...");
    let manager = BootstrapManager::new("silo.yaml");

    // 1. Check dependencies
    let pb = ProgressBar::new_spinner();
    pb.set_message("Checking dependencies...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let vault_installed = manager.check_vault_installed();
    if !vault_installed {
        pb.finish_with_message("❌ Vault not found in PATH.");
        if !non_interactive {
            println!("Silo recommends HashiCorp Vault for local state storage.");
            println!("Please install it via 'brew install vault' or visit https://www.vaultproject.io/downloads");
            return;
        }
    } else {
        pb.finish_with_message("✅ Vault detected.");
    }

    // 2. Generate config
    if Path::new("silo.yaml").exists()
        && !non_interactive
        && !Confirm::new()
            .with_prompt("silo.yaml already exists. Overwrite?")
            .default(false)
            .interact()
            .unwrap_or(false)
    {
        println!("❌ Aborted.");
        return;
    }

    match manager.generate_default_config() {
        Ok(_) => println!("✅ Created default silo.yaml"),
        Err(e) => println!("❌ Failed to create config: {}", e),
    }

    // 3. Generate Certs
    println!("🔑 Generating certificates (PKI)...");
    let home = dirs::home_dir().unwrap();
    let certs_dir = home.join(".silo/certs");
    if !certs_dir.exists() {
        std::fs::create_dir_all(&certs_dir).unwrap();
    }

    // Call the internal certificate generation logic
    match silo::certs::generate_certs(&certs_dir) {
        Ok(_) => println!("✅ Certificates generated in {:?}", certs_dir),
        Err(e) => println!("❌ Certificate generation failed: {}", e),
    }

    // 4. Systemd Service Integration (Optional/Converged)
    if service
        || (!non_interactive
            && Confirm::new()
                .with_prompt("Do you want to install Silo as a systemd service? (Linux only)")
                .default(false)
                .interact()
                .unwrap_or(false))
    {
        println!("📝 Initiating systemd service installation...");
        if let Err(e) = silo::service::install_service("all", "root") {
            println!("   ⚠️  Service installation skipped: {}", e);
            println!("   (This is normal on non-Linux systems or if not running as root)");
        }
    }

    println!("\n✨ Initialization complete! Run 'silo up' to start the environment.");
}

async fn handle_up(detach: bool, dev: bool, raft: bool) {
    if !Path::new("silo.yaml").exists() {
        println!("❌ Error: silo.yaml not found.");
        println!("Run 'silo init' first to generate a configuration.");
        return;
    }

    silo::banner::print_banner();
    println!("⬆️ Starting Silo Environment...");
    let manager = BootstrapManager::new("silo.yaml");
    manager.cleanup_orphan_ports();

    // Load config to determine storage backend
    let config = match silo::config::Config::load("silo.yaml") {
        Ok(c) => c,
        Err(e) => {
            println!("❌ Failed to load silo.yaml: {}", e);
            return;
        }
    };

    // 1. Start storage backend (Vault or etcd)
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );

    match config.storage.storage_type.as_str() {
        "vault" => {
            // Determine Vault storage mode
            let mode = if dev {
                pb.set_message("Starting Vault (Dev Mode - Ephemeral)...");
                silo::bootstrap::VaultStorageMode::Dev
            } else if raft {
                pb.set_message("Starting Vault (Raft Mode - HA)...");
                silo::bootstrap::VaultStorageMode::Raft
            } else {
                pb.set_message("Starting Vault (File Mode - Persistent)...");
                silo::bootstrap::VaultStorageMode::File
            };
            pb.enable_steady_tick(std::time::Duration::from_millis(100));

            match manager.start_vault(mode).await {
                Ok(info) => {
                    pb.finish_with_message(format!("✅ Vault is ready. ({})", info));
                }
                Err(e) => {
                    pb.finish_with_message(format!("❌ Vault failed: {}", e));
                    if e.to_string().contains("responding") {
                        println!("   (Vault might be already running or unreachable)");
                    }
                    return; // Stop here if Vault is critical
                }
            }
        }
        "etcd" => {
            pb.set_message("Starting etcd (Dev Mode)...");
            pb.enable_steady_tick(std::time::Duration::from_millis(100));

            match manager.start_etcd_dev().await {
                Ok(_) => pb.finish_with_message("✅ etcd is ready."),
                Err(e) => {
                    pb.finish_with_message(format!("❌ etcd failed: {}", e));
                    if e.to_string().contains("responding") {
                        println!("   (etcd might be already running or unreachable)");
                    }
                    return;
                }
            }
        }
        other => {
            pb.finish_with_message(format!("⚠️  Unknown storage type: {}", other));
        }
    }


    // 2. Start Silo Server
    pb.reset();
    pb.set_message("Starting Silo Gateway & Control Plane...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    match manager.start_silo_server(detach) {
        Ok(_) => {
            pb.finish_with_message("✅ Silo Server process started.");
            if !detach {
                println!("(Running in foreground. Press Ctrl+C to stop everything)");
                // Implementation note: Ideally we'd log output or wait here
            }
        }
        Err(e) => {
            pb.finish_with_message(format!("❌ Failed to start Silo Server: {}", e));
            return;
        }
    }

    // 3. Health Check with proper readiness verification
    let pb2 = ProgressBar::new_spinner();
    pb2.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb2.set_message("Waiting for server to become healthy...");
    pb2.enable_steady_tick(std::time::Duration::from_millis(100));

    let endpoint = "https://127.0.0.1:8443";
    if manager.wait_for_healthy(endpoint, 30).await {
        pb2.finish_with_message("✅ Server is healthy.");
        println!("\n🚀 Silo is UP and HEALTHY.");
    } else {
        pb2.finish_with_message("⚠️  Health check timed out.");
        println!("\n⚠️  Silo may not be fully ready. Check logs with 'silo service logs'.");
    }
}

async fn handle_stop(force: bool) {
    silo::banner::print_banner();
    println!("🛑 Stopping Silo Environment...");

    let manager = BootstrapManager::new("silo.yaml");

    // Check for active sessions unless --force is used
    if !force {
        check_active_sessions().await;
    } else {
        println!("⚠️  Force mode: skipping session check.");
    }

    // Stop services in order: Silo Server first, then storage backends
    stop_process(&manager, "Silo Server", "silo.pid", 15);
    stop_process(&manager, "Vault", "vault.pid", 10);
    stop_process(&manager, "etcd", "etcd.pid", 10);

    println!("\n✅ Silo environment stopped.");
}

/// Check for active sessions before stopping
async fn check_active_sessions() {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.blue} {msg}")
            .unwrap(),
    );
    pb.set_message("Checking for active sessions...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    match client.get("https://127.0.0.1:8443/health").send().await {
        Ok(_) => pb.finish_with_message("✅ No active blocking sessions detected."),
        Err(_) => pb.finish_with_message("ℹ️  Server not responding, proceeding with cleanup."),
    }
}

/// Stop a process gracefully with SIGTERM, then SIGKILL if needed
fn stop_process(manager: &BootstrapManager, name: &str, pid_file: &str, timeout_secs: u64) {
    if let Some(pid) = manager.read_pid(pid_file) {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.red} {msg}")
                .unwrap(),
        );
        pb.set_message(format!("Stopping {} (PID: {})...", name, pid));
        pb.enable_steady_tick(std::time::Duration::from_millis(100));

        // Send SIGTERM
        send_signal(pid, "SIGTERM");

        // Wait for process to terminate
        if manager.wait_for_stopped(pid_file, timeout_secs) {
            pb.finish_with_message(format!("✅ {} stopped.", name));
        } else {
            pb.finish_with_message(format!("⚠️  {} did not stop gracefully, forcing...", name));
            send_signal(pid, "SIGKILL");
        }
        manager.cleanup_pid(pid_file);
    } else {
        println!("ℹ️  {} not running.", name);
    }
}

/// Send a signal to a process (Unix only)
fn send_signal(pid: u32, signal: &str) {
    #[cfg(unix)]
    {
        use std::process::Command;
        let _ = Command::new("kill")
            .arg(format!("-{}", signal))
            .arg(pid.to_string())
            .status();
    }
    #[cfg(windows)]
    {
        if signal == "SIGKILL" || signal == "SIGTERM" {
            use std::process::Command;
            let _ = Command::new("taskkill")
                .arg("/F")
                .arg("/PID")
                .arg(pid.to_string())
                .status();
        }
    }
}

/// Setup Vault as OIDC Provider for Silo authentication
async fn handle_setup_oidc(
    vault_addr: &str,
    vault_token: &str,
    username: &str,
    password: Option<String>,
    redirect_uri: &str,
) {
    silo::banner::print_banner();
    println!("🔐 Setting up Vault OIDC Provider...\n");

    // Prompt for password if not provided
    let password = match password {
        Some(p) => p,
        None => {
            use dialoguer::Password;
            Password::new()
                .with_prompt("Enter password for admin user")
                .with_confirmation("Confirm password", "Passwords don't match")
                .interact()
                .unwrap_or_else(|_| {
                    eprintln!("❌ Failed to read password");
                    std::process::exit(1);
                })
        }
    };

    let client = reqwest::Client::new();
    let pb = ProgressBar::new(10);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  {spinner:.green} {msg}")
            .unwrap(),
    );

    // 1. Enable userpass auth
    pb.set_message("Enabling userpass auth...");
    let _ = client
        .post(format!("{}/v1/sys/auth/userpass", vault_addr))
        .header("X-Vault-Token", vault_token)
        .json(&serde_json::json!({"type": "userpass"}))
        .send()
        .await;
    pb.inc(1);

    // 2. Create silo-admin policy
    pb.set_message("Creating silo-admin policy...");
    let policy_hcl = r#"
path "identity/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "auth/*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
path "auth/token/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "sys/*" { capabilities = ["read", "list"] }
path "secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }
"#;
    let _ = client
        .put(format!("{}/v1/sys/policies/acl/silo-admin", vault_addr))
        .header("X-Vault-Token", vault_token)
        .json(&serde_json::json!({"policy": policy_hcl}))
        .send()
        .await;
    pb.inc(1);

    // 3. Create admin user
    pb.set_message(format!("Creating user: {}...", username));
    let _ = client
        .post(format!("{}/v1/auth/userpass/users/{}", vault_addr, username))
        .header("X-Vault-Token", vault_token)
        .json(&serde_json::json!({
            "password": password,
            "policies": "default,silo-admin"
        }))
        .send()
        .await;
    pb.inc(1);

    // 4. Create identity entity
    pb.set_message("Creating identity entity...");
    let entity_resp = client
        .post(format!("{}/v1/identity/entity", vault_addr))
        .header("X-Vault-Token", vault_token)
        .json(&serde_json::json!({
            "name": format!("{}-entity", username),
            "metadata": {"email": format!("{}@silo.local", username)}
        }))
        .send()
        .await;
    
    let entity_id = if let Ok(resp) = entity_resp {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        body["data"]["id"].as_str().unwrap_or("").to_string()
    } else {
        String::new()
    };
    pb.inc(1);

    // 5. Get userpass accessor and create entity-alias
    pb.set_message("Linking entity to userpass...");
    let auth_resp = client
        .get(format!("{}/v1/sys/auth", vault_addr))
        .header("X-Vault-Token", vault_token)
        .send()
        .await;
    
    if let Ok(resp) = auth_resp {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        if let Some(accessor) = body["userpass/"]["accessor"].as_str() {
            let _ = client
                .post(format!("{}/v1/identity/entity-alias", vault_addr))
                .header("X-Vault-Token", vault_token)
                .json(&serde_json::json!({
                    "name": username,
                    "mount_accessor": accessor,
                    "canonical_id": entity_id
                }))
                .send()
                .await;
        }
    }
    pb.inc(1);

    // 6. Create OIDC key
    pb.set_message("Creating OIDC key...");
    let _ = client
        .post(format!("{}/v1/identity/oidc/key/silo-key", vault_addr))
        .header("X-Vault-Token", vault_token)
        .json(&serde_json::json!({"algorithm": "RS256"}))
        .send()
        .await;
    pb.inc(1);

    // 7. Create OIDC assignment
    pb.set_message("Creating OIDC assignment...");
    let _ = client
        .post(format!("{}/v1/identity/oidc/assignment/silo-users", vault_addr))
        .header("X-Vault-Token", vault_token)
        .json(&serde_json::json!({
            "entity_ids": [entity_id]
        }))
        .send()
        .await;
    pb.inc(1);

    // 8. Create OIDC client
    pb.set_message("Creating OIDC client...");
    let _ = client
        .post(format!("{}/v1/identity/oidc/client/silo-cli", vault_addr))
        .header("X-Vault-Token", vault_token)
        .json(&serde_json::json!({
            "redirect_uris": [redirect_uri],
            "assignments": ["silo-users"],
            "key": "silo-key",
            "id_token_ttl": "30m",
            "access_token_ttl": "1h"
        }))
        .send()
        .await;
    pb.inc(1);

    // 9. Get client credentials
    let client_resp = client
        .get(format!("{}/v1/identity/oidc/client/silo-cli", vault_addr))
        .header("X-Vault-Token", vault_token)
        .send()
        .await;
    
    let (client_id, client_secret) = if let Ok(resp) = client_resp {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        (
            body["data"]["client_id"].as_str().unwrap_or("").to_string(),
            body["data"]["client_secret"].as_str().unwrap_or("").to_string(),
        )
    } else {
        (String::new(), String::new())
    };

    // 10. Authorize key for client and create provider
    pb.set_message("Creating OIDC provider...");
    let _ = client
        .post(format!("{}/v1/identity/oidc/key/silo-key", vault_addr))
        .header("X-Vault-Token", vault_token)
        .json(&serde_json::json!({
            "algorithm": "RS256",
            "allowed_client_ids": [&client_id]
        }))
        .send()
        .await;

    // Create profile scope
    let _ = client
        .post(format!("{}/v1/identity/oidc/scope/profile", vault_addr))
        .header("X-Vault-Token", vault_token)
        .json(&serde_json::json!({
            "template": r#"{"name": {{identity.entity.name}}}"#,
            "description": "Profile scope"
        }))
        .send()
        .await;

    let _ = client
        .post(format!("{}/v1/identity/oidc/provider/silo", vault_addr))
        .header("X-Vault-Token", vault_token)
        .json(&serde_json::json!({
            "allowed_client_ids": [&client_id],
            "scopes_supported": ["profile"]
        }))
        .send()
        .await;
    pb.inc(1);

    pb.finish_and_clear();

    // Print summary
    println!("  ✅ Enabled userpass auth");
    println!("  ✅ Created policy: silo-admin");
    println!("  ✅ Created user: {}", username);
    println!("  ✅ Created identity entity");
    println!("  ✅ Created OIDC key: silo-key");
    println!("  ✅ Created OIDC client: silo-cli");
    println!("  ✅ Created OIDC provider: silo");
    println!();

    // Print OIDC config for silo.yaml
    println!("📝 Add this to your silo.yaml:");
    println!("────────────────────────────────────────");
    println!("auth:");
    println!("  oidc:");
    println!("    enabled: true");
    println!("    issuer: \"{}/v1/identity/oidc/provider/silo\"", vault_addr);
    println!("    jwks_uri: \"{}/v1/identity/oidc/provider/silo/.well-known/keys\"", vault_addr);
    println!("    authorization_endpoint: \"{}/ui/vault/identity/oidc/provider/silo/authorize\"", vault_addr);
    println!("    token_endpoint: \"{}/v1/identity/oidc/provider/silo/token\"", vault_addr);
    println!("    client_id: \"{}\"", client_id);
    println!("    client_secret: \"{}\"", client_secret);
    println!("    redirect_uri: \"{}\"", redirect_uri);
    println!("────────────────────────────────────────");
    println!();
    println!("🎉 Vault OIDC setup complete!");
    println!("   Login with: silo login --endpoint https://127.0.0.1:8443");
}
