use std::fs;
use std::path::Path;
use std::process::Command;

pub fn install_service(component: &str, user: &str) -> Result<(), String> {
    let binary_path = find_binary("silo-server")?;
    let config_path = "/etc/silo/silo.yaml";

    if !Path::new(config_path).exists() {
        return Err(format!("Configuration file not found at {}. Please run 'silo init' and copy silo.yaml to /etc/silo/.", config_path));
    }

    let service_name = if component == "all" {
        "silo".to_string()
    } else {
        match component {
            "control-plane" => "silo-control".to_string(),
            "gateway" => "silo-gateway".to_string(),
            _ => return Err(format!("Invalid component: {}", component)),
        }
    };

    let unit_content = format!(
r#"[Unit]
Description=Silo Secure Terraform State Gateway - {component}
After=network.target vault.service

[Service]
Type=simple
User={user}
WorkingDirectory=/etc/silo
ExecStart={binary_path} --component {component} --config {config_path}
Restart=always
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
"#,
        component = component,
        user = user,
        binary_path = binary_path,
        config_path = config_path
    );

    let unit_path = format!("/etc/systemd/system/{}.service", service_name);
    
    println!("📝 Generating service unit at {}...", unit_path);
    
    // In a real implementation, we'd need sudo to write to /etc/systemd/system/
    // For this CLI tool, we'll suggest the command if we fail to write directly.
    match fs::write(&unit_path, &unit_content) {
        Ok(_) => {
            println!("✅ Service unit installed.");
            println!("🚀 Run 'systemctl daemon-reload' and 'systemctl enable --now {}' to start.", service_name);
            Ok(())
        }
        Err(e) => {
            let tmp_path = format!("/tmp/{}.service", service_name);
            fs::write(&tmp_path, &unit_content).map_err(|e| e.to_string())?;
            Err(format!(
                "Failed to write to {}: {}. \nUnit file generated at {}. \nPlease run: sudo cp {} {} && sudo systemctl daemon-reload",
                unit_path, e, tmp_path, tmp_path, unit_path
            ))
        }
    }
}

pub fn show_status() {
    let services = ["silo", "silo-control", "silo-gateway"];
    println!("{:<20} {:<10} {:<15}", "Service", "Status", "Description");
    println!("{}", "-".repeat(45));

    for svc in services {
        let output = Command::new("systemctl")
            .arg("is-active")
            .arg(svc)
            .output();
        
        let status = match output {
            Ok(out) => {
                if out.status.success() {
                    "ACTIVE"
                } else {
                    "INACTIVE"
                }
            },
            Err(_) => "UNKNOWN (systemd not found)",
        };
        
        let desc = match svc {
            "silo" => "All-in-one Silo",
            "silo-control" => "Control Plane Only",
            "silo-gateway" => "Gateway Proxy Only",
            _ => "",
        };

        println!("{:<20} {:<10} {:<15}", svc, status, desc);
    }
}

pub fn tail_logs(component: &str) {
    let service_name = match component {
        "all" => "silo",
        "control-plane" => "silo-control",
        "gateway" => "silo-gateway",
        _ => component,
    };

    println!("📋 Tailing logs for service: {} (Ctrl+C to stop)", service_name);
    let _ = Command::new("journalctl")
        .arg("-u")
        .arg(service_name)
        .arg("-f")
        .spawn()
        .and_then(|mut child| child.wait());
}

fn find_binary(name: &str) -> Result<String, String> {
    // Check common locations
    let paths = ["/usr/local/bin/", "/usr/bin/", "/opt/homebrew/bin/"];
    for p in paths {
        let full = format!("{}{}", p, name);
        if Path::new(&full).exists() {
            return Ok(full);
        }
    }
    
    // Try which command
    let output = Command::new("which")
        .arg(name)
        .output();
    
    if let Ok(out) = output {
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
        }
    }

    Err(format!("Binary '{}' not found in PATH or common locations. Please install it first.", name))
}
