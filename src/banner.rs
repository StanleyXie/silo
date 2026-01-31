use console::style;

pub fn print_banner() {
    let text = [
        r#"  _____ _ _      "#,
        r#" / ____(_) |     "#,
        r#"| (___  _| | ___ "#,
        r#" \___ \| | |/ _ \"#,
        r#" ____) | | | (_) |"#,
        r#"|_____/|_|_|\___/ "#,
        r#"                  "#,
        &format!("Secure Terraform State Gateway v{} ", env!("CARGO_PKG_VERSION")),
    ];

    println!();
    for line in text {
        println!("  {}", style(line).cyan());
    }
    println!();
}
