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

    let icon = [
        r#"   #######################   "#,
        r#"   #######################   "#,
        r#"            #####            "#,
        r#"            #####            "#,
        r#"            #####            "#,
        r#"            #####            "#,
        r#"            #####            "#,
        r#"            #####            "#,
        r#"            #####            "#,
    ];

    println!();
    for i in 0..9 {
        let left = if i < text.len() {
            text[i]
        } else {
            ""
        };
        let right = icon[i];
        
        // Ensure consistent width for text column
        println!("  {}{}", style(format!("{: <45}", left)).cyan(), style(right).cyan().bold());
    }
    println!();
}
