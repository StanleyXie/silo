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
        r#"       ________________       "#,
        r#"      /       |        \      "#,
        r#"     |________|_________|     "#,
        r#"              |               "#,
        r#"            __#__             "#,
        r#"           |  #  |            "#,
        r#"           |  #  |            "#,
        r#"           |__#__|            "#,
        r#"      \_______|________/      "#,
    ];

    println!();
    for i in 0..9 {
        let left = if i < text.len() {
            text[i]
        } else {
            ""
        };
        let right = icon[i];
        
        // Print text on left (cyan), icon on right (cyan bold)
        println!("  {}{}", style(format!("{: <25}", left)).cyan(), style(right).cyan().bold());
    }
    println!();
}
