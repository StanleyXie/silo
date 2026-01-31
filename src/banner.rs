use console::style;

pub fn print_banner() {
    let text = [
        r#"  ____  ____  _      ____  "#,
        r#" / ___)(_  _)( \    / __ \ "#,
        r#" \___ \  )(   ) )  ( (  ) )"#,
        r#" (____/ (__) (___)  \____/ "#,
        r#"                           "#,
        r#"  SECURE TERRAFORM GATEWAY "#,
        &format!("  v{} ", env!("CARGO_PKG_VERSION")),
    ];

    let icon = [
        r#"      .---------------.       "#,
        r#"     /        |        \      "#,
        r#"    |_________|_________|     "#,
        r#"              |               "#,
        r#"           ___#___            "#,
        r#"          |   #   |           "#,
        r#"          |   #   |           "#,
        r#"          |___#___|           "#,
        r#"     \________|________/      "#,
    ];

    println!();
    for i in 0..9 {
        let left = if i >= 1 && i - 1 < text.len() {
            text[i - 1]
        } else {
            ""
        };
        let right = icon[i];
        
        // Print text on left (cyan), icon on right (cyan bold)
        println!("{}{}", style(format!("{: <30}", left)).cyan(), style(right).cyan().bold());
    }
    println!();
}
