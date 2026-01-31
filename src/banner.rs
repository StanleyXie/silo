use console::style;

pub fn print_banner() {
    let logo = [
        "      .-------.      ",
        "    /    |    \\     ",
        "   |_____|_____|    ",
        "   |  |  #  |  |    ",
        "   |  |  #  |  |    ",
        "   |  |  #  |  |    ",
        "   |  |__|__|  |    ",
        "    \\    |    /     ",
        "      '-----'       ",
    ];

    let text = [
        "  ",
        "  ____  ____  _      ____  ",
        " / ___)(_  _)( \\    / __ \\ ",
        " \\___ \\  )(   ) )  ( (  ) )",
        " (____/ (__) (___)  \\____/ ",
        " ",
        "  SECURE TERRAFORM GATEWAY ",
    ];

    println!();
    for i in 0..9 {
        let left = logo[i];
        let right = if i >= 1 && i - 1 < text.len() {
            text[i - 1]
        } else {
            ""
        };
        // Print with fixed width for the logo
        println!("{}{}", style(format!("{: <22}", left)).cyan().bold(), style(right).cyan());
    }
    println!();
}
