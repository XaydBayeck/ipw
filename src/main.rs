mod app;
mod cli;
mod head;
mod socket;

use clap::Parser;
use cli::{Args, Command};

use crate::app::App;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut app = App::<256>::new()?;

    match args.command {
        Command::Send {
            dhost,
            destip,
            protocol,
            radix,
            text,
            file,
        } => {
            let id_count = 0;
            if let Some(file) = file {
                app.send_file(id_count, dhost, destip, protocol, &file, radix)?;
            } else if let Some(text) = text {
                app.send(id_count, dhost, destip, protocol, &text, radix)?;
            } else {
                app.send(id_count, dhost, destip, protocol, "", radix)?;
            }
        }
        Command::Analyz => app.analyz()?,
        Command::Filter {
            src_mac,
            dst_mac,
            shost,
            dhost,
            log,
        } => app.filter(src_mac, dst_mac, shost, dhost, log)?,
    }
    Ok(())
}
