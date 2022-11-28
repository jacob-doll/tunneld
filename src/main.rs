use std::process::exit;

use clap::{Parser, Subcommand};
use env_logger::Env;
use log::{error, info};

pub mod server;
use crate::server::Server;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, default_value_t = String::from("tun%d"))]
    ifname: String,

    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Client {
        #[arg(short, long)]
        server: String,
    },
    Server {
        #[arg(short, long)]
        subnet: String,
    },
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Client { server }) => {
            info!("Client with server: {:?}", server);
        }
        Some(Commands::Server { subnet }) => {
            info!("Server with subnet: {:?}", subnet);
            match Server::new(cli.ifname.as_str(), subnet.as_str()) {
                Ok(mut server) => server.start(),
                Err(e) => {
                    error!("Could not start server: {}", e);
                    exit(1)
                }
            }
        }
        None => {
            error!("Must specify either client or server!");
            exit(1)
        }
    }
}
