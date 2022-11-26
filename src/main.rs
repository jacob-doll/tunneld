use clap::{Parser, Subcommand};
use log::{error, info};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    device: Option<String>,

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

        #[arg(short, long, default_value_t = String::from("255.255.255.0"))]
        mask: String,
    },
}

fn main() {
    env_logger::init();

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Client { server }) => {
            info!("Client with server: {:?}", server);
        }
        Some(Commands::Server { subnet, mask }) => {
            info!("Server with subnet: {:?} and mask: {:?}", subnet, mask);
        }
        None => {
            error!("Must specify either client or server!");
        }
    }
}
