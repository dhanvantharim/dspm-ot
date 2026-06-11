use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

#[derive(Parser)]
#[command(name = "ot-dspm", version, about = "Passive OT network traffic analyzer for data security posture management")]
struct Cli {
    #[arg(long, env = "OT_DSPM_CONFIG", global = true)]
    config: Option<PathBuf>,

    #[arg(long, global = true, default_value = "ot-dspm.db")]
    db: PathBuf,

    #[arg(long, global = true, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Capture {
        #[arg(long)]
        interface: String,

        #[arg(long)]
        duration: Option<u64>,

        #[arg(long)]
        filter: Option<String>,
    },
    Analyze {
        #[arg(long)]
        file: PathBuf,
    },
    Report {
        #[arg(long, default_value = "json")]
        format: String,

        #[arg(long)]
        output: Option<PathBuf>,

        #[arg(long, default_value = "posture")]
        r#type: String,

        #[arg(long)]
        top: Option<usize>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    ot_dspm::logging::init(&cli.log_level)?;

    info!(version = env!("CARGO_PKG_VERSION"), "ot-dspm starting");

    match cli.command {
        Command::Capture { interface, duration, filter } => {
            ot_dspm::capture::run(&interface, duration, filter.as_deref(), &cli.db, cli.config.as_deref())
        }
        Command::Analyze { file } => {
            ot_dspm::analyze::run(&file, &cli.db, cli.config.as_deref())
        }
        Command::Report { format, output, r#type, top } => {
            ot_dspm::report::run(&format, output.as_deref(), &r#type, top, &cli.db)
        }
    }
}
