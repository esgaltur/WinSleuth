use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about = "Instability WinSleuth: A Windows-native diagnostic tool.", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Full system scan and analysis
    Scan {
        /// Format of the report (text or json)
        #[arg(short, long, default_value = "text")]
        format: String,
        /// How many days of events to look back
        #[arg(short, long, default_value = "7")]
        days: u32,
    },
    /// Enumerate all suspicious drivers
    InspectDrivers,
    /// Enumerate all devices with problem codes
    InspectDevices,
    /// List critical event logs from the last N days
    InspectEvents {
        #[arg(short, long, default_value = "7")]
        days: u32,
    },
    /// Print a chronological timeline of all gathered events and crashes
    Timeline,
    /// Live monitoring mode: watch for new critical system events in real-time
    Monitor {
        /// Refresh interval in seconds
        #[arg(short, long, default_value = "5")]
        interval: u64,
        /// Optional: Discord/Slack webhook URL to ping on critical crashes
        #[arg(short, long)]
        webhook: Option<String>,
        /// Optional: Path to a CSV/txt file to persistently log all detected events
        #[arg(short, long)]
        log_file: Option<String>,
    },
    /// Launch the Desktop UI
    Ui,
}
