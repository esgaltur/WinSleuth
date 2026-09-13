use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

pub const DEFAULT_DAYS: u32 = 7;

#[derive(Parser)]
#[command(
    name = "winsleuth",
    author,
    version,
    about = "Windows instability diagnosis: drivers, crashes, hardware errors and what changed.",
    long_about = None
)]
pub struct Cli {
    /// Re-launch with Administrator rights if not already elevated.
    #[arg(long, global = true)]
    pub elevate: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Collect evidence, correlate it and rank the likely causes.
    Scan(ScanArgs),

    /// List loaded kernel drivers.
    InspectDrivers {
        /// Include Microsoft-signed operating system drivers.
        #[arg(long)]
        all: bool,
        /// Show only drivers matching the known-vulnerable corpus.
        #[arg(long)]
        vulnerable_only: bool,
    },

    /// List devices reporting a problem code.
    InspectDevices,

    /// List critical events from the scan window.
    InspectEvents {
        #[arg(short, long, default_value_t = DEFAULT_DAYS)]
        days: u32,
    },

    /// Print a chronological timeline of events and crashes.
    Timeline {
        #[arg(short, long, default_value_t = DEFAULT_DAYS)]
        days: u32,
    },

    /// Watch for crashes and critical events as they happen.
    Monitor(MonitorArgs),

    /// Gather a redacted evidence bundle to send to someone who can help.
    Collect {
        /// Where to write the zip archive.
        #[arg(short, long, default_value = "winsleuth-evidence.zip")]
        output: PathBuf,

        #[arg(short, long, default_value_t = 30)]
        days: u32,

        /// Include crash dump files. They are large and may contain fragments
        /// of whatever was in memory.
        #[arg(long)]
        include_dumps: bool,
    },

    /// Compare this machine now against a previously saved scan.
    Diff {
        /// A stored snapshot to compare against. Defaults to the most recent.
        #[arg(short, long)]
        against: Option<PathBuf>,

        #[arg(short, long, default_value_t = DEFAULT_DAYS)]
        days: u32,
    },

    /// List saved scans.
    History,

    /// Download the known-vulnerable driver corpus from loldrivers.io.
    UpdateBlocklist,

    /// Arm or disarm Driver Verifier against the drivers under suspicion.
    Verify(VerifyArgs),

    /// Launch the desktop interface.
    Ui,
}

#[derive(Args)]
pub struct ScanArgs {
    /// How many days of history to examine.
    #[arg(short, long, default_value_t = DEFAULT_DAYS)]
    pub days: u32,

    #[arg(short, long, value_enum, default_value_t = ReportFormat::Text)]
    pub format: ReportFormat,

    /// Write the report to a file as UTF-8.
    ///
    /// Prefer this over shell redirection: PowerShell's `>` writes UTF-16 with
    /// a byte order mark, which is not valid JSON for most parsers.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Do not save this scan to the local history.
    #[arg(long)]
    pub no_save: bool,

    /// Skip SHA-256 hashing of every driver. Faster, but disables exact
    /// matching against the known-vulnerable corpus.
    #[arg(long)]
    pub no_hashes: bool,
}

#[derive(Args)]
pub struct MonitorArgs {
    /// How often to poll the things that cannot be subscribed to, in seconds.
    #[arg(short, long, default_value_t = 30)]
    pub interval: u64,

    /// Discord or Slack webhook to notify on a crash.
    #[arg(short, long)]
    pub webhook: Option<String>,

    /// Append every detection to this file.
    #[arg(short, long)]
    pub log_file: Option<PathBuf>,

    /// Run without a system tray icon.
    #[arg(long)]
    pub no_tray: bool,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Arm Driver Verifier against the top suspects from a fresh scan.
    #[arg(long, conflicts_with_all = ["off", "status"])]
    pub suspects: bool,

    /// Turn Driver Verifier off.
    #[arg(long, conflicts_with_all = ["suspects", "status"])]
    pub off: bool,

    /// Report what Driver Verifier is currently configured to do.
    #[arg(long, conflicts_with_all = ["suspects", "off"])]
    pub status: bool,

    /// Skip the confirmation prompt. Only do this if you have read what
    /// `--suspects` prints and know how to reach Safe Mode.
    #[arg(long)]
    pub yes: bool,

    #[arg(short, long, default_value_t = DEFAULT_DAYS)]
    pub days: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    /// Human-readable console output.
    Text,
    /// Machine-readable, for tooling or support.
    Json,
    /// A self-contained page that can be shared.
    Html,
}

impl ReportFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            ReportFormat::Text => "txt",
            ReportFormat::Json => "json",
            ReportFormat::Html => "html",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_tree_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn days_is_parsed_and_defaulted() {
        let cli = Cli::try_parse_from(["winsleuth", "scan", "--days", "30"]).unwrap();
        match cli.command {
            Commands::Scan(args) => assert_eq!(args.days, 30),
            _ => panic!("expected scan"),
        }

        let cli = Cli::try_parse_from(["winsleuth", "scan"]).unwrap();
        match cli.command {
            Commands::Scan(args) => assert_eq!(args.days, DEFAULT_DAYS),
            _ => panic!("expected scan"),
        }
    }

    #[test]
    fn format_is_a_closed_set_rather_than_a_free_string() {
        // The old `--format` was a String compared with `==`, so a typo silently
        // produced text output.
        assert!(Cli::try_parse_from(["winsleuth", "scan", "--format", "jsonn"]).is_err());
        assert!(Cli::try_parse_from(["winsleuth", "scan", "--format", "json"]).is_ok());
        assert!(Cli::try_parse_from(["winsleuth", "scan", "--format", "html"]).is_ok());
    }

    #[test]
    fn output_path_is_available_so_redirection_is_not_needed() {
        let cli = Cli::try_parse_from(["winsleuth", "scan", "-f", "json", "-o", "r.json"]).unwrap();
        match cli.command {
            Commands::Scan(args) => {
                assert_eq!(args.output, Some(PathBuf::from("r.json")));
                assert_eq!(args.format, ReportFormat::Json);
            }
            _ => panic!("expected scan"),
        }
    }

    #[test]
    fn verifier_modes_are_mutually_exclusive() {
        assert!(Cli::try_parse_from(["winsleuth", "verify", "--suspects", "--off"]).is_err());
        assert!(Cli::try_parse_from(["winsleuth", "verify", "--suspects"]).is_ok());
        assert!(Cli::try_parse_from(["winsleuth", "verify", "--off"]).is_ok());
    }
}
