use clap::{Parser, Subcommand};
use std::fs::read_to_string;
use std::path::PathBuf;
use std::process::ExitCode;

mod utils;

pub enum ToyVmmExitCode {
    /// Success exit code.
    Ok = 0,
    /// Generic error exit code.
    GenericError = 1,
    /// Generic exit code for an error considered not possible to occur if program logic is
    /// sound.
    UnexpectedError = 2,
    /// Bad configuration for toyvmm's resources.
    BadConfiguration = 153,
}

#[derive(Debug, thiserror::Error)]
enum CliInputError {
    #[error("Failed to open file: {0}")]
    FileIo(#[from] std::io::Error),
    #[error("Failed to execute vmm: {0}")]
    Utils(#[from] utils::UtilsError),
}

#[derive(Debug, thiserror::Error)]
enum MainError {
    #[error("Unexpected input error: {0}")]
    CliError(#[from] CliInputError),
}

impl From<MainError> for ExitCode {
    fn from(value: MainError) -> Self {
        let exit_code = match value {
            MainError::CliError(e) => match e {
                CliInputError::FileIo(_) => ToyVmmExitCode::BadConfiguration,
                CliInputError::Utils(_) => ToyVmmExitCode::GenericError,
            },
        };
        ExitCode::from(exit_code as u8)
    }
}

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Virtual Machine related operations
    #[command(subcommand)]
    Vm(VmOperation),
}

#[derive(Debug, Subcommand)]
enum VmOperation {
    /// Run guest VM
    Run {
        /// Path of the config file
        #[arg(short, long, value_name = "PATH")]
        config: PathBuf,
    },
}

fn run(cli: Cli) -> Result<(), CliInputError> {
    match cli.command {
        Command::Vm(op) => match op {
            VmOperation::Run { config } => {
                let config = read_to_string(config)?;
                utils::run_vm_from_config(&config)?;
                Ok(())
            }
        },
    }
}

fn main_exec() -> Result<(), MainError> {
    let cli = Cli::parse();
    let result = run(cli);
    if let Err(e) = result {
        eprintln!("{}", e);
        return Err(MainError::CliError(e));
    }
    Ok(())
}

fn main() -> ExitCode {
    let result = main_exec();
    if let Err(err) = result {
        eprintln!("Error: {err:?}");
        ExitCode::from(err)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::utils::tempfile::TempFile;
    use std::io::Write;

    pub fn generate_config(kernel_image_path: &str, rootfs_path: &str) -> String {
        format!(
            r#"{{
                "boot-source": {{
                    "kernel_path": "{}",
                    "boot_args": "console=ttyS0 reboot=k panic=1"
                }},
                "drives": [
                    {{
                        "path_on_host": "{}",
                        "is_root_device": true
                    }}
                ],
                "machine-config": {{
                    "vcpu_count": 1,
                    "mem_size_mib": 128,
                    "track_dirty_page": false
                }}
            }}"#,
            kernel_image_path, rootfs_path,
        )
    }

    fn generate_config_file(kernel_image_path: &str, rootfs_path: &str) -> TempFile {
        let config = generate_config(kernel_image_path, rootfs_path);
        let config_file = TempFile::new().unwrap();
        config_file.as_file().write_all(config.as_bytes()).unwrap();
        config_file
    }

    #[test]
    fn test_vm_run_command() {
        let kernel_image_path = TempFile::new().unwrap();
        let rootfs_file = TempFile::new().unwrap();
        let config_file = generate_config_file(
            kernel_image_path.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap(),
        );
        let args = vec![
            "toyvmm",
            "vm",
            "run",
            "--config",
            config_file.as_path().to_str().unwrap(),
        ];
        let cli = Cli::parse_from(args);
        #[allow(unreachable_patterns)]
        #[allow(clippy::collapsible_match)]
        #[allow(unused_variables)]
        match cli.command {
            Command::Vm(op) => match op {
                VmOperation::Run { config } => (),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
    }
}
