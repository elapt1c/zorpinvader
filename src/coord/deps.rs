//! Runtime dependencies, installed on demand.
//!
//! The scanner needs two external programs: `tor` (only when tor transport is
//! used) and `curl` (page fetching and the client's control channel). Asking a
//! user to install them by hand is friction with no upside, so this module
//! detects the platform's package manager and installs what is missing.
//!
//! Rules it follows:
//!
//! * it never downloads binaries itself — the distribution's signed packages are
//!   used, so the trust chain stays the distro's;
//! * the exact command is printed before it runs;
//! * it works without a password when root, and falls back to non-interactive
//!   `sudo -n` otherwise (never prompts into a pipe);
//! * `--no-install` (or an unknown package manager) turns it into a clear error
//!   naming the command to run.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A package manager we know how to drive non-interactively.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageManager {
    Apt,
    Dnf,
    Yum,
    Pacman,
    Zypper,
    Apk,
    Brew,
}

impl PackageManager {
    pub fn binary(self) -> &'static str {
        match self {
            PackageManager::Apt => "apt-get",
            PackageManager::Dnf => "dnf",
            PackageManager::Yum => "yum",
            PackageManager::Pacman => "pacman",
            PackageManager::Zypper => "zypper",
            PackageManager::Apk => "apk",
            PackageManager::Brew => "brew",
        }
    }

    pub fn install_args(self, package: &str) -> Vec<String> {
        let pkg = package.to_string();
        let args: Vec<&str> = match self {
            PackageManager::Apt => vec!["install", "-y", &pkg],
            PackageManager::Dnf | PackageManager::Yum => vec!["install", "-y", &pkg],
            PackageManager::Pacman => vec!["-S", "--noconfirm", &pkg],
            PackageManager::Zypper => vec!["--non-interactive", "install", &pkg],
            PackageManager::Apk => vec!["add", &pkg],
            PackageManager::Brew => vec!["install", &pkg],
        };
        args.into_iter().map(|s| s.to_string()).collect()
    }

    pub fn command_line(self, package: &str) -> String {
        format!(
            "{} {}",
            self.binary(),
            self.install_args(package).join(" ")
        )
    }
}

/// Pick the package manager this machine actually has, most specific first.
pub fn detect_package_manager() -> Option<PackageManager> {
    for candidate in [
        PackageManager::Apt,
        PackageManager::Dnf,
        PackageManager::Yum,
        PackageManager::Pacman,
        PackageManager::Zypper,
        PackageManager::Apk,
        PackageManager::Brew,
    ] {
        if find_in_path(candidate.binary()).is_some() {
            return Some(candidate);
        }
    }
    None
}

/// Look for an executable in the usual places and `$PATH`.
pub fn find_in_path(binary: &str) -> Option<PathBuf> {
    for dir in ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"] {
        let path = Path::new(dir).join(binary);
        if is_executable(&path) {
            return Some(path);
        }
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let path = dir.join(binary);
        if is_executable(&path) {
            return Some(path);
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// Make sure `binary` exists, installing `package` when it does not.
///
/// `purpose` is used in the messages ("the HTTP fetcher", "tor transport").
pub fn ensure_binary(
    binary: &str,
    package: &str,
    purpose: &str,
    auto_install: bool,
) -> Result<PathBuf, String> {
    if let Some(path) = find_in_path(binary) {
        return Ok(path);
    }

    if !auto_install {
        return Err(missing_message(binary, package, purpose, None));
    }

    let manager = match detect_package_manager() {
        Some(m) => m,
        None => return Err(missing_message(binary, package, purpose, None)),
    };

    let command_line = manager.command_line(package);
    eprintln!(
        "[deps] {} is not installed (needed for {}); installing with: {}",
        binary, purpose, command_line
    );

    let status = run_privileged(manager, package)?;
    if !status {
        return Err(format!(
            "automatic installation failed. Install it yourself: sudo {}",
            command_line
        ));
    }

    find_in_path(binary).ok_or_else(|| {
        format!(
            "{} still is not in PATH after installing it. If the package is already \
             present but its binary is missing, reinstall it (e.g. `sudo {} install \
             --reinstall {}`), or pass an explicit path.",
            binary,
            manager.binary(),
            package
        )
    })
}

/// Run the install, as root if we are, otherwise via passwordless sudo.
fn run_privileged(manager: PackageManager, package: &str) -> Result<bool, String> {
    let args = manager.install_args(package);
    let is_root = unsafe { libc::geteuid() } == 0;

    let mut command = if is_root {
        Command::new(manager.binary())
    } else {
        let mut cmd = Command::new("sudo");
        cmd.arg("-n").arg(manager.binary());
        cmd
    };
    command.args(&args);

    match command.status() {
        Ok(status) if status.success() => Ok(true),
        Ok(_) => Ok(false),
        Err(e) if !is_root => Err(format!(
            "could not run sudo -n: {}. Install it yourself: sudo {}",
            e,
            manager.command_line(package)
        )),
        Err(e) => Err(format!(
            "could not run {}: {}. Install it yourself: sudo {}",
            manager.binary(),
            e,
            manager.command_line(package)
        )),
    }
}

fn missing_message(
    binary: &str,
    package: &str,
    purpose: &str,
    manager: Option<PackageManager>,
) -> String {
    let install = match manager.or_else(detect_package_manager) {
        Some(m) => format!("sudo {}", m.command_line(package)),
        None => format!(
            "install `{}` with your platform's package manager (it is needed for {})",
            package, purpose
        ),
    };
    format!(
        "{} is required for {} but is not installed.\n  {}",
        binary, purpose, install
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knows_the_noninteractive_install_flags() {
        assert_eq!(
            PackageManager::Apt.install_args("tor"),
            vec!["install", "-y", "tor"]
        );
        assert_eq!(
            PackageManager::Pacman.install_args("tor"),
            vec!["-S", "--noconfirm", "tor"]
        );
        assert_eq!(
            PackageManager::Brew.command_line("tor"),
            "brew install tor"
        );
        assert_eq!(
            PackageManager::Apk.install_args("curl"),
            vec!["add", "curl"]
        );
    }

    #[test]
    fn finds_a_binary_that_exists() {
        // `sh` is guaranteed to be present in the test environment.
        assert!(find_in_path("sh").is_some());
        assert!(find_in_path("definitely-not-a-real-binary-xyz").is_none());
    }

    #[test]
    fn ensure_binary_passes_through_what_is_already_installed() {
        let path = ensure_binary("sh", "sh", "tests", false).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn missing_binary_without_install_says_what_to_run() {
        let err = ensure_binary("definitely-not-real-xyz", "xyz", "tests", false).unwrap_err();
        assert!(err.contains("definitely-not-real-xyz"), "got: {}", err);
        assert!(err.contains("install"), "got: {}", err);
    }
}
