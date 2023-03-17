#![feature(never_type, exit_status_error)]
mod pty;
use alpm::SigLevel;
use anyhow::{anyhow, Error};
use clap::Parser;
use futures::{stream::FuturesOrdered, StreamExt, TryStreamExt};
use indicatif::ProgressStyle;
use ordered_float::NotNan;
use pty::PtyProcess;
use serde::{Deserialize, Serialize};
use srcinfo::Srcinfo;
use std::{
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    io::{stderr, stdin, stdout, Cursor, Write},
    os::{
        fd::AsRawFd,
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Path, PathBuf},
};
use syscalls::{syscall, Sysno};
use tokio::{io::AsyncBufReadExt, sync::oneshot};
use tokio_stream::wrappers::LinesStream;

#[derive(Debug, Serialize, Deserialize)]
pub struct RunnerCommand {
    name: String,
    pkgbuild_dir: PathBuf,
    depends: Vec<String>,
    quit: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BuildResult {
    success: bool,
    error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct AurResult<T> {
    resultcount: u32,
    results: Vec<T>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct AurPackage {
    name: String,
    package_base: String,
    description: String,
    num_votes: u32,
    popularity: f32,
    first_submitted: u32,
    last_modified: u32,
    out_of_date: Option<u32>,
    maintainer: Option<String>,
    version: String,
    #[serde(rename = "URLPath")]
    url_path: String,
    #[serde(rename = "URL")]
    url: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct AurSearch {
    package_base: String,
    name: String,
    description: String,
    version: String,
    popularity: NotNan<f32>,
    num_votes: u32,
}
use std::{
    mem::ManuallyDrop,
    os::fd::{AsFd, OwnedFd},
};

use rustix::fd::FromRawFd;

trait Unwrap {
    type Item;
    fn unwrap(self) -> Self::Item;
}

impl Unwrap for bool {
    type Item = ();
    fn unwrap(self) -> Self::Item {
        if !self {
            panic!("unwrapping a false value")
        }
    }
}

struct KillGuard {
    child: std::process::Child,
}

impl Drop for KillGuard {
    fn drop(&mut self) {
        if let Err(e) = self.child.kill() {
            eprintln!("Failed to kill child: {}, pid: {}", e, self.child.id());
        }
    }
}

trait EnsureKill {
    fn ensure_kill(self) -> KillGuard;
}

impl EnsureKill for std::process::Child {
    fn ensure_kill(self) -> KillGuard {
        KillGuard { child: self }
    }
}

fn run_nspawn(
    root: &str,
    command: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> Result<bool, Error> {
    let root = format!("/var/lib/aurbuild/x86_64/{}", root);
    let nspawn_args = [
        "-C",
        "/etc/aurutils/pacman-localrepo.conf",
        "-M",
        "/etc/makepkg-chroot.conf",
        &root,
        "--bind=/var/cache/pacman/pkg",
        "--bind=/home/shui/.local/var/repo",
    ];
    Ok(std::process::Command::new("arch-nspawn")
        .args(nspawn_args)
        .args(command)
        .status()?
        .success())
}

fn runner_main() -> Result<!, Error> {
    // We only inherit fd 0 and 1. 1 is our special control fd, we will move 1 to something else
    // and dup 0 to 1 and 2
    sudo::with_env(&["GNUPGHOME", "SSH_AUTH_SOCK"]).unwrap();
    let special_fd = std::io::stdout().as_fd().try_clone_to_owned().unwrap();
    // highly unsafe. only works if we are exec'd properly
    unsafe {
        rustix::io::close(std::io::stdout().as_raw_fd());
        rustix::io::close(std::io::stderr().as_raw_fd());
        rustix::io::dup2(
            std::io::stdin(),
            &mut ManuallyDrop::new(OwnedFd::from_raw_fd(std::io::stdout().as_raw_fd())),
        )?;
        rustix::io::dup2(
            std::io::stdin(),
            &mut ManuallyDrop::new(OwnedFd::from_raw_fd(std::io::stderr().as_raw_fd())),
        )?;
    }

    // mount overlayfs for distfile cache
    println!("Runner has started.");
    println!("SUDO_USER: {}", std::env::var("SUDO_USER").unwrap());
    // Update chroot environment
    run_nspawn("root", ["pacman", "-Syu", "--noconfirm"])?.unwrap();
    // Send a notification to parent
    let control: std::fs::File = special_fd.into();
    bincode::serialize_into(
        &control,
        &BuildResult {
            success: true,
            error: None,
        },
    )?;
    let chroot_base = Path::new("/var/lib/aurbuild/x86_64");
    let makechrootpkg_args = [
        "-D",
        "/var/cache/pacman/pkg",
        "-D",
        "/home/shui/.local/var/repo",
        "-D",
        "/home/shui/.cache/makepkg",
        "-r",
        "/var/lib/aurbuild/x86_64",
    ];
    struct ZfsSnapshot;
    impl ZfsSnapshot {
        fn new() -> Result<Self, Error> {
            std::process::Command::new("zfs")
                .args(["snapshot", "grid/base/root/aurbuild@shui"])
                .status()?
                .exit_ok()?;
            std::process::Command::new("zfs")
                .args(["clone", "-o", "mountpoint=/var/lib/aurbuild/x86_64/shui"])
                .args([
                    "grid/base/root/aurbuild@shui",
                    "grid/base/root/aurbuild/shui",
                ])
                .status()?
                .exit_ok()?;
            Ok(Self)
        }
    }
    impl Drop for ZfsSnapshot {
        fn drop(&mut self) {
            // Cleanup the chroot environment
            let result = std::process::Command::new("zfs")
                .args(["destroy", "-Rr", "grid/base/root/aurbuild@shui"])
                .status();
            if result.as_ref().map(|r| !r.success()).unwrap_or(true) {
                eprintln!("Failed to destroy zfs snapshot: {:?}", result);
            }
        }
    }
    loop {
        // Read packets of bincode encoded RunnerCommand
        let cmd: RunnerCommand = bincode::deserialize_from(&control)?;
        if cmd.quit {
            break;
        }
        std::fs::copy(
            "/etc/makepkg-chroot.conf",
            chroot_base.join("root").join("etc").join("makepkg.conf"),
        )?;
        std::fs::copy(
            "/etc/aurutils/pacman-localrepo.conf",
            chroot_base.join("root").join("etc").join("pacman.conf"),
        )?;
        // synchronize the chroot environment, clone the zfs filesystem
        let zfs_snapshot = ZfsSnapshot::new()?;
        std::process::Command::new("chown")
            .args(["-R", "shui:shui", "/var/lib/aurbuild/x86_64/shui/home/shui"])
            .status()?;
        let pacmanconf = pacmanconf::Config::with_opts(
            None,
            Some(chroot_base.join("shui").join("etc").join("pacman.conf")),
            Some(chroot_base.join("shui")),
        )?;
        println!("DBPath: {:?}", pacmanconf.db_path);
        let alpm = alpm::Alpm::new(
            chroot_base.join("shui").into_os_string().into_vec(),
            pacmanconf.db_path.into(),
        )?;
        // install missing dependencies
        let to_install: Vec<_> = cmd
            .depends
            .into_iter()
            .filter(|dep| !alpm.satisfied(dep))
            .collect();
        run_nspawn(
            "shui",
            ["pacman", "-Syu", "--noconfirm"]
                .into_iter()
                .chain(to_install.iter().map(|s| s.as_str())),
        )?
        .unwrap();
        let result = std::process::Command::new("makechrootpkg")
            .args(makechrootpkg_args)
            .env("SRCDEST", "/home/shui/.cache/makepkg/distfiles")
            .current_dir(&cmd.pkgbuild_dir)
            .status();
        let success = result.map(|s| s.success()).unwrap_or(false);
        if !success {
            std::mem::forget(zfs_snapshot);
        }
        bincode::serialize_into(
            &control,
            &BuildResult {
                success,
                error: None,
            },
        )?;
    }
    std::process::exit(0);
}

fn fetch_options<'a>(progress: &'a mut Option<git2::Progress<'static>>) -> git2::FetchOptions<'a> {
    let mut remote_cbs = git2::RemoteCallbacks::new();
    remote_cbs.transfer_progress(|stats| {
        *progress = Some(stats.to_owned());
        true
    });
    let mut fetch_options = git2::FetchOptions::default();
    fetch_options.remote_callbacks(remote_cbs);
    fetch_options
}

async fn query_aur(name: &str) -> Result<AurResult<AurPackage>, Error> {
    let url = format!("https://aur.archlinux.org/rpc/?v=5&type=info&arg={}", name);
    let resp = reqwest::get(&url).await?.json().await?;
    Ok(resp)
}

fn base_dir() -> PathBuf {
    Path::new(std::env::var("HOME").unwrap().as_str())
        .join(".cache")
        .join("pkgbuilds")
}

fn is_source_vcs(source: &str) -> bool {
    if !source.contains("://") {
        return false;
    }

    let (_filename, url) = source.split_once("::").unwrap_or(("", source));
    let (proto, _url) = url.split_once("://").unwrap_or(("", url));
    let (proto, _transport) = proto.split_once('+').unwrap_or((proto, ""));
    matches!(proto, "git" | "hg" | "svn" | "bzr")
}

fn copy_pkgbuild_dir_to_tmp(path: &Path) -> Result<tempfile::TempDir, Error> {
    let tmpdir = tempfile::tempdir().unwrap();
    let mut path = path.as_os_str().to_owned();
    if path.as_bytes().last() != Some(&b'/') {
        // adds a trailing slash, so rsync copies the contents of the directory
        // instead of the directory itself
        path.push("/");
    }
    // rsync
    let cmd = std::process::Command::new("rsync")
        .args(["-a", "--delete", "--delete-excluded", "--exclude", ".git"])
        .arg(path)
        .arg(tmpdir.path())
        .status()?;
    if !cmd.success() {
        Err(anyhow!("Failed to copy pkgbuild dir to tmp"))
    } else {
        Ok(tmpdir)
    }
}

/// Returns Some(Srcinfo) if update was successful, None if there are conflicts in the git repo
async fn update_one_repo(
    name: String,
    aur_version: &alpm::Version,
    update_vcs: bool,
    progress: indicatif::ProgressBar,
    resolve_conflicts_tx: tokio::sync::mpsc::Sender<ResolveConflicts>,
) -> Result<Srcinfo, Error> {
    progress.set_style(ProgressStyle::with_template(&format!(
        "[{{spinner:.green}}] {{wide_msg}} [{name}]"
    ))?);
    let base = base_dir();
    let path = base.join(&name);
    tracing::info!("Processing {}", name);
    let path = if !path.exists() {
        // Check if package exists on AUR
        let resp = query_aur(&name).await?;
        // Clone the repo
        let package_base = resp
            .results
            .get(0)
            .unwrap_or_else(|| panic!("Package {} not found on AUR", name))
            .package_base
            .clone();
        let path = base.join(package_base.clone());
        if !path.exists() {
            tracing::info!("Cloning into {}", path.display());
            let url = format!(
                "https://aur.archlinux.org/{}.git",
                resp.results[0].package_base
            );
            let path = path.to_path_buf();
            tokio::task::spawn_blocking(move || {
                let mut progress = None;
                {
                    let mut builder = git2::build::RepoBuilder::new();
                    builder.fetch_options(fetch_options(&mut progress));
                    builder.clone(&url, &path)?;
                }
                let progress = progress.unwrap();
                tracing::info!(
                    "Cloned {}, {} objects, {} bytes",
                    package_base,
                    progress.received_objects(),
                    progress.received_bytes()
                );
                Ok::<_, Error>(())
            })
            .await??;
        }
        if name != resp.results[0].package_base {
            let dst = base.join(&name);
            let src = base.join(&resp.results[0].package_base);
            if !dst.exists() {
                std::os::unix::fs::symlink(src, dst)?;
            }
        }
        path
    } else {
        path
    };
    tracing::debug!("Path: {:?}", path);
    let srcinfo_path = path.join(".SRCINFO");
    let repo = git2::Repository::open_ext(
        &path,
        git2::RepositoryOpenFlags::NO_SEARCH,
        None::<OsString>,
    )?;
    let mut repo = if repo.index()?.has_conflicts() {
        let (tx, rx) = oneshot::channel();
        resolve_conflicts_tx
            .send(ResolveConflicts {
                path: path.clone(),
                reply: tx,
                repo,
            })
            .await
            .map_err(|e| anyhow!("Error sending resolve conflicts request: {}", e))?;
        rx.await?
    } else {
        repo
    };
    let srcinfo = Srcinfo::parse_file(&srcinfo_path)?;
    let our_version = alpm::Version::new(srcinfo.version());
    if &our_version >= aur_version {
        tracing::info!(
            "{} is up to date, ({} >= {})",
            name,
            srcinfo.version(),
            aur_version
        );
        tracing::info!("Sources: {:?}", srcinfo.base.source);
        let is_vcs = srcinfo
            .base
            .source
            .iter()
            .filter(|av| matches!(av.arch.as_deref(), None | Some("any") | Some("x86_64")))
            .flat_map(|av| av.vec.iter().map(|s| s.as_str()))
            .any(is_source_vcs);
        tracing::info!("is_vcs: {}", is_vcs);
        if &our_version > aur_version && !is_vcs {
            tracing::warn!("{}: Local version {} is newer than AUR", name, our_version);
        }
        return if is_vcs && update_vcs {
            // Ask makepkg to update sources
            tracing::info!("VCS source detected, updating");
            let tmpdir = copy_pkgbuild_dir_to_tmp(&path)?;
            let mut cmd = tokio::process::Command::new("makepkg");
            cmd.current_dir(tmpdir.path())
                .arg("--nodeps")
                .arg("-o")
                .arg("SRCDEST=/home/shui/.cache/makepkg/distfiles")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let (pty, mut child) = PtyProcess::spawn(cmd)?;
            let mut output_stream = LinesStream::new(
                tokio::io::BufReader::new(tokio::fs::File::from_std(pty.get_raw_handle()?)).lines(),
            );
            let mut output = String::new();
            let mut timer = tokio::time::interval(std::time::Duration::from_secs_f32(0.5));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let status = loop {
                tokio::select! {
                    status = child.wait() => {
                        break status?;
                    }
                    line = output_stream.next() => {
                        match line {
                            Some(Ok(line)) =>  {
                                output.push_str(&line);
                                output.push('\n');
                                let message = format!("{}: vcs: {}", srcinfo.base.pkgbase, &line);
                                progress.set_message(message);
                                progress.tick();
                            },
                            None => break child.wait().await?,
                            Some(Err(e)) if e.raw_os_error() == Some(5) => break child.wait().await?, // EIO means the child closed their pts
                            Some(Err(e)) => tracing::error!("Error reading output: {}", e),
                        }
                        tokio::task::yield_now().await;
                    }
                    _ = timer.tick() => {
                        progress.inc(1);
                        progress.tick();
                    }
                }
            };
            if !status.success() {
                tracing::error!("makepkg failed: {}", status);
                tracing::error!("Output: {}", output);
                return Err(anyhow!("makepkg failed"));
            }
            let status = std::process::Command::new("makepkg")
                .arg("--printsrcinfo")
                .current_dir(tmpdir.path())
                .output()?;
            status.status.exit_ok()?;
            progress.finish_and_clear();
            Ok(srcinfo::Srcinfo::parse_buf(Cursor::new(status.stdout))?)
        } else {
            progress.finish_and_clear();
            Ok(srcinfo)
        };
    }
    let (repo, has_conflicts, stashed) = tokio::task::spawn_blocking(move || {
        let current_branch = repo.head()?.shorthand().unwrap().to_owned();
        tracing::debug!("Current branch: {}", current_branch);
        {
            let mut remote = repo.find_remote("origin")?;
            let mut progress = None;
            remote.fetch(
                &[&current_branch],
                Some(&mut fetch_options(&mut progress)),
                None,
            )?;
            if let Some(progress) = progress {
                tracing::info!(
                    "Fetched {}, {} objects, {} bytes",
                    name,
                    progress.received_objects(),
                    progress.received_bytes()
                )
            }
        }
        // Update the branch reference
        let signature = repo.signature()?;
        let stashed = match repo.stash_save(&signature, "saving local changes", None) {
            Ok(_) => {
                tracing::info!("Stashed local changes");
                true
            }
            Err(e) => {
                if e.code() != git2::ErrorCode::NotFound {
                    panic!("Error stashing {name}: {}", e);
                }
                false
            }
        };
        {
            let remote_branch =
                repo.find_reference(&format!("refs/remotes/origin/{}", current_branch))?;
            let remote_branch =
                repo.find_annotated_commit(remote_branch.resolve()?.target().unwrap())?;
            let (analysis, _) = repo.merge_analysis(&[&remote_branch])?;
            if analysis.is_up_to_date() {
                tracing::info!("{} is up to date", name);
            } else if analysis.is_fast_forward() {
                let mut branch_head =
                    repo.find_reference(&format!("refs/heads/{}", current_branch))?;
                let mut checkout_tot = 0;
                let checkout_progress = |path: Option<&Path>, cur: usize, tot: usize| {
                    tracing::debug!("Checked out {}/{} files, {:?}", cur, tot, path);
                    checkout_tot = tot;
                };
                let treeish = repo.find_object(remote_branch.id(), None)?;
                repo.checkout_tree(
                    &treeish,
                    Some(git2::build::CheckoutBuilder::default().progress(checkout_progress)),
                )?;
                if checkout_tot > 0 {
                    tracing::info!("Checked out {checkout_tot} files for {name}");
                }
                branch_head.set_target(remote_branch.id(), "")?;
                repo.head()?.set_target(remote_branch.id(), "")?;
            } else {
                panic!("{} is not fast-forwardable", name);
            }
        }
        let has_conflicts = if stashed {
            repo.stash_pop(0, None)?;
            repo.index()?.has_conflicts()
        } else {
            false
        };
        Ok::<_, Error>((repo, has_conflicts, stashed))
    })
    .await??;
    if has_conflicts {
        let (tx, rx) = oneshot::channel();
        resolve_conflicts_tx
            .send(ResolveConflicts {
                path: path.clone(),
                reply: tx,
                repo,
            })
            .await
            .map_err(|e| anyhow!("Error sending resolve conflicts request: {}", e))?;
        rx.await?;
    }
    if stashed {
        // Re-generate srcinfo
        tracing::info!("Regenerating srcinfo");
        progress.set_message("Regenerating srcinfo");
        let status = std::process::Command::new("makepkg")
            .arg("--printsrcinfo")
            .current_dir(&path)
            .output()?;
        status.status.exit_ok()?;
        progress.finish_and_clear();
        Ok(srcinfo::Srcinfo::parse_buf(Cursor::new(status.stdout))?)
    } else {
        progress.finish_and_clear();
        Ok(srcinfo::Srcinfo::parse_file(srcinfo_path)?)
    }
}

trait Packages {
    fn repo_of(&self, name: &str) -> Vec<&str>;
    fn repo_package(&self, name: &str) -> Vec<(&str, alpm::Package)>;
    fn satisfied(&self, name: &str) -> bool;
}

impl Packages for alpm::Alpm {
    fn repo_of(&self, name: &str) -> Vec<&str> {
        self.syncdbs()
            .iter()
            .filter_map(|db| {
                let pkgs = db.pkgs();
                pkgs.find_satisfier(name).map(|_| db.name())
            })
            .collect()
    }
    fn repo_package(&self, name: &str) -> Vec<(&str, alpm::Package)> {
        self.syncdbs()
            .iter()
            .filter_map(|db| {
                let pkgs = db.pkgs();
                pkgs.find_satisfier(name).map(|pkg| (db.name(), pkg))
            })
            .collect()
    }
    fn satisfied(&self, name: &str) -> bool {
        let db = self.localdb();
        let pkgs = db.pkgs();
        pkgs.find_satisfier(name).is_some()
    }
}

#[derive(Debug, Clone)]
struct DepNode {
    /// srcinfo for this package, None means the package comes from official Arch repos
    srcinfo: Option<Srcinfo>,
    /// pkgbase for non-repo packages, or package name for official repo packages
    name: String,
}

fn srcinfo_to_depends(srcinfo: &Srcinfo) -> impl Iterator<Item = (&str, alpm::Depend)> + '_ {
    srcinfo
        .pkgs
        .iter()
        .flat_map(|pkg| pkg.depends.iter().map(|d| (pkg.pkgname.as_str(), d)))
        .chain(
            srcinfo
                .base
                .makedepends
                .iter()
                .map(|d| (srcinfo.base.pkgbase.as_str(), d)),
        )
        .filter_map(|(pkgname, d)| {
            if let Some(arch) = d.arch.as_ref() {
                if arch != "any" && arch != "x86_64" {
                    return None;
                }
            }
            Some((pkgname, &d.vec))
        })
        .flat_map(|(pkgname, d)| {
            d.iter()
                .map(move |d| (pkgname, alpm::Depend::new(d.clone())))
        })
}

fn prompt_resolve_conflict(
    path: impl AsRef<Path>,
    repo: &mut git2::Repository,
) -> Result<(), Error> {
    // Run git-diff to show the conflict
    loop {
        std::process::Command::new("git")
            .arg("diff")
            .arg("--color=always")
            .current_dir(path.as_ref())
            .status()?;
        let mut rl = rustyline::DefaultEditor::new()?;
        let path = path.as_ref();
        let readline = rl.readline(&format!(
            "Conflicts found in {} (e: edit, r: reset, a: abort): ",
            path.file_name().unwrap().to_str().unwrap()
        ))?;
        match readline.as_str() {
            "e" => {
                std::process::Command::new("git")
                    .arg("mergetool")
                    .current_dir(path)
                    .status()?;
                // Re-open the repository
                *repo = git2::Repository::open_ext(
                    path,
                    git2::RepositoryOpenFlags::NO_SEARCH,
                    None::<OsString>,
                )?
            }
            "r" => {
                let head = repo.head()?.resolve()?.target().unwrap();
                let head = repo.find_object(head, None)?;
                let reset_progress = |path: Option<&Path>, cur: usize, tot: usize| {
                    tracing::info!("Reset {}/{} files, {:?}", cur, tot, path);
                };
                repo.reset(
                    &head,
                    git2::ResetType::Hard,
                    Some(
                        git2::build::CheckoutBuilder::default()
                            .progress(reset_progress)
                            .force(),
                    ),
                )?;
                break;
            }
            "a" => {
                panic!("Aborting");
            }
            _ => (),
        };
        if repo.index()?.has_conflicts() {
            tracing::warn!("Conflicts still exist");
        } else {
            break;
        }
    }
    Ok(())
}

struct ResolveConflicts {
    path: PathBuf,
    reply: oneshot::Sender<git2::Repository>,
    repo: git2::Repository,
}

impl std::fmt::Debug for ResolveConflicts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolveConflicts")
            .field("path", &self.path)
            .finish()
    }
}

fn build(
    path: impl AsRef<Path>,
    srcinfo: &Srcinfo,
    runner_com: Option<&mut std::os::unix::net::UnixStream>,
) -> Result<(), Error> {
    let tmpdir = tempfile::Builder::new().prefix("aur-build").tempdir()?;
    let path = path.as_ref();
    let copy_options = fs_extra::dir::CopyOptions {
        copy_inside: true,
        content_only: true,
        ..Default::default()
    };
    fs_extra::dir::copy(path, tmpdir.path(), &copy_options)?;
    let pkgnames: HashSet<_> = srcinfo
        .pkgs
        .iter()
        .map(|pkg| pkg.pkgname.as_str())
        .collect();
    let depends = srcinfo_to_depends(srcinfo)
        .filter(|(_, dep)| !pkgnames.contains(dep.name())) // skip self dependencies
        .map(|(_, dep)| dep.to_string())
        .collect();
    let cmd = RunnerCommand {
        name: srcinfo.base.pkgbase.clone(),
        pkgbuild_dir: tmpdir.path().to_owned(),
        depends,
        quit: false,
    };
    if let Some(com) = runner_com {
        tracing::info!("Running: {:?}", cmd);
        bincode::serialize_into(&mut *com, &cmd)?;
        let result: BuildResult = bincode::deserialize_from(com)?;
        if !result.success {
            return Err(anyhow::anyhow!(
                "aur build failed: {}",
                result.error.unwrap_or_default()
            ));
        }
        let packages = std::process::Command::new("makepkg")
            .arg("--packagelist")
            .current_dir(tmpdir.path())
            .output()?;
        for line in String::from_utf8(packages.stdout)?.lines() {
            let dest = Path::new(&std::env::var("HOME").unwrap())
                .join(".local")
                .join("var")
                .join("repo");
            let pkg = Path::new(line);
            std::fs::copy(pkg, dest.join(pkg.file_name().unwrap()))?;
            std::process::Command::new("repo-add")
                .arg(dest.join("localrepo.db.tar.gz"))
                .arg(dest.join(pkg.file_name().unwrap()))
                .status()?
                .exit_ok()?;
        }
    } else {
        tracing::info!("Would have run: {:?}", cmd);
    }
    Ok(())
}

#[derive(clap::Subcommand)]
#[non_exhaustive]
enum Action {
    Update {
        /// Update all packages in local repo
        #[arg(short = 'a', long)]
        all: bool,
        /// Update only packages that are installed
        #[arg(short = 'i', long)]
        installed: bool,
        /// Refresh vcs sources
        #[arg(long)]
        vcs: bool,
        packages: Vec<String>,
    },
    /// Remove packages from localrepo if they are no longer in the AUR,
    /// or if they are available from the official repo
    CleanUp,
    #[doc(hidden)]
    #[clap(hide = true)]
    Runner,
}

#[derive(Parser)]
#[clap(version = "0.1", author = "")]
struct Opts {
    #[clap(subcommand)]
    action: Action,
    #[clap(short = 'n', long)]
    dry_run: bool,
}

fn localrepo_packages(alpm: &alpm::Alpm) -> Vec<alpm::Package<'_>> {
    alpm.syncdbs()
        .iter()
        .find(|db| db.name() == "localrepo")
        .unwrap()
        .pkgs()
        .iter()
        .filter_map(|pkg| {
            if pkg.name().ends_with("-debug") {
                // ignore debug symbol packages
                None
            } else {
                Some(pkg.to_owned())
            }
        })
        .collect()
}

#[derive(Debug)]
struct PackageInfo {
    name: String,
    pkgbase: String,
    version: alpm::Version,
}

async fn get_aur_info(
    mut packages: impl ExactSizeIterator<Item = &str>,
) -> Result<Vec<PackageInfo>, Error> {
    tracing::info!("Fetching AUR info for {} packages", packages.len());
    let base_url = "https://aur.archlinux.org/rpc/?v=5&type=info&";
    let mut url = base_url.to_owned();
    let mut futs = FuturesOrdered::new();
    loop {
        let package = packages.next();
        let append = if let Some(package) = package {
            format!("arg[]={}&", package)
        } else {
            String::new()
        };
        if url.len() + append.len() > 2000 || package.is_none() {
            futs.push_back(async move {
                tracing::debug!("Fetching {}", url);
                let aur_info: AurResult<AurPackage> = reqwest::get(&url).await?.json().await?;
                Ok::<_, Error>(aur_info)
            });
            url = base_url.to_owned();
            url.push_str(&append);
        } else {
            url.push_str(&append);
        }
        if package.is_none() {
            break;
        }
    }

    Ok(futs
        .try_collect::<Vec<_>>()
        .await?
        .into_iter()
        .flat_map(|res| res.results.into_iter())
        .map(|info| PackageInfo {
            name: info.name,
            pkgbase: info.package_base,
            version: alpm::Version::new(info.version),
        })
        .collect())
}

fn check_fd() -> Result<(), Error> {
    #[allow(dead_code)]
    #[repr(usize)]
    enum KcmpType {
        File = 0,
        Vm,
        Files,
        Fs,
        Sighand,
        Io,
        Sysvsem,
        EpollTfd,
        Types,
    }
    let pid = std::process::id();
    let stdin_vs_stdout = unsafe {
        syscall!(
            Sysno::kcmp,
            pid,
            pid,
            KcmpType::File,
            stdout().as_raw_fd(),
            stdin().as_raw_fd()
        )
    }? == 0;
    if !stdin_vs_stdout {
        return Err(anyhow::anyhow!(
            "stdout and stdin are not the same file descriptor"
        ));
    }

    let stdin_vs_stderr = unsafe {
        syscall!(
            Sysno::kcmp,
            pid,
            pid,
            KcmpType::File,
            stderr().as_raw_fd(),
            stdin().as_raw_fd()
        )
    }? == 0;
    if !stdin_vs_stderr {
        return Err(anyhow::anyhow!(
            "stderr and stdin are not the same file descriptor"
        ));
    }
    Ok(())
}

async fn run() -> Result<(), Error> {
    let opts = Opts::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::WARN.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();
    let pacman = pacmanconf::Config::from_file("/etc/pacman.conf")?;
    let alpm = alpm::Alpm::new("/", &pacman.db_path)?;
    for repo in pacman.repos {
        alpm.register_syncdb(repo.name.into_bytes(), alpm::SigLevel::NONE)?;
    }
    match opts.action {
        Action::CleanUp => {
            let db = Path::new(std::env::var("HOME")?.as_str())
                .join(".local")
                .join("var")
                .join("repo");
            let tmpdir = tempfile::tempdir()?;
            std::fs::create_dir(tmpdir.path().join("sync"))?;
            std::fs::copy(
                db.join("localrepo.db"),
                tmpdir.path().join("sync").join("localrepo.db"),
            )?;
            let alpm = alpm::Alpm::new("/", tmpdir.path().to_str().unwrap())?;
            alpm.register_syncdb("localrepo", SigLevel::NONE)?;
            let files: HashSet<_> = alpm
                .syncdbs()
                .iter()
                .flat_map(|db| db.pkgs().into_iter().map(|pkg| pkg.filename().to_owned()))
                .collect();
            tracing::info!("Removing files no longer in localrepo");
            for e in db.read_dir()? {
                let e = e?;
                if !e.file_name().to_str().unwrap().contains(".pkg.tar.") {
                    // not a package
                    continue;
                }
                if files.contains(e.file_name().to_str().unwrap()) {
                    // still in localrepo
                    continue;
                }
                if !opts.dry_run {
                    tracing::info!("Removing {file}", file = e.file_name().to_str().unwrap());
                    std::fs::remove_file(e.path())?;
                } else {
                    tracing::info!(
                        "Would have removed {file}",
                        file = e.file_name().to_str().unwrap()
                    );
                }
            }
            let packages = localrepo_packages(&alpm);
            for package in packages {
                if alpm.repo_of(package.name()).len() > 1 {
                    tracing::info!(
                        "Removing {package} from localrepo, because it is also available from {repo:?}",
                        package = package.name(),
                        repo = alpm
                            .repo_of(package.name())
                    );
                    let mut cmd = std::process::Command::new("repo-remove");
                    cmd.args(["localrepo.db.tar.gz", package.name()])
                        .current_dir(&db);
                    if opts.dry_run {
                        tracing::info!("Would have run: {:?}", cmd);
                    } else {
                        cmd.status()?;
                    }
                    for e in db.read_dir()? {
                        let e = e?;
                        if !e.file_name().to_str().unwrap().starts_with(package.name()) {
                            continue;
                        }
                        // Parse the file name to see if it's a file we want to remove
                        // <pkgname>-<pkgver>-<pkgrel>-<arch>.pkg.tar.<ext>
                        let stem = e
                            .file_name()
                            .to_str()
                            .unwrap()
                            .split_once(".pkg.tar.")
                            .unwrap()
                            .0
                            .to_owned();
                        let pkgname = &stem[..stem.rmatch_indices('-').nth(2).unwrap().0];
                        if pkgname != package.name() {
                            continue;
                        }
                        if opts.dry_run {
                            tracing::info!("Would have removed: {:?}", e.path());
                        } else {
                            std::fs::remove_file(e.path())?;
                        }
                    }
                }
            }
            return Ok(());
        }
        Action::Runner => runner_main()?,
        _ => (),
    }
    let multi_progress = indicatif::MultiProgress::new();
    let (resolve_conflicts_tx, mut resolve_conflicts_rx) =
        tokio::sync::mpsc::channel::<ResolveConflicts>(1);
    let multi_progress2 = multi_progress.clone();
    tokio::spawn(async move {
        while let Some(ResolveConflicts {
            path,
            reply,
            mut repo,
        }) = resolve_conflicts_rx.recv().await
        {
            multi_progress2.suspend(|| {
                prompt_resolve_conflict(path, &mut repo).unwrap();
                reply
                    .send(repo)
                    .unwrap_or_else(|_| panic!("Failed to send repo"));
            });
        }
    });
    let mut dep_graph = petgraph::graph::DiGraph::<DepNode, ()>::new();
    let mut package_base_map = HashMap::new();
    let mut index_map = HashMap::new();
    let (mut pending, update_vcs): (HashSet<String>, _) = match opts.action {
        Action::Update {
            all,
            packages,
            vcs,
            installed,
        } => {
            assert!(
                !installed || !all,
                "Can't use --installed and --all together"
            );
            let packages = if all {
                localrepo_packages(&alpm)
                    .into_iter()
                    .map(|pkg| pkg.name().to_owned())
                    .collect()
            } else {
                packages
                    .into_iter()
                    .flat_map(|p| {
                        let repo_pkg = alpm.repo_package(&p);
                        let localrepo_pkgs: Vec<_> = repo_pkg
                            .iter()
                            .filter(|(db, _)| *db == "localrepo")
                            .map(|(_, pkg)| pkg.name().to_owned())
                            .collect();
                        if localrepo_pkgs.is_empty() {
                            if let Some((repo, _)) = repo_pkg.first() {
                                println!("Package {p} already exists in {repo}");
                                Vec::new()
                            } else {
                                // Package not found in any repo, query aur
                                vec![p]
                            }
                        } else {
                            if localrepo_pkgs.len() > 1 || localrepo_pkgs[0] != p {
                                println!("Mapping {} to [{}]", p, localrepo_pkgs.join(", "));
                            }
                            localrepo_pkgs
                        }
                    })
                    .collect()
            };
            (packages, vcs)
        }
        _ => unreachable!(),
    };
    let mut all_srcinfos = Vec::new();
    let mut disambiguous = HashMap::<String, String>::new();
    // 1. Refresh all the pkgbuild repos
    while !pending.is_empty() {
        tracing::info!("Fetching information for {:?}", pending);
        let aur_info: Vec<(_, _)> =
            // TODO: before querying aur, search for package in local dbs.
            get_aur_info(pending.iter().map(|s| s.as_str()))
                .await?
                .into_iter()
                .map(|p| (p.pkgbase.clone(), p))
                .collect();
        let covered: HashSet<_> = aur_info.iter().map(|(_, p)| p.name.clone()).collect();
        let mut aur_info: HashMap<_, _> = aur_info.into_iter().collect();
        for p in pending.drain() {
            if covered.contains(&p) {
                continue;
            }
            let search_url = format!(
                "https://aur.archlinux.org/rpc/?v=5&type=search&type=provides&arg={}",
                p
            );
            tracing::info!("Searching for {} in aur", search_url);
            let mut search_result: AurResult<AurSearch> =
                reqwest::get(&search_url).await?.json().await?;
            if search_result.results.is_empty() {
                tracing::error!("No results found for {}", p);
                panic!();
            }
            let choice = multi_progress.suspend(|| {
                // Prompt the user to select one of the results.
                println!("Found multiple results for {}:", p);
                println!("(v: votes, p: popularity)");
                search_result.results.sort_by_key(|a| -a.popularity);
                for (i, result) in search_result.results.iter().enumerate() {
                    println!(
                        "\t{}) {} (v: {}, p: {})\n\t    {}",
                        i, result.name, result.num_votes, result.popularity, result.description
                    );
                }
                let mut rl = rustyline::DefaultEditor::new()?;
                rl.readline("Select one: ")?
                    .parse::<u32>()
                    .map_err(Error::from)
            })? as usize;
            assert!(choice < search_result.results.len());
            let old = disambiguous.insert(p, search_result.results[choice].name.clone());
            assert!(old.is_none());
            aur_info.insert(
                search_result.results[choice].package_base.clone(),
                PackageInfo {
                    name: search_result.results[choice].name.clone(),
                    pkgbase: search_result.results[choice].package_base.clone(),
                    version: alpm::Version::new(search_result.results[choice].version.clone()),
                },
            );
        }
        tracing::info!("{aur_info:?}");
        let o = futures::future::try_join_all(aur_info.into_values().map(|aur_info| {
            tracing::info!("Fetching srcinfo for {}", aur_info.pkgbase);
            let resolve_conflicts_tx = resolve_conflicts_tx.clone();
            let pb = multi_progress.add(indicatif::ProgressBar::new_spinner());
            #[allow(clippy::redundant_async_block)]
            Box::pin(async move {
                update_one_repo(
                    aur_info.name,
                    &aur_info.version,
                    update_vcs,
                    pb,
                    resolve_conflicts_tx,
                )
                .await
            })
        }))
        .await?;
        pending.clear();
        // Don't append to pending while we iterating over fetched srcinfo, 
        // because we might end up appending something we already fetched, but haven't
        // reached it in the iteration.
        for srcinfo in &o {
            for pkg in &srcinfo.pkgs {
                package_base_map.insert(pkg.pkgname.clone(), srcinfo.base.pkgbase.clone());
            }
        }
        for srcinfo in o {
            let node = dep_graph.add_node(DepNode {
                srcinfo: Some(srcinfo.clone()),
                name: srcinfo.base.pkgbase.clone(),
            });
            index_map.insert(srcinfo.base.pkgbase.clone(), node);
            for (_, dep) in srcinfo_to_depends(&srcinfo) {
                if package_base_map.contains_key(dep.name()) {
                    continue;
                }
                let repo_of_dep = alpm.repo_of(dep.name());
                if repo_of_dep.len() > 1 && repo_of_dep.contains(&"localrepo") {
                    tracing::info!("{} is in multiple repos: {:?}", dep, repo_of_dep);
                }
                if let Some(&repo) = repo_of_dep.iter().find(|&&r| r != "localrepo") {
                    tracing::info!("{} comes from {}", dep, repo);
                    // Create a dummy node for packages from official repos
                    let node = dep_graph.add_node(DepNode {
                        srcinfo: None,
                        name: dep.name().to_owned(),
                    });
                    package_base_map.insert(dep.name().to_owned(), dep.name().to_owned());
                    index_map.insert(dep.name().to_owned(), node);
                    continue;
                }
                if repo_of_dep.is_empty() {
                    // We don't know anything about this package, so add the dep as is.
                    pending.insert(dep.name().to_owned());
                } else {
                    // We have a package in localrepo for this dep, use its information
                    // Like sometimes multiple package can have the same provides, it
                    // being already in localrepo means the user has already made a choice.
                    let (_, pkg) = alpm.repo_package(dep.name()).into_iter().next().unwrap();
                    if dep.name() != pkg.name() {
                        let old = disambiguous.insert(dep.name().to_owned(), pkg.name().to_owned());
                        if let Some(old) = old {
                            assert_eq!(old, pkg.name());
                        }
                    }
                    if !package_base_map.contains_key(pkg.name()) {
                        pending.insert(pkg.name().to_owned());
                    }
                }
            }
            all_srcinfos.push(srcinfo);
        }
    }
    multi_progress.set_draw_target(indicatif::ProgressDrawTarget::hidden());
    for srcinfo in &all_srcinfos {
        let node = index_map[&srcinfo.base.pkgbase];
        for (pkgname, dep) in srcinfo_to_depends(srcinfo) {
            let dep = if disambiguous.contains_key(dep.name()) {
                alpm::Depend::new(disambiguous[dep.name()].clone())
            } else {
                dep
            };
            assert!(
                package_base_map.contains_key(dep.name()),
                "{:?} not in package_base_map",
                dep
            );
            let dep_base = &package_base_map[dep.name()];
            let dep_node = index_map[dep_base];
            if node != dep_node {
                dep_graph.add_edge(node, dep_node, ());
            } else if dep.name() == pkgname {
                // Report self-dependency. If dep != pkg.pkgname, then this means it's a
                // dependency from pkg to its pkgbase, which is fine.
                tracing::error!("{} depends on itself", pkgname);
            }
        }
    }
    //let print_graph = dep_graph.map(|_, n| &n.name, |_, ()| "");
    //let dot = petgraph::dot::Dot::with_config(&print_graph, &[petgraph::dot::Config::EdgeNoLabel]);
    //println!("{}", dot);

    let sorted = petgraph::algo::toposort(&dep_graph, None);
    let sorted = match sorted {
        Ok(sorted) => sorted,
        Err(e) => {
            let name = dep_graph[e.node_id()].name.clone();
            tracing::error!("Dependency cycle detected, build order is unreliable. {e:?} {name}");
            let scc = petgraph::algo::kosaraju_scc(&dep_graph);
            for component in &scc {
                if component.len() > 1 {
                    tracing::error!("Cycle detected: {:?}", component);
                }
            }
            scc.into_iter().flatten().collect()
        }
    };
    let mut gpgme = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
    let base = base_dir();
    let mut to_build = Vec::new();
    let mut missing_keys = HashMap::new();
    println!("Build order (in reverse):");
    for node_idx in sorted {
        let node = &dep_graph[node_idx];
        if let Some(srcinfo) = &node.srcinfo {
            let repo_ver = srcinfo
                .pkgs
                .iter()
                .filter_map(|p| alpm.repo_package(&p.pkgname).into_iter().next())
                .map(|(db, p)| {
                    assert_eq!(db, "localrepo");
                    p.version()
                })
                .next();
            let our_ver = format!("{}-{}", srcinfo.base.pkgver, srcinfo.base.pkgrel);
            let our_ver = alpm::Version::new(our_ver);
            let newer = repo_ver.map_or(true, |v| our_ver > v);
            if newer {
                println!(
                    "{}, {} => {}",
                    srcinfo.base.pkgbase,
                    repo_ver.map(ToString::to_string).unwrap_or("_".to_owned()),
                    our_ver
                );
                to_build.push(srcinfo.clone());
                for key in &srcinfo.base.valid_pgp_keys {
                    match gpgme.get_key(key) {
                        Err(e) if e.code() == gpgme::Error::EOF.code() => {
                            missing_keys.insert(key.as_str(), srcinfo.base.pkgbase.as_str());
                        }
                        e @ Err(_) => {
                            e?;
                        }
                        Ok(_) => (),
                    }
                }
            } else {
                tracing::info!(
                    "{} is up to date (version: {} <= {})",
                    srcinfo.base.pkgbase,
                    our_ver,
                    repo_ver.unwrap()
                );
            }
        }
    }

    if to_build.is_empty() {
        println!("Nothing to do");
        return Ok(());
    }

    let mut rl = rustyline::DefaultEditor::new()?;
    let readline = rl.readline("Proceed? [y/N] ")?;
    if readline != "Y" && readline != "y" {
        return Ok(());
    }

    // import missing keys
    gpgme.set_key_list_mode(gpgme::KeyListMode::EXTERN)?;
    for (key, pkg) in missing_keys {
        println!("Missing key {} for {}", key, pkg);
        let keys: Result<Vec<_>, _> = gpgme.find_keys(Some(key))?.collect();
        let keys = keys?;
        for key in &keys {
            println!("User IDs:");
            for user_id in key.user_ids() {
                println!("\t{}", user_id);
            }
            println!("Subkeys:");
            for subkey in key.subkeys() {
                println!(
                    "\t  {} bit {} key {}",
                    subkey.length(),
                    subkey.algorithm(),
                    subkey.fingerprint().unwrap()
                );
            }
        }
        let readline = rl.readline("Import? [y/N] ")?;
        if readline == "Y" || readline == "y" {
            gpgme.import_keys(&keys)?;
        } else {
            println!("Key rejected, cannot continue");
            return Ok(());
        }
    }

    let mut runner_com = if !opts.dry_run {
        // Start the runner
        check_fd()?;

        let (runner_tx, runner_rx) = std::os::unix::net::UnixStream::pair()?;
        let ownedfd: OwnedFd = runner_rx.into();
        std::process::Command::new(std::env::current_exe()?)
            .arg("runner")
            .stdout(ownedfd)
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let result: BuildResult = bincode::deserialize_from(&runner_tx)?;
        assert!(result.success);
        Some(runner_tx)
    } else {
        None
    };
    let total = to_build.len();
    for (i, srcinfo) in to_build.into_iter().rev().enumerate() {
        use crossterm::ExecutableCommand;
        stdout().execute(crossterm::terminal::SetTitle(format!(
            "building {} ({}/{})",
            srcinfo.base.pkgbase,
            i + 1,
            total
        )))?;
        build(
            base.join(&srcinfo.base.pkgbase),
            &srcinfo,
            runner_com.as_mut(),
        )?;
    }
    if let Some(runner_com) = runner_com {
        bincode::serialize_into(
            &runner_com,
            &RunnerCommand {
                name: String::new(),
                pkgbuild_dir: PathBuf::new(),
                depends: Vec::new(),
                quit: true,
            },
        )?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let fut = run();
    tokio::select! {
        res = fut => res,
        _ = tokio::signal::ctrl_c() => {
            println!("Ctrl-C pressed, exiting");
            Ok(())
        }
    }
}
