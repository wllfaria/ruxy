mod error;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::OnceLock;

use nix::ioctl_read_bad;
use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::pty::{ForkptyResult, forkpty};
use nix::unistd::Pid;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::Directive;

use crate::error::{Error, Result};

pub const SOCKET_PATH: &str = "/tmp/ruxy.sock";

#[cfg(debug_assertions)]
pub const LOG_DIR: &str = "/Users/wiru/.local/share/ruxy";
#[cfg(not(debug_assertions))]
pub const LOG_DIR: &str = "/var/log/ruxy";

pub const LOG_FILE: &str = "ruxy.log";

static LOG_GUARD: OnceLock<WorkerGuard> = OnceLock::new();

macro_rules! borrow_raw {
    ($fd:expr) => {
        ::std::os::fd::BorrowedFd::borrow_raw($fd)
    };
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Session {
    parent: OwnedFd,
    child: Pid,
    socket: UnixStream,
}

impl Session {
    fn new(socket: UnixStream, parent: OwnedFd, child: Pid) -> Self {
        Self {
            parent,
            child,
            socket,
        }
    }
}

pub fn init_logging<P: AsRef<Path>>(log_dir: P, log_file: P) -> Result<()> {
    std::fs::create_dir_all(log_dir.as_ref())?;

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.as_ref().join(log_file))?;

    let (non_blocking, _guard) = tracing_appender::non_blocking(file);

    LOG_GUARD
        .set(_guard)
        .map_err(|_| Error::Logging("failed to initialize logging service"))?;

    tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_writer(non_blocking)
        .init();

    Ok(())
}

pub fn daemonize<F>(f: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    match unsafe { nix::unistd::fork()? } {
        nix::unistd::ForkResult::Parent { .. } => return Ok(()),
        nix::unistd::ForkResult::Child => {}
    }

    nix::unistd::setsid()?;

    unsafe {
        use nix::sys::signal::{SigHandler, Signal, signal};
        let signals = [
            Signal::SIGHUP,
            Signal::SIGINT,
            Signal::SIGQUIT,
            Signal::SIGCHLD,
        ];
        for sig in signals {
            signal(sig, SigHandler::SigIgn)?;
        }
    }

    match unsafe { nix::unistd::fork()? } {
        nix::unistd::ForkResult::Parent { .. } => std::process::exit(0),
        nix::unistd::ForkResult::Child => {}
    }

    nix::sys::stat::umask(nix::sys::stat::Mode::empty());

    let max_fd = unsafe { nix::libc::sysconf(nix::libc::_SC_OPEN_MAX) };
    let max_fd = if max_fd == -1 { 1024 } else { max_fd as i32 };

    for fd in 3..=max_fd {
        nix::unistd::close(fd).ok();
    }

    if let Err(e) = f() {
        tracing::error!("Daemon main function returned error: {e:?}");
    };

    std::process::exit(0);
}

pub struct RuxyServer {
    listener: UnixListener,
    sessions: HashMap<i32, Session>,
}

impl RuxyServer {
    pub fn new() -> Result<Self> {
        std::fs::remove_file(SOCKET_PATH).ok();

        Ok(Self {
            listener: UnixListener::bind(SOCKET_PATH)?,
            sessions: HashMap::new(),
        })
    }

    pub fn run(&mut self) -> Result<()> {
        self.listener.set_nonblocking(true)?;

        loop {
            let listener_fd = unsafe { borrow_raw!(self.listener.as_raw_fd()) };
            let mut poll_fds: Vec<PollFd> = vec![PollFd::new(listener_fd, PollFlags::POLLIN)];

            for client in self.sessions.values() {
                let client_fd = unsafe { borrow_raw!(client.socket.as_raw_fd()) };
                poll_fds.push(PollFd::new(client_fd, PollFlags::POLLIN));
            }

            nix::poll::poll(&mut poll_fds, 30u16)?;

            // check if we got data from the client socket
            self.read_client_data(&poll_fds)?;

            // accept any new clients we may beed to
            if poll_fds[0].revents().unwrap().contains(PollFlags::POLLIN) {
                self.accept_new_clients()?;
            }

            self.read_session_processes()?;
            // check if clients processes got updates
            // if so we send then to their respective client
        }
    }

    fn accept_new_clients(&mut self) -> Result<()> {
        let Ok((stream, _addr)) = self.listener.accept() else { unreachable!() };
        stream.set_nonblocking(true)?;

        tracing::debug!("getting size");
        let size = get_term_size(std::io::stdin())?;
        tracing::debug!("got");
        let key = stream.as_raw_fd();
        let session = create_pty_session(size, stream)?;

        self.sessions.insert(key, session);

        Ok(())
    }

    fn read_client_data(&mut self, poll_fds: &[PollFd]) -> Result<()> {
        let total_clients = self.sessions.len();

        let mut clients_with_data: Vec<i32> = Vec::with_capacity(total_clients);
        let mut clients_to_remove: Vec<i32> = Vec::with_capacity(total_clients);

        for (idx, fd) in self.sessions.keys().enumerate() {
            // skip first fd as it's the socket listener
            let poll_idx = idx + 1;
            let events = poll_fds[poll_idx].revents().unwrap();

            if matches!(
                events,
                PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL
            ) {
                clients_to_remove.push(*fd);
            }

            if poll_fds[poll_idx]
                .revents()
                .unwrap()
                .contains(PollFlags::POLLIN)
            {
                clients_with_data.push(*fd);
            }
        }

        for fd in clients_with_data {
            let session = self.sessions.get_mut(&fd).unwrap();
            let mut buf = [0u8; 1024];

            match session.socket.read(&mut buf) {
                Err(_) | Ok(0) => _ = self.sessions.remove(&fd),
                Ok(bytes_read) => {
                    _ = nix::unistd::write(session.parent.as_fd(), &buf[..bytes_read])?;
                }
            }
        }

        Ok(())
    }

    pub fn read_session_processes(&mut self) -> Result<()> {
        for session in self.sessions.values_mut() {
            let parent_fd = session.parent.as_fd();
            let mut poll_fds = [PollFd::new(parent_fd, PollFlags::POLLIN)];

            nix::poll::poll(&mut poll_fds, 30u16)?;

            if poll_fds[0].revents().unwrap().contains(PollFlags::POLLIN) {
                let mut buf = [0u8; 4096];

                let bytes_read = nix::unistd::read(parent_fd, &mut buf)?;
                if bytes_read == 0 {
                    break;
                };

                session.socket.write_all(&buf[..bytes_read])?;
            }
        }

        Ok(())
    }
}

pub fn should_start_server() -> bool {
    // socket is reachable, so the server is already running
    if UnixStream::connect(SOCKET_PATH).is_ok() {
        return false;
    };

    // socket wasn't reachable, but the socket file exists, so we clean it up
    if std::path::Path::new(SOCKET_PATH).exists() {
        std::fs::remove_file(SOCKET_PATH).ok();
    };

    true
}

fn create_pty_session(size: nix::pty::Winsize, socket: UnixStream) -> Result<Session> {
    match unsafe { forkpty(&size, None)? } {
        ForkptyResult::Child => {
            // let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
            let shell = "/bin/zsh".to_string();
            let shell = std::ffi::CString::new(shell).unwrap();
            let args = [shell.clone()];
            nix::unistd::execvp(&shell, &args).expect("Failed to exec shell");
            unreachable!();
        }
        ForkptyResult::Parent { master, child } => Ok(Session::new(socket, master, child)),
    }
}

ioctl_read_bad!(get_win_size, nix::libc::TIOCGWINSZ, nix::pty::Winsize);

fn get_term_size<F: AsRawFd>(fd: F) -> Result<nix::pty::Winsize> {
    let mut ws: nix::pty::Winsize = unsafe { std::mem::zeroed() };
    unsafe { get_win_size(fd.as_raw_fd(), &mut ws) }.map_err(|_| Error::IoctlFailed)?;
    Ok(ws)
}
