mod error;

use std::collections::HashMap;
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};

use nix::ioctl_read_bad;
use nix::poll::{PollFd, PollFlags};
use nix::pty::{ForkptyResult, forkpty};
use nix::unistd::Pid;

use crate::error::{Error, Result};

const SOCKET_PATH: &str = "/tmp/ruxy.sock";

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

pub struct RuxyServer {
    listener: UnixListener,
    sessions: HashMap<i32, Session>,
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
        signal(Signal::SIGHUP, SigHandler::SigIgn)?;
        signal(Signal::SIGINT, SigHandler::SigIgn)?;
        signal(Signal::SIGQUIT, SigHandler::SigIgn)?;
        signal(Signal::SIGCHLD, SigHandler::SigIgn)?;
    }

    match unsafe { nix::unistd::fork()? } {
        nix::unistd::ForkResult::Parent { .. } => return Ok(()),
        nix::unistd::ForkResult::Child => {}
    }

    nix::unistd::chdir("/")?;

    nix::sys::stat::umask(nix::sys::stat::Mode::empty());

    let max_fd = unsafe { nix::libc::sysconf(nix::libc::_SC_OPEN_MAX) };
    let max_fd = if max_fd == -1 { 1024 } else { max_fd as i32 };

    for fd in 3..=max_fd {
        nix::unistd::close(fd).ok();
    }

    use std::os::fd::{AsFd, FromRawFd};

    use nix::unistd::dup2;

    let dev_null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    let fd = dev_null.as_fd();

    let mut stdin_fd = unsafe { OwnedFd::from_raw_fd(0) };
    let mut stdout_fd = unsafe { OwnedFd::from_raw_fd(1) };
    let mut stderr_fd = unsafe { OwnedFd::from_raw_fd(2) };

    dup2(fd, &mut stdin_fd)?;
    dup2(fd, &mut stdout_fd)?;
    dup2(fd, &mut stderr_fd)?;

    f()?;

    Ok(())
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

            nix::poll::poll(&mut poll_fds, 1000u16)?;

            self.read_client_data(&poll_fds)?;

            if poll_fds[0].revents().unwrap().contains(PollFlags::POLLIN) {
                self.accept_new_clients()?;
            }
        }
    }

    fn accept_new_clients(&mut self) -> Result<()> {
        let Ok((stream, _addr)) = self.listener.accept() else { unreachable!() };
        stream.set_nonblocking(true)?;

        let size = get_term_size(std::io::stdin())?;
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
                Ok(0) => {
                    println!("Client {fd} closed connection");
                    self.sessions.remove(&fd);
                }
                Ok(n) => {
                    println!("Received from client {fd}: {:?}", &buf[..n]);
                }
                Err(e) => {
                    eprintln!("Error reading from client {fd}: {e:?}");
                    self.sessions.remove(&fd);
                }
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
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
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
