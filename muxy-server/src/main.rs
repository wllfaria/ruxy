use std::collections::HashMap;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};

use nix::ioctl_read_bad;
use nix::poll::{PollFd, PollFlags};
use nix::pty::{ForkptyResult, forkpty};
use nix::unistd::Pid;

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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ioctl failed")]
    IoctlFailed,
    #[error("forkpty failed: {0}")]
    ForkptyFailed(#[from] nix::errno::Errno),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

type Result<T, E = Error> = std::result::Result<T, E>;

const SOCKET_PATH: &str = "/tmp/muxy.sock";

pub struct MuxyServer {
    listener: UnixListener,
    sessions: HashMap<i32, Session>,
}

impl MuxyServer {
    pub fn new(socket_path: &str) -> Result<Self> {
        Ok(Self {
            listener: UnixListener::bind(socket_path)?,
            sessions: HashMap::new(),
        })
    }

    pub fn run(&mut self) -> Result<()> {
        self.listener.set_nonblocking(true)?;

        loop {
            self.accept_new_clients()?;
            self.read_client_data()?;
        }
    }

    fn accept_new_clients(&mut self) -> Result<()> {
        let listener_fd = self.listener.as_fd();
        let mut poll_fds: Vec<PollFd> = vec![PollFd::new(listener_fd, PollFlags::POLLIN)];

        for client in self.sessions.values() {
            poll_fds.push(PollFd::new(client.socket.as_fd(), PollFlags::POLLIN));
        }

        nix::poll::poll(&mut poll_fds, 1000u16)?;

        if poll_fds[0].revents().unwrap().contains(PollFlags::POLLIN) {
            let Ok((stream, _addr)) = self.listener.accept() else { unreachable!() };
            println!("accepted new client");
            stream.set_nonblocking(true)?;

            let size = get_term_size(std::io::stdin())?;
            let key = stream.as_raw_fd();
            let session = create_pty_session(size, stream)?;

            self.sessions.insert(key, session);
        }

        Ok(())
    }

    fn read_client_data(&mut self) -> Result<()> {
        let listener_fd = self.listener.as_fd();
        let mut poll_fds: Vec<PollFd> = vec![PollFd::new(listener_fd, PollFlags::POLLIN)];

        for session in self.sessions.values() {
            poll_fds.push(PollFd::new(session.socket.as_fd(), PollFlags::POLLIN));
        }

        nix::poll::poll(&mut poll_fds, 1000u16)?;

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

        drop(poll_fds);

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

pub fn main() -> Result<()> {
    std::fs::remove_file(SOCKET_PATH).ok();

    MuxyServer::new(SOCKET_PATH)?.run()?;

    unreachable!();
}

pub fn create_pty_session(size: nix::pty::Winsize, socket: UnixStream) -> Result<Session> {
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

pub fn get_term_size<F: AsRawFd>(fd: F) -> Result<nix::pty::Winsize> {
    let mut ws: nix::pty::Winsize = unsafe { std::mem::zeroed() };
    unsafe { get_win_size(fd.as_raw_fd(), &mut ws) }.map_err(|_| Error::IoctlFailed)?;
    Ok(ws)
}
