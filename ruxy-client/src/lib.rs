use std::io::{Read, Write, stdin, stdout};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use crossterm::event::{Event, KeyCode, poll, read};
use crossterm::terminal;
use error::Result;
use nix::poll::{PollFd, PollFlags, PollTimeout};

mod error;

pub struct RuxyClient {
    stream: UnixStream,
}

impl RuxyClient {
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Result<Self> {
        let stream = UnixStream::connect(socket_path)?;
        stream.set_nonblocking(true)?;
        Ok(Self { stream })
    }

    pub fn run(&mut self) -> Result<()> {
        terminal::enable_raw_mode()?;

        // TODO:
        // So technically, all we do in a higher level here is:
        // 1. Poll for user input
        //   - If we have input, it is either a command or we send to the server
        // 2. Receive server data
        //   - if the server got any update for us, read it all and write to stdout
        // 3. repeat?

        loop {
            self.get_user_input()?;

            let ok = self.poll_server()?;

            if ok {
                break;
            }
        }

        terminal::disable_raw_mode()?;
        Ok(())
    }

    fn poll_server(&mut self) -> Result<bool> {
        let stream_fd = self.stream.as_fd();
        let mut poll_fds = [PollFd::new(stream_fd, PollFlags::POLLIN)];

        nix::poll::poll(&mut poll_fds, 30u16)?;

        if poll_fds[0].revents().unwrap().contains(PollFlags::POLLIN) {
            let mut buf = [0u8; 4096];
            let bytes_read = self.stream.read(&mut buf)?;
            let message = String::from_utf8_lossy(&buf[..bytes_read]);
            write!(stdout(), "{message}")?;
            stdout().flush()?;
        }

        Ok(false)
    }

    fn get_user_input(&mut self) -> Result<()> {
        let stdin = stdin();
        let stdin = stdin.as_fd();
        let mut poll_fds = [PollFd::new(stdin, PollFlags::POLLIN)];

        nix::poll::poll(&mut poll_fds, 30u16)?;

        if poll_fds[0].revents().unwrap().contains(PollFlags::POLLIN) {
            let mut buf = [0u8; 1024];
            let bytes_read = nix::unistd::read(stdin, &mut buf)?;
            self.stream.write_all(&buf[..bytes_read])?;
        }

        Ok(())
    }
}
