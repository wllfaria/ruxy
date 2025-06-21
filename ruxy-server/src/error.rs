pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ioctl failed")]
    IoctlFailed,
    #[error("forkpty failed: {0}")]
    ForkptyFailed(#[from] nix::errno::Errno),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Logging(&'static str),
}
