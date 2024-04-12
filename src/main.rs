//!
use std::collections::HashMap;
use std::ops::Neg;
use std::os::fd::RawFd;
use std::path::Path;
use std::sync::Arc;
use std::thread::spawn;

use anyhow::Context;
use libseccomp::{ScmpFd, ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags, ScmpSyscall};
use nix::errno::Errno;
use nix::sched::{setns, unshare, CloneFlags};
use nix::unistd::{chdir, fork};
use rustix::process as rpr;
use rustix::process::pidfd_open;
use sendfd::RecvWithFd;

use subuidless::create_socket;
use subuidless::error::attach;
use subuidless::syscall::Syscall;

fn main() -> anyhow::Result<()> {
    let mut syscalls = HashMap::new();

    for syscall in inventory::iter::<&dyn Syscall> {
        syscalls.insert(syscall.get_syscall()?, *syscall);
    }
    let syscalls = Arc::new(syscalls);
    let listener = create_socket()?;
    loop {
        let (unix_stream, _socket_address) = listener.accept()?;

        let mut fd: [RawFd; 1] = [0; 1];
        let mut data = vec![0; 4096];
        let (size, _fd) = unix_stream.recv_with_fd(&mut data, &mut fd)?;

        data.truncate(size);
        data.shrink_to_fit();

        let json: serde_json::Value = serde_json::from_slice(&data)?;
        let pid = json
            .get("pid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|pid| i32::try_from(pid).ok())
            .and_then(rpr::Pid::from_raw)
            .context("Could not get Container pid")?;

        #[allow(unsafe_code)]
        // SAFETY:
        // Process is no multithreaded. Each Connection spawns a new child that gets moved into the "container"
        if unsafe { fork() }?.is_parent() {
            continue;
        }

        unshare(CloneFlags::CLONE_FS)?;
        let pid_fd = pidfd_open(pid, rpr::PidfdFlags::empty())?;
        setns(&pid_fd, CloneFlags::CLONE_NEWUSER)?;
        setns(&pid_fd, CloneFlags::CLONE_NEWNS)?;
        setns(&pid_fd, CloneFlags::CLONE_NEWPID)?;

        #[allow(unsafe_code)]
        // SAFETY:
        // To get the NSpid from seccomp the process needs to be in the same PID Namespace.
        // Therefore, we need to create a new Process, because pids remain the same.
        if unsafe { fork() }?.is_parent() {
            continue;
        }
        let mut runtime = true;

        loop {
            let mut notif_req = ScmpNotifReq::receive(fd[0])?;

            if runtime && i32::try_from(notif_req.pid)? < pid.as_raw_nonzero().get() {
                runtime = false;
                if i32::try_from(notif_req.pid)? == pid.as_raw_nonzero().get() {
                    notif_req.pid = 1;
                }
            }

            {
                let syscalls = Arc::clone(&syscalls);
                spawn(move || handle_scmp_req(fd[0], notif_req, &syscalls));
            }
        }
    }
}

fn handle_scmp_req(fd: ScmpFd, req: ScmpNotifReq, syscalls: &HashMap<ScmpSyscall, &dyn Syscall>) {
    let syscall = || {
        let syscall = syscalls
            .get(&req.data.syscall)
            .context("Syscall not supported")
            .map_err(attach(Errno::ENOSYS))?;

        chdir(Path::new(&format!("/proc/{}/cwd", req.pid)))?;
        syscall.execute(req, fd)?;

        Ok::<(), subuidless::Error>(())
    };

    #[allow(clippy::expect_used)]
    match syscall() {
        Ok(()) => ScmpNotifResp::new_val(req.id, 0, ScmpNotifRespFlags::empty()).respond(fd),
        Err(err) => {
            ScmpNotifResp::new_error(req.id, i32::from(err).neg(), ScmpNotifRespFlags::empty())
                .respond(fd)
        }
    }
    .expect("Could not respond to Seccomp");
}
