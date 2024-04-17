# OCI Seccomp Receiver for running Rootless Containers without `/etc/subuid` and `/etc/subgid`

`subuidless` is an implementaion of OCI Seccomp Receiver for running Rootless Containers without `/etc/subuid` and `/etc/subgid`.

`subuidlesss` emulates ID-related system calls using Seccomp User Notification and XAttrs.

Unlike similar projects such as [runROOTLESS (PRoot)](https://github.com/rootless-containers/runrootless) and [remainroot](https://github.com/cyphar/remainroot), `subuidless` can minimize the overhead of system call hooking, as `subuidless` does not use ptrace.

## Status

Early POC. Do not use.

## Why do we need subuidless?
* It is hard to configure `/etc/subuid` and `/etc/subgid` in LDAP environments
* Some container images may require strange UIDs/GIDs that are out of the typical `/etc/subuid` and `/etc/subgid` configuration. The typical configuration only allows 65,536 IDs to be available in the container.

## Goals and non-goals
Goals:
* Simplicity
* Minimal overhead

Non-goals:
* Provide security boundry across emulated IDs

## Requirements
* Rust Toolchain
* libseccomp

> Note: There is a devbox.json File for easier setup

## Usage

Terminal 1:
```console
$ cargo run --bin subuidless
Listening on $XDG_RUNTIME_DIR/subuidless.sock
...
```

Terminal 2:
```console
$ docker run -it --security-opt seccomp=seccomp.json alpine:latest
/ # touch foo
/ # chown 42:42 foo
/ # ls -ln foo
-rw-r--r--    1 42       42               0 Apr 17 06:19 foo
```

The UID ang GID are recorded to [the `user.rootlesscontainers` xattr](https://github.com/rootless-containers/proto) of the target file. 

## Hooked system calls
- [ ] `fchown`
- [X] `fchownat`
- [ ] `lchown`

- [X] `fstatat`
- ...

TODO:
```
https://github.com/rootless-containers/PRoot/blob/081bb63955eb4378e53cf4d0eb0ed0d3222bf66e/src/extension/fake_id0/fake_id0.c#L141-L205
https://github.com/cyphar/remainroot/blob/master/src/ptrace/generic-shims.c
```
