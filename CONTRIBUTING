# Contributing to Subuidless

Thanks for your interest in contributing to Subuidless!

All activity in Subuidless forums is subject to our [Code of Conduct](CODE_OF_CONDUCT.md). Additionally.

## Contribution ideas

If you're looking for new Syscalls to implement check out:

https://github.com/rootless-containers/PRoot/blob/081bb63955eb4378e53cf4d0eb0ed0d3222bf66e/src/extension/fake_id0/fake_id0.c#L141-L205
https://github.com/cyphar/remainroot/blob/master/src/ptrace/generic-shims.c

## How to add a new syscall
All syscalls reside in the `src/syscall` directory.
An easy example to get started is the `fstatat` syscall.

Everything from parsing and reading the remote memory to registering the syscall is handled by the `syscall!` macro.
That does not mean, that it isn't possible to create a possible attack surface, you still have to be careful with you implementation!

## Proposing changes

The best way to propose a change is to [start a discussion on our GitHub repository](https://github.com/Srylax/subuidless/discussions).

First, write a short **problem statement**, which _clearly_ and _briefly_ describes the problem you want to solve independently from any specific solution. It doesn't need to be long or formal, but it's difficult to consider a solution in absence of a clear understanding of the problem.

Next, write a short **solution proposal**. How can the problem (or set of problems) you have stated above be addressed? What are the pros and cons of your approach? Again, keep it brief and informal. This isn't a specification, but rather a starting point for a conversation.

By effectively engaging with the Subuidless team and community early in your process, we're better positioned to give you feedback and understand your pull request once you open it. If the first thing we see from you is a big changeset, we're much less likely to respond to it in a timely manner.

## Tips to improve the chances of your PR getting reviewed and merged

- Discuss your plans ahead of time with the team
- Small, focused, incremental pull requests are much easier to review
- Spend time explaining your changes in the pull request body
- Add test coverage and documentation
- Low effort PRs, such as those that just re-arrange syntax, won't be merged without a compelling justification

## Setup
If you are on a Nix based system or have the Nix package manager:
There is a `devbox.json` File which downloads all necessary packages.

Non Nix:
The only compile time requirement is `libseccomp-dev`. Consult your distribution specific documentation on how to download packages.
