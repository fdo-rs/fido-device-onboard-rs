# Contributing to FIDO-Device-Onboard-RS

Thank you for considering contributing to this project and taking the time to read this document in advance!

This document describes the guidelines for contributing to this project.
If you want to suggest any changes to the process, please feel free to open a Pull Request against this file!

## Developing / building

In order to make a test build of this crate, when using Fedora, you can run:

``` bash
sudo yum install -y cargo git-core openssl-devel
git clone https://github.com/fedora-iot/fido-device-onboard-rs.git
cd fido-device-onboard-rs
cargo build --release
```

After making changes, you can use `cargo test` to run the test suite, `cargo fmt` to ensure the code style is adhered to, and `cargo clippy` to check for some common lints against the code.

## Issues

For filing issues with the codebase, we use the GitHub issue tracker.
If you find an issue you'd like to work on, feel free to ask in the issue if someone is currently working on it.

You will see the `Jira` tag on many issues there, this is used to sync the issues to an internal tracker some contributors use for scheduling reasons.
The precense or absense of this tag does not mean that we will fix this, or that it has been claimed by anyone, it is purely used for some tooling.

## Specifications

This repository implements the FIDO Device Onboard specification (see the link in README.md for the exact version/link).
Anything that is in this codebase that isn't part of that specification, but that does interact with external systems, should have a specification in the [`docs/specs/`](https://github.com/fedora-iot/fido-device-onboard-rs/tree/main/docs/specs) directory, which gets rendered (from the `main`) branch to [here](https://fedora-iot.github.io/fido-device-onboard-rs/specs/).

## Submitting changes

In this project, we use the GitHub [Pull Request](https://docs.github.com/en/pull-requests) process for changes.

Please do try to make sure your commit messages are clear and describe what your patch does.
Please try to follow the [Conventional Commits (v1.0.0)](https://www.conventionalcommits.org/en/v1.0.0/) scheme to format your commit message.
This gets checked by the `commitlint` CI task, but you can also check your own commit message via the [commitlint website](https://commitlint.io/).
If you are having difficulties with this, feel free to still submit your change, and someone will try to help you along!

Before patches can land in the main repository, they will need to pass the test suite, not violate clippy lints, and conform to the code style.
These things are all tested by CI when you submit your Pull Request, and you can test them yourself via the commands in "Developing/building".

After your patch has been approved by a maintainer, it will be scheduled for merging.
It will first be rebased, to make sure that it still passes CI when, and then automatically merged.
This may take some time, so please don't worry!
(But if it does take longer than +- 30 minutes, and there are no updates visible in the user interface, please feel free to ping the contributor so they can check the automation.)
