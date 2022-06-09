# Contributing to FIDO-Device-Onboard-RS

## For contributors

Thank you for considering contributing to this project and taking the time to read this document in advance!

This document describes the guidelines for contributing to this project.
If you want to suggest any changes to the process, please feel free to open a Pull Request against this file!

### Developing / building

In order to make a test build of this crate, when using Fedora, you can run:

``` bash
sudo yum install -y cargo rust rust-src git-core openssl-devel clippy rustfmt golang tpm2-tss-devel clevis clevis-luks cryptsetup cryptsetup-devel clang-devel
git clone https://github.com/fedora-iot/fido-device-onboard-rs.git
cd fido-device-onboard-rs
cargo build --release
```

After making changes, you can use `cargo test` to run the test suite, `cargo fmt` to ensure the code style is adhered to, and `cargo clippy` to check for some common lints against the code.

### Issues

For filing issues with the codebase, we use the GitHub issue tracker.
If you find an issue you'd like to work on, feel free to ask in the issue if someone is currently working on it.

You will see the `Jira` tag on many issues there, this is used to sync the issues to an internal tracker some contributors use for scheduling reasons.
The presence or absence of this tag does not mean that we will fix this, or that it has been claimed by anyone, it is purely used for some tooling.

### Specifications

This repository implements the FIDO Device Onboard specification (see the link in README.md for the exact version/link).
Anything that is in this codebase that isn't part of that specification, but that does interact with external systems, should have a specification in the [`docs/specs/`](https://github.com/fedora-iot/fido-device-onboard-rs/tree/main/docs/specs) directory, which gets rendered (from the `main`) branch to [here](https://fedora-iot.github.io/fido-device-onboard-rs/specs/).

### Submitting changes

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

## For maintainers

Here follow a few considerations and process descriptions for maintainers (people with permissions to merge PRs).

### Merging PRs

To merge pull requests, we use [https://mergify.io/](Mergify), which is a tool that will automatically rebase PRs, wait until CI passes, and then merge them.
You can check the status of a PR according to Mergify by opening the "Summary" check details inside the PR: it will automatically be merged when all of the checkboxes under any of the rulesets are checked.

To work well with Mergify, do not use the "Merge" button in the GitHub interface, but instead just mark the PR as Approved via the GitHub review UI.
That will automatically set the `#approved-reviews-by>=1` checkbox under all the rules, and it will then automatically go ahead and rebase the PR onto main, wait until CI passes again, and then merge it.
If there are multiple PRs that all have been approved, it will automatically create a "merge train" out of them, and rebase, wait for CI, and merge them all in order of the train.
This means that even if there are multiple PRs, you only have to mark them as approved, and the automation will get them merged in time.

#### Stability impact

The one exception to `#approved-reviews-by>=1` is on PRs that have the "possible stability impact" label set.
This label will automatically be set when certain files are changed that change a stable API (for example, the generated C header file for libfdo-data), or it could be set by the reviewer when they think this change is in fact stability impacting.
PRs with this label will *not* be automatically considered for merging with a single review: they will need *two* reviews, from different reviewers, in order to make sure that the stability impact is well understood, and acknowledged.

If, however, you are reviewing a PR that automatically got the "possibly stability impact" label because of changed files, but you can trivially see that the changes do not actually change a stable API (for example, it is just a documentation change that doesn't impact the actual API), you can set the "stability impact assessed: no impact" label.
When that label is set, a single review will get the PR merged.
