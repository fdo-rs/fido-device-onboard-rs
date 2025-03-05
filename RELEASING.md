Releasing a new version
=======================

We will use the `v0.5.3` release (#738) as an example of how to release a new
FDO version:

* Fork the repo and create a new branch for the new release:

    ```bash
    gh repo fork fdo-rs/fido-device-onboard-rs --clone --remote
    git pull upstream main
    git checkout -b prepare-v0.5.3
    ```

* Update the `fido-device-onboard.spec` file and set the new version: `Version: 0.5.3`
* Update the `version` within the `[[package]]` section in all the `Cargo.toml` files.
* Update the `[[dependencies]]` in all the `Cargo.toml` files to use the latest
FDO versions.
* Update the `libfdo-data/fdo_data.h` file to reflect the correct version:

    ```c
    #define FDO_DATA_MAJOR 0
    #define FDO_DATA_MINOR 5
    #define FDO_DATA_PATCH 3
    ```

* Update `Cargo.lock` file:

    ```bash
    cargo update --offline --workspace
    ```

* Commit all the changes and create a PR (see #738 with all the changes described
above):

    ```bash
    git add fido-device-onboard.spec Cargo.toml Cargo.lock */Cargo.toml libfdo-data/fdo_data.h
    git commit -s -m "chore: bump for 0.5.3 release" -m "Prepare for the 0.5.3 release."
    gh pr create
    ```

* Once all the tests pass and the PR is merged, tag and sign the release:

    ```bash
    git tag -a -s v0.5.3
    git push upstream v0.5.3
    ```

* Using the webui, open the [Releases](https://github.com/fdo-rs/fido-device-onboard-rs/releases)
page and click the "Draft a new release" button in the middle of the page. From
there you can choose the `v0.5.3` tag you created in the previous step.
  * Use the version as the "Release title" and keep the format i.e. "v0.5.3".
  * In the description add in any release notes. When satisfied, click the
  "Save draft" or "Publish release" button at the bottom of the page.
