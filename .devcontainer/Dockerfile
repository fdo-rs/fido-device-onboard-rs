FROM fedora:latest

ENV PATH "$PATH:/home/vscode/.cargo/bin"

RUN bash -c "$(curl -fsSL "https://raw.githubusercontent.com/microsoft/vscode-dev-containers/main/script-library/common-redhat.sh")" -- "true" "vscode" "1000" "1000" "true"

RUN dnf install -y \
    sudo git cargo rust rust-src git-core openssl openssl-devel clippy rustfmt golang tpm2-tss-devel clevis clevis-luks cryptsetup cryptsetup-devel clang-devel sqlite sqlite-devel libpq libpq-devel \
    && dnf clean all

USER vscode

RUN cargo install --force diesel_cli --no-default-features --features sqlite