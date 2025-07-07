FROM fedora:latest

ENV PATH "$PATH:/home/vscode/.cargo/bin"

# Create vscode user with sudo access
RUN groupadd --gid 1000 vscode \
    && useradd --uid 1000 --gid 1000 -m vscode \
    && echo "vscode ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Install development dependencies
RUN dnf install -y \
    sudo git cargo rust rust-src git-core openssl openssl-devel clippy rustfmt golang tpm2-tss-devel clevis clevis-luks cryptsetup cryptsetup-devel clang-devel sqlite sqlite-devel libpq libpq-devel \
    && dnf clean all

USER vscode

RUN cargo install --force diesel_cli --no-default-features --features sqlite