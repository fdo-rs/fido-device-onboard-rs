use openssl_kdf::{supports_args, KdfArgument};

#[allow(clippy::panic)]
fn main() {
    if std::env::var("CARGO_FEATURE_USE_NONINTEROPERABLE_KDF").is_err() {
        let test_args = &[
            &KdfArgument::Salt(&[]),
            &KdfArgument::KbInfo(&[]),
            &KdfArgument::Key(&[]),
            &KdfArgument::UseL(false),
            &KdfArgument::R(8),
        ];

        if !supports_args(test_args) {
            panic!(
                "\n\
				Current KDF implementation does not support the interoperable parameters.\n\
				If you still want to build, you can enable the non-interoperable KDF, but be aware that \
				that implementation does not interoperate with FDO-spec-compliant implementations.\n\
				"
            );
        }
    }
}
