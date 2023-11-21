pub mod tls_config {
    use crate::ManufacturingServiceUD;
    use openssl::ssl::{SslContext, SslFiletype, SslMethod};
    use std::path::Path;
    use std::sync::Arc;
    pub type Acceptor = openssl::ssl::SslContext;

    fn tls_acceptor_impl<P: AsRef<Path>>(cert_file: P, key_file: P) -> Acceptor {
        let mut builder = SslContext::builder(SslMethod::tls_server()).unwrap();
        builder
            .set_certificate_file(cert_file, SslFiletype::PEM)
            .unwrap();
        builder
            .set_private_key_file(key_file, SslFiletype::PEM)
            .unwrap();
        builder.build()
    }

    pub fn tls_acceptor(user_data: Arc<ManufacturingServiceUD>) -> Acceptor {
        let cert_file = &user_data.manufacturing_server_https_cert;
        let key_file = &user_data.manufacturing_server_https_key;
        tls_acceptor_impl(cert_file, key_file)
    }
}

pub use tls_config::tls_acceptor;
pub use tls_config::Acceptor;
