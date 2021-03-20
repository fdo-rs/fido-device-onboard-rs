use warp::Filter;

use std::sync::{Arc, Mutex};

mod handlers {
    use fdo_data_formats::constants::ErrorCode;
    use fdo_data_formats::messages;

    use fdo_http_wrapper::server::{set_encryption_keys, Error};
    use fdo_http_wrapper::EncryptionKeys;

    use fdo_http_wrapper::server::{SessionStore, SessionWithStore};

    pub(super) async fn appstart<ST: SessionStore>(
        user_data: super::MfgUDT,
        mut ses_with_store: SessionWithStore<ST>,
        msg: messages::di::AppStart,
    ) -> Result<(messages::di::SetCredentials, SessionWithStore<ST>), warp::Rejection> {
        let mut session = ses_with_store.session;

        println!("DI Appstart: {:?}", msg);
        println!("Session: {:?}", session);
        println!("user_data: {:?}", user_data);

        {
            let mut ud = user_data.lock().unwrap();
            ud.counter += 1;
        }

        let newval = match session.get::<u8>("ctr") {
            Some(4) => return Err(Error::new(ErrorCode::InvalidJWT, 0, "Called 4 times").into()),
            Some(n) => n + 1,
            None => 1,
        };
        session.insert("ctr", newval).unwrap();

        if newval == 2 {
            set_encryption_keys::<messages::di::AppStart>(
                &mut session,
                EncryptionKeys::AEAD(vec![1, 2, 3, 4]),
            )?;
        }

        println!("Counter is now set with val {}", newval);

        ses_with_store.session = session;

        println!("Returning");

        Ok((messages::di::SetCredentials::new(42), ses_with_store))
    }
}

#[derive(Debug)]
struct MfgStorage {
    counter: u8,
}

type MfgUDT = Arc<Mutex<MfgStorage>>;

#[tokio::main]
async fn main() {
    let user_data = Arc::new(Mutex::new(MfgStorage { counter: 0 }));

    let hello = warp::get().map(|| "Hello from the MFG Station");

    let ses_store = fdo_http_wrapper::server::MemoryStore::new();

    let routes = warp::any()
        .and(hello)
        .or(fdo_http_wrapper::server::fdo_request_filter(
            user_data.clone(),
            ses_store.clone(),
            handlers::appstart,
        ));

    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
}
