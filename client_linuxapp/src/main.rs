use fdo_data_formats::messages;
use fdo_data_formats::types::CborSimpleType;

use fdo_http_wrapper::client::RequestResult;
use fdo_http_wrapper::EncryptionKeys;

#[tokio::main]
async fn main() {
    let mut di_client = fdo_http_wrapper::client::ServiceClient::new("http://localhost:8080/");

    println!("CLient: {:?}", di_client);

    let mut i: u8 = 0;
    while i < 6 {
        println!("Performing request nr {}", i);
        let appstart = messages::di::AppStart::new(CborSimpleType::Text("testing".to_string()));
        let response: RequestResult<messages::di::SetCredentials> = di_client
            .send_request(
                appstart,
                if i == 1 {
                    Some(EncryptionKeys::AEAD(vec![1, 2, 3, 4]))
                } else {
                    None
                },
            )
            .await;

        println!("Response: {:?}", response);

        i += 1
    }
}
