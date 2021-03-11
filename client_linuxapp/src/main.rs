use fdo_data_formats::messages;

use fdo_http_wrapper::client::RequestResult;

#[tokio::main]
async fn main() {
    let mut di_client = fdo_http_wrapper::client::ServiceClient::new(
        "http://localhost:8080/",
    );

    let appstart = messages::DIAppStart::new("testclient");
    let response: RequestResult<messages::DIAppStart> = di_client.send_request(appstart).await;

    println!("CLient: {:?}", di_client);
    println!("Response: {:?}", response);
}
