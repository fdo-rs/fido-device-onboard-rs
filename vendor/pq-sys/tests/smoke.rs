extern crate pq_sys;

#[test]
fn test_ssl_init()
{
    unsafe{pq_sys::PQinitSSL(1);}
}