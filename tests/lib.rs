use alby_api_lib::{Client, Error};
use tokio;

use dotenv_codegen::dotenv;

#[tokio::test]
async fn test_refresh_token() {
    let refresh_token = dotenv!("ALBY_REFRESH_TOKEN");
    let client_id = dotenv!("ALBY_CLIENT_ID");
    let client_secret = dotenv!("ALBY_CLIENT_SECRET");

    let old_refresh_token = refresh_token.to_owned();
    
    let client = Client::from_refresh_token(&refresh_token, &client_id, &client_secret).await;

    assert!(client.is_ok());
    let mut client = client.unwrap();
    
    assert!(client.refresh_token.is_some());
    let refresh_token = client.refresh_token.to_owned().unwrap();

    assert_ne!(refresh_token, old_refresh_token);

    let old_refresh_token = refresh_token.to_owned();

    let refresh_result = client.refresh_token().await;

    assert!(refresh_result.is_ok());
    assert!(client.refresh_token.is_some());
    assert_ne!(client.refresh_token.to_owned().unwrap(), old_refresh_token);
}

#[tokio::test]
async fn test_from_access_token() {
    let client = get_client_from_access_token();
    assert!(client.is_ok());
}

#[tokio::test]
async fn test_get_v4v() {
    let client = get_client_from_access_token().unwrap();

    let v4v = client.get_value4value().await;

    assert!(v4v.is_ok());
    let v4v = v4v.unwrap();

    assert_eq!(v4v.keysend_custom_key, dotenv!("ALBY_CUSTOM_KEY"));
    assert_eq!(v4v.keysend_custom_value, dotenv!("ALBY_CUSTOM_VALUE"));
    assert_eq!(v4v.keysend_pubkey, dotenv!("ALBY_PUBKEY"));
    assert!(v4v.lightning_address.is_some());
    assert_eq!(v4v.lightning_address.unwrap(), dotenv!("ALBY_LIGHTNING_ADDRESS"));
}

#[tokio::test]
async fn test_create_invoice() {
    let client = get_client_from_access_token().unwrap();

    let invoice = client.create_invoice(1000, None).await;

    assert!(invoice.is_ok());
    let invoice = invoice.unwrap();
    assert!(invoice.payment_request.is_some());
}

fn get_client_from_access_token() -> Result<Client, Error>{
    let access_token = dotenv!("ALBY_ACCESS_TOKEN");
    Client::from_access_token(access_token.to_owned())
}