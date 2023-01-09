use reqwest::{self, header};
use reqwest::header::HeaderMap;

use serde_derive::{Deserialize, Serialize};

use thiserror::Error;

use serde_json;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid access token")]
    InvalidAccessToken,

    #[error("Request Error {0}")]
    RequestError(reqwest::Error),

    #[error("Parsing Error {msg:?}")]
    ParsingError { msg: String },
}
pub struct Client {
    pub client: reqwest::Client,
    pub access_token: String,
    pub refresh_token: Option<String>,
}


impl Client {
    pub fn from_access_token(access_token: String) -> Result<Self, Error> {
        let mut headers = HeaderMap::new();
        let mut auth_value = header::HeaderValue::from_str(&format!("Bearer {}", access_token)).map_err(|_| Error::InvalidAccessToken)?;
        auth_value.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, auth_value);

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|_| Error::InvalidAccessToken)?;
        
        Ok(Self {
            client,
            access_token,
            refresh_token: None,
        })
    }

    pub async fn get_value4value(&self) -> Result<Value4ValueResponse, Error> {
        let resp = self.client.get("https://api.getalby.com/user/value4value")
            .send()
            .await
            .map_err(|e| Error::RequestError(e))?;

        let resp = resp.bytes()
        .await
        .map_err(|e| Error::ParsingError { msg: format!("Failed to convert alby reponse into bytes {}", e.to_string()) })?;

        return serde_json::from_slice(&resp)
            .map_err(|e| Error::ParsingError { msg: format!("Failed to parse alby reponse {}", e.to_string()) });
    }
}

#[derive(Serialize, Deserialize)]
pub struct Value4ValueResponse {
    pub keysend_pubkey: String,
    pub keysend_custom_key: String,
    pub keysend_custom_value: String,
    pub lightning_address: Option<String>,
}