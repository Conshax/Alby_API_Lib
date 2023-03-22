use std::collections::HashMap;

use reqwest::header::HeaderMap;
use reqwest::{self, header};

use serde::{Deserialize, Serialize};

use thiserror::Error;

use sha2::{Digest, Sha256};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Missing Auth")]
    MissingAuth,

    #[error("Missing Refresh Token")]
    MissingRefreshToken,

    #[error("Invalid access token")]
    InvalidAccessToken,

    #[error("Request Error {0}")]
    RequestError(reqwest::Error),

    #[error("Parsing Error {0}")]
    ParsingError(String),

    #[error("Authorization Error")]
    AuthError,

    #[error("Alby Error")]
    AlbyError(String),
}

#[derive(Debug)]
struct Auth {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug)]
pub struct Client {
    pub client: reqwest::Client,
    pub access_token: String,
    pub refresh_token: Option<String>,
    auth: Option<Auth>,
}

impl Client {
    pub async fn from_refresh_token(
        old_refresh_token: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Self> {
        let auth = Auth {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
        };
        let client = reqwest::Client::new();
        let refresh_struct = get_new_refresh_token(&client, &auth, old_refresh_token).await?;

        let mut headers = HeaderMap::new();
        let mut auth_value =
            header::HeaderValue::from_str(&format!("Bearer {}", refresh_struct.access_token))
                .map_err(|_| Error::InvalidAccessToken)?;
        auth_value.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, auth_value);

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|_| Error::InvalidAccessToken)?;

        Ok(Self {
            client,
            access_token: refresh_struct.access_token,
            refresh_token: Some(refresh_struct.refresh_token),
            auth: Some(auth),
        })
    }

    pub fn from_access_token(access_token: String) -> Result<Self> {
        let mut headers = HeaderMap::new();
        let mut auth_value = header::HeaderValue::from_str(&format!("Bearer {}", access_token))
            .map_err(|_| Error::InvalidAccessToken)?;
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
            auth: None,
        })
    }

    pub async fn refresh_token(&mut self) -> Result<()> {
        let auth = self.auth.as_ref().ok_or(Error::MissingAuth)?;
        let refresh_token = self
            .refresh_token
            .as_ref()
            .ok_or(Error::MissingRefreshToken)?;

        let refresh_response = get_new_refresh_token(&self.client, auth, refresh_token).await?;

        self.access_token = refresh_response.access_token;
        self.refresh_token = Some(refresh_response.refresh_token);

        let headers = HeaderMap::from_iter(vec![(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {}", self.access_token))
                .map_err(|_| Error::InvalidAccessToken)?,
        )]);

        self.client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|_| Error::InvalidAccessToken)?;

        Ok(())
    }

    pub async fn get_value4value(&self) -> Result<Value4ValueResponse> {
        let resp = self
            .client
            .get("https://api.getalby.com/user/value4value")
            .send()
            .await
            .map_err(Error::RequestError)?;

        if resp.status() == 401 {
            return Err(Error::AuthError);
        }

        let resp = resp.bytes().await.map_err(|e| {
            Error::ParsingError(format!("Failed to convert alby reponse into bytes {}", e))
        })?;

        serde_json::from_slice(&resp)
            .map_err(|e| Error::ParsingError(format!("Failed to parse alby reponse {}", e)))
    }

    pub async fn create_invoice(
        &self,
        amount: usize,
        description: Option<String>,
    ) -> Result<CreateInvoiceResponse> {
        let description_hash = description.clone().map(|description| {
            let mut hasher = Sha256::new();
            hasher.update(description.as_bytes());
            hex::encode(hasher.finalize())
        });

        let request = CreateInvoiceRequest {
            amount,
            description,
            description_hash,
        };

        let json_request = serde_json::to_string(&request)
            .map_err(|e| Error::ParsingError(format!("Failed to parse request {}", e)))?;

        let resp = self
            .client
            .post("https://api.getalby.com/invoices")
            .body(json_request)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(Error::RequestError)?;

        if resp.status() == 401 {
            Err(Error::AuthError)
        } else if resp.status() == 200 {
            let resp = resp.bytes().await.map_err(|e| {
                Error::ParsingError(format!("Failed to convert alby reponse into bytes {}", e))
            })?;

            return serde_json::from_slice(&resp)
                .map_err(|e| Error::ParsingError(format!("Failed to parse alby reponse {}", e)));
        } else {
            return Err(Error::AlbyError(resp.text().await.map_err(|e| {
                Error::ParsingError(format!(
                    "Failed to convert alby error reponse into string {}",
                    e
                ))
            })?));
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Value4ValueResponse {
    pub keysend_pubkey: Option<String>,
    pub keysend_custom_key: Option<String>,
    pub keysend_custom_value: Option<String>,
    pub lightning_address: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub token_type: String,
    pub scope: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateInvoiceResponse {
    pub expires_at: Option<String>,
    pub payment_hash: Option<String>,
    pub payment_request: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateInvoiceRequest {
    pub amount: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description_hash: Option<String>,
}

async fn get_new_refresh_token(
    client: &reqwest::Client,
    auth: &Auth,
    refresh_token: &str,
) -> Result<RefreshTokenResponse> {
    let form: HashMap<&str, &str> = HashMap::from_iter(vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ]);

    let resp = client
        .post("https://api.getalby.com/oauth/token")
        .basic_auth(&auth.client_id, Some(&auth.client_secret))
        .form(&form)
        .header(header::CONTENT_TYPE, "multipart/form-data")
        .send()
        .await
        .map_err(Error::RequestError)?;

    if resp.status() == 401 {
        return Err(Error::AuthError);
    }
    if resp.status() != 200 {
        let error = resp
            .error_for_status()
            .map_err(Error::RequestError)?
            .text()
            .await
            .map_err(Error::RequestError)?;
        Err(Error::AlbyError(error))
    } else {
        let refresh_token_response = resp.bytes().await.map_err(|e| {
            Error::ParsingError(format!("Failed to convert alby reponse into bytes {}", e))
        })?;

        serde_json::from_slice(&refresh_token_response)
            .map_err(|e| Error::ParsingError(format!("Failed to parse alby reponse {}", e)))
    }
}
