use std::collections::HashMap;

use chrono::FixedOffset;
use reqwest::header::HeaderMap;
use reqwest::{self, header};

use serde::{Deserialize, Serialize};

use thiserror::Error;

use rust_v4v::boostagram::Boostagram;
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

    pub async fn get_me(&self) -> Result<MeResponse> {
        let resp = self
            .client
            .get("https://api.getalby.com/user/me")
            .send()
            .await
            .map_err(Error::RequestError)?;

        if resp.status() == 401 {
            return Err(Error::AuthError);
        }

        resp.json()
            .await
            .map_err(|e| Error::ParsingError(format!("Failed to parse alby reponse {}", e)))
    }

    pub async fn get_summary(&self) -> Result<SummaryResponse> {
        let resp = self
            .client
            .get("https://api.getalby.com/user/summary")
            .send()
            .await
            .map_err(Error::RequestError)?;

        if resp.status() == 401 {
            return Err(Error::AuthError);
        }

        resp.json()
            .await
            .map_err(|e| Error::ParsingError(format!("Failed to parse alby reponse {}", e)))
    }

    pub async fn get_invoices(
        &self,
        created_at_gt: Option<chrono::DateTime<FixedOffset>>,
        created_at_lt: Option<chrono::DateTime<FixedOffset>>,
        items: Option<u8>, //max 100
        page: Option<usize>,
    ) -> Result<Vec<InvoiceResponse>> {
        if items > Some(100) {
            return Err(Error::AlbyError(
                "items can not be greater than 100(Alby api has max 100)".to_string(),
            ));
        }

        let mut req = self.client.get("https://api.getalby.com/invoices/incoming");

        if let Some(created_at_gt) = created_at_gt {
            req = req.query(&("created_at_gt", created_at_gt.timestamp()));
        }
        if let Some(created_at_lt) = created_at_lt {
            req = req.query(&("created_at_lt", created_at_lt.timestamp()));
        }
        if let Some(items) = items {
            req = req.query(&("items", items));
        }
        if let Some(page) = page {
            req = req.query(&("page", page));
        }

        let resp = req.send().await.map_err(Error::RequestError)?;

        if resp.status() == 401 {
            return Err(Error::AuthError);
        }

        resp.json()
            .await
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

    pub async fn post_webhook(&self, request: PostWebhookRequest) -> Result<PostWebhookResponse> {
        self.client
            .post("https://api.getalby.com/webhook_endpoints")
            .json(&request)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(Error::RequestError)?
            .json()
            .await
            .map_err(Error::RequestError)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct PostWebhookResponse {
    pub url: String,
    pub description: String,
    pub filter_types: Vec<InvoiceFilterTypes>,
    pub created_at: String,
    pub id: String,
    pub endpoint_secret: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostWebhookRequest {
    pub description: String,
    pub url: String,
    pub filter_types: Vec<InvoiceFilterTypes>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InvoiceFilterTypes {
    #[serde(rename = "invoice.incoming.settled")]
    IncomingSettled,
    #[serde(rename = "invoice.outgoing.settled")]
    OutgoingSettled,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct InvoiceResponse {
    pub amount: u64,
    pub boostagram: Option<Boostagram>,
    pub comment: Option<String>,
    #[serde(rename = "created_at")]
    pub created_at: String,
    #[serde(rename = "creation_date")]
    pub creation_date: u64,
    pub currency: String,
    #[serde(rename = "custom_records")]
    pub custom_records: CustomRecords,
    #[serde(rename = "description_hash")]
    pub description_hash: Option<String>,
    #[serde(rename = "expires_at")]
    pub expires_at: String,
    pub expiry: i64,
    #[serde(rename = "fiat_currency")]
    pub fiat_currency: String,
    #[serde(rename = "fiat_in_cents")]
    pub fiat_in_cents: u64,
    pub identifier: String,
    #[serde(rename = "keysend_message")]
    pub keysend_message: Option<String>,
    pub memo: String,
    #[serde(rename = "payer_name")]
    pub payer_name: String,
    #[serde(rename = "payment_hash")]
    pub payment_hash: String,
    #[serde(rename = "payment_request")]
    pub payment_request: String,
    #[serde(rename = "r_hash_str")]
    pub r_hash_str: String,
    pub settled: bool,
    #[serde(rename = "settled_at")]
    pub settled_at: String,
    pub state: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub value: u64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomRecords {
    #[serde(rename = "696969")]
    pub n696969: String,
    #[serde(rename = "7629169")]
    pub n7629169: Option<String>,
    #[serde(rename = "7629171")]
    pub n7629171: Option<String>,
    #[serde(rename = "5482373484")]
    pub n5482373484: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Value4ValueResponse {
    pub keysend_pubkey: Option<String>,
    pub keysend_custom_key: Option<String>,
    pub keysend_custom_value: Option<String>,
    pub lightning_address: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub token_type: String,
    pub scope: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct CreateInvoiceResponse {
    pub expires_at: Option<String>,
    pub payment_hash: Option<String>,
    pub payment_request: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct MeResponse {
    pub identifier: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub avatar: Option<String>,
    pub keysend_custom_key: Option<String>,
    pub keysend_custom_value: Option<String>,
    pub keysend_pubkey: Option<String>,
    pub lightning_address: Option<String>,
    pub nostr_pubkey: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct CreateInvoiceRequest {
    pub amount: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description_hash: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryResponse {
    pub balance: u64,
    #[serde(rename = "boostagrams_count")]
    pub boostagrams_count: usize,
    pub currency: String,
    #[serde(rename = "invoices_count")]
    pub invoices_count: usize,
    #[serde(rename = "last_invoice_at")]
    pub last_invoice_at: String,
    #[serde(rename = "total_received")]
    pub total_received: usize,
    #[serde(rename = "total_sent")]
    pub total_sent: usize,
    #[serde(rename = "transactions_count")]
    pub transactions_count: usize,
    pub unit: String,
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
        resp.json().await.map_err(|e| {
            Error::ParsingError(format!("Failed to convert alby reponse into bytes {}", e))
        })
    }
}
