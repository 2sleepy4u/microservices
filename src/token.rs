use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey, errors::Error};
use serde::{Serialize, Deserialize};

use chrono::prelude::*;
use sqlx::MySqlPool;
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Sha512, Digest};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub email: String,
    pub password: String
}

#[derive(Debug, Clone)]
pub enum CredentialsError {
    AlreadyExists
}

impl Credentials {
    pub fn new(email: String, password: String) -> Self {
        Self { email, password }
    }

    pub async fn register(&self, db: &MySqlPool) -> Result<(), CredentialsError> {
        let result = self.get_user(db).await;

        match result {
            Ok(res) => if res.is_some() { return Err(CredentialsError::AlreadyExists) },
            Err(e) => panic!("Unknown error! {}", e)
        }
        

        let salt = generate_salt();
        let password_digest = self.get_password_digest(&salt);

        sqlx::query!(
            "INSERT INTO Users(email, password_digest, salt) VALUES (?, ?, ?)", 
            &self.email, &password_digest, &salt
            )
            .execute(db)
            .await
            .unwrap();

        Ok(())
    }

    pub fn get_password_digest(&self, salt: &str) -> String {
        let password_with_salt = format!("{}{}", self.password, salt);

        let mut hasher = Sha512::new();
        hasher.update(password_with_salt.as_bytes());
        let digest = hasher.finalize();
        let password_digest = format!("{:X}", digest);

        password_digest
    }

    pub async fn get_user(&self, db: &MySqlPool) -> Result<Option<Credentials>, sqlx::Error> {
        sqlx::query_as!(
            Credentials,
            "SELECT email, password_digest as password FROM Users WHERE email = ?", 
            &self.email
            )
            .fetch_optional(db)
            .await
    }
}

fn generate_salt() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(9)
        .map(char::from)
        .collect()
}

pub struct TokenGenerator {
    pub_key: DecodingKey,
    priv_key: EncodingKey
}

impl TokenGenerator {
    pub fn new(pub_key: &[u8], priv_key: &[u8]) -> Result<Self, Error> {
        let priv_key = EncodingKey::from_rsa_pem(priv_key)?;
        let pub_key = DecodingKey::from_rsa_pem(pub_key)?;
        Ok(Self { priv_key, pub_key })
    }
    pub fn token(&self, sub: String, duration: u32) -> Result<String, Error> {
        let utc: DateTime<Utc> = Utc::now(); 
        let hours = utc.hour() + duration;
        let exp = utc.with_hour(hours)
            .expect("Error setting exp timestamp")
            .timestamp() as usize;

        let payload = Payload { sub, exp };
        let token = encode(&Header::new(Algorithm::RS256), &payload, &self.priv_key)?;
        Ok(token)
    }

    pub fn verify(&self, token: &str) -> Result<Payload, Error> {
        let token = decode::<Payload>(&token, &self.pub_key, &Validation::new(Algorithm::RS256))?;
        Ok(token.claims)
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub struct Payload {
    //the user
    sub: String,
    //expiration
    exp: usize,
    //from what auth service
    //iss: String, 
    //for what service
    //aud: String 
}
