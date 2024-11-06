use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey, errors::Error};
use serde::{Serialize, Deserialize};

use chrono::prelude::*;
use sqlx::MySqlPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub email: String,
    pub password: String
}

pub enum CredentialsError {
    AlreadyExists
}

impl Credentials {
    pub fn new(email: String, password: String) -> Self {
        Self { email ,password }
    }

    pub async fn register(&self, db: MySqlPool) -> Result<(), CredentialsError> {
        let result = sqlx::query!("select exists(select * from Users where email = ?) as found", &self.email)
            .fetch_one(&db)
            .await;

        match result {
            Err(e) => panic!("Unknown error! {}", e),
            Ok(res) => if res.found == 1 { return Err(CredentialsError::AlreadyExists) }
        }


        sqlx::query!("INSERT INTO Users(email, password_digest, salt) VALUES (?, ?, ?)", &self.email, &self.password, "")
            .execute(&db)
            .await
            .unwrap();

        Ok(())
    }

    pub async fn check(&self, db: MySqlPool) -> Result<i64, ()> {
        let result: (i64,) = sqlx::query_as("select 1")
            .fetch_one(&db)
            .await
            .unwrap();
        Ok(result.0)

    }
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
