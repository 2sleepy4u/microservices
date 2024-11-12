use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey, errors::Error};
use serde::{Serialize, Deserialize};

use chrono::prelude::*;
use sqlx::MySqlPool;
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Sha512, Digest};

use tracing::debug;
use utoipa::ToSchema;

use crate::OptionLogError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(ToSchema)]
pub struct Credentials {
    pub email: String,
    pub password: String
}

#[derive(Debug, Clone)]
pub enum CredentialsError {
    AlreadyExists
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(ToSchema)]
pub struct User {
    pub email: String,
    pub role: String
}

impl User {
    pub async fn insert(&self, aud: &str, db: &MySqlPool) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "
                INSERT INTO UsersPermissions 
                    (user_id, permission_id) 
                SELECT 
                    Users.id, Permissions.id 
                FROM
                    Users INNER JOIN 
                    UsersPermissions ON Users.id = UsersPermissions.user_id INNER JOIN
                    Permissions ON Permissions.id = UsersPermissions.permission_id
                WHERE
                    Users.email = ? AND
                    Permissions.audience = ?
                   
            ",
            &self.email,
            &aud
            )
            .fetch_optional(db)
            .await
            .and_then(|_| Ok(()))

    }
    pub async fn update(&self, aud: &str, db: &MySqlPool) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "
                UPDATE 
                    UsersPermissions INNER JOIN
                    Users ON Users.id = UsersPermissions.user_id INNER JOIN
                    Permissions ON Permissions.id = UsersPermissions.permission_id
                SET 
                    user_id = Users.id, 
                    permission_id = Permissions.id
                WHERE
                    Users.email = ? AND
                    Permissions.audience = ?
            ",
            &self.email,
            &aud
            )
            .fetch_optional(db)
            .await
            .and_then(|_| Ok(()))
    }
    pub async fn get_user(&self, aud: &str, db: &MySqlPool) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as!(
            User,
            "
                SELECT
                    Users.email,
                    Permissions.name as role
                FROM
                    Users INNER JOIN 
                    UsersPermissions ON Users.id = UsersPermissions.user_id INNER JOIN
                    Permissions ON Permissions.id = UsersPermissions.permission_id
                WHERE
                    Users.email = ? AND
                    Permissions.audience = ?
            ",
            &self.email,
            &aud
            )
            .fetch_optional(db)
            .await
    }
    
}

impl Credentials {
    pub fn new(email: String, password: String) -> Self {
        Self { email, password }
    }

    pub fn validate_email(&self) -> bool {
        regex::Regex::new(r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})")
            .is_ok_and(|x| x.is_match(&self.email))
    }

    pub fn validate_password(&self) -> bool {
        let mut has_whitespace = false;
        let mut has_upper = false;
        let mut has_lower = false;
        let mut has_digit = false;

        for c in self.password.chars() {
            has_whitespace |= c.is_whitespace();
            has_lower |= c.is_lowercase();
            has_upper |= c.is_uppercase();
            has_digit |= c.is_digit(10);
        }

        !has_whitespace && has_upper && has_lower && has_digit && self.password.len() >= 8
    }

    pub async fn register(&self, aud: String, db: &MySqlPool) -> Result<(), CredentialsError> {
        match self.get_user(aud, db).await {
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

    pub async fn get_user(&self, aud: String, db: &MySqlPool) -> Result<Option<User>, sqlx::Error> {
        debug!("{}", &aud);
        sqlx::query_as!(
            User,
            "
                SELECT
                    Users.email,
                    Permissions.name as role
                FROM
                    Users INNER JOIN 
                    UsersPermissions ON Users.id = UsersPermissions.user_id INNER JOIN
                    Permissions ON Permissions.id = UsersPermissions.permission_id
                WHERE
                    Users.active = true AND
                    Users.email = ? AND
                    Permissions.audience = ?
            ",
            &self.email,
            &aud
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

    pub fn token(&self, payload: Payload) -> Result<String, Error> {
        let token = encode(&Header::new(Algorithm::RS256), &payload, &self.priv_key)?;
        Ok(token)
    }

    pub fn verify(&self, token: &str) -> Result<Payload, Error> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        let token = decode::<Payload>(&token, &self.pub_key, &validation)?;
        Ok(token.claims)
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub struct Payload {
    role: String,
    //the user
    sub: String,
    //expiration
    exp: usize,
    //from what auth service
    iss: String, 
    //for what service
    aud: String 
}

impl Payload  {
    pub fn new(duration: u32, sub: String, iss: String, aud: String, role: String) -> Self {
        let utc: DateTime<Utc> = Utc::now(); 
        let hours = utc.hour() + duration;
        let exp = utc.with_hour(hours)
            .expect_and_log("Error setting exp timestamp")
            .timestamp() as usize;


        Self { sub, iss, aud, exp, role}
    }
}
