use dotenv::dotenv;

#[test] 
fn test_credentials_validation() {
    use crate::token::*;

    let email = "test@gmail.com".to_string();
    let password = "Secretpassword123!".to_string();
    let credentials = Credentials::new(email, password);

    assert!(credentials.validate_email());
    assert!(credentials.validate_password());

    let email = "not an email".to_string();
    let password = "weak ".to_string();
    let credentials = Credentials::new(email, password);
 
    assert!(!credentials.validate_email());
    assert!(!credentials.validate_password());
}

#[test]
fn test_token_creation() {
    use crate::state::*;
    use crate::token::*;

    let email = "test@newspaper.com".to_string();
    let duration_hours = 1;
    //let credentials = Credentials::new(email.clone(), password);
    dotenv::dotenv().ok();
    let config: Config = Config::load_from_env();
    let pub_key = config.pub_key.as_bytes();
    let priv_key = config.priv_key.as_bytes();

    //generate keys at startup to save resource in runtime
    let token_generator = TokenGenerator::new(pub_key, priv_key).unwrap();
    let payload = Payload::new(duration_hours, email, config.ip.to_string(), config.ip, "TestUser".to_string());
    let token = token_generator.token(payload);

    assert!(token.is_ok());

    let verified = token_generator.verify(&token.unwrap());

    assert!(verified.is_ok());
}

#[tokio::test]
async fn test_register_user() {
    use crate::token::*;
    use crate::state::*;
    use sqlx::mysql::MySqlPoolOptions;

    dotenv::dotenv().ok();
    let config: Config = Config::load_from_env();
    let url = config.db_string;


    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("Unable to connect to db");



    let email = "test@gmail.com".to_string();
    let password = "secretpassword123!".to_string();
    let credentials = Credentials::new(email.clone(), password);

    let res = credentials.register(config.ip, &pool).await;
    assert!(true);
}
