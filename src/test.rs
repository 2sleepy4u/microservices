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
    use crate::token::*;

    let email = "test@gmail.com".to_string();
    let duration_hours = 1;
    //let credentials = Credentials::new(email.clone(), password);
    let pub_key = include_bytes!("../keys/pubkey.pem");
    let priv_key = include_bytes!("../keys/privkey.pem");

    //generate keys at startup to save resource in runtime
    let token_generator = TokenGenerator::new(pub_key, priv_key).unwrap();
    let token = token_generator.token(email, duration_hours);

    assert!(token.is_ok());

    let verified = token_generator.verify(&token.unwrap());

    assert!(verified.is_ok());
}

#[tokio::test]
async fn test_register_user() {
    use crate::token::*;
    use sqlx::mysql::MySqlPoolOptions;

    dotenv::dotenv().ok();
    let url = std::env::var("DATABASE_URL").expect("Connection string not found");


    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("Unable to connect to db");



    let email = "test@gmail.com".to_string();
    let password = "secretpassword123!".to_string();
    let credentials = Credentials::new(email.clone(), password);

    let res = credentials.register(&pool).await;
    assert!(true);
}
