

pub mod helper {
    use oauth2::{
        AuthUrl,
        ClientId,
        ClientSecret,
        RedirectUrl,
        TokenUrl, 
        //reqwest,
    };
    use oauth2::basic::BasicClient;

    use mongodb::{Client, options::{ClientOptions, ResolverConfig}};
    use std::env;

    use actix_web::cookie::Key;

    pub fn client_create() -> Result<BasicClient, anyhow::Error> {
        let client =
        BasicClient::new(
            ClientId::new(env::var("DASHBOARD_CLIENT_ID").expect("Missing Client ID").to_string()),
            Some(ClientSecret::new(env::var("DASHBOARD_CLIENT_SECRET").expect("Missing Client Secret").to_string())),
            AuthUrl::new(env::var("DISCORD_OAUTH_URL").expect("Missing Auth URL").to_string())?,
            Some(TokenUrl::new(env::var("TOKEN_ENDPOINT_URL").expect("Missing Token URL").to_string())?)
        )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(RedirectUrl::new(env::var("DASHBOARD_CALLBACK_URL").expect("Missing Redirect URL").to_string()).expect("Missing Redirect URL 2"));
    
    
        // return the value
        Ok( client )
    }

    pub async fn mongo_init() -> Result<Client, anyhow::Error> {
        let client_uri = 
            env::var("MONGODB_URL").expect("Missing DB URL, Cannot Continue Operation, Abort.");
        // A Client is needed to connect to MongoDB:
        // An extra line of code to work around a DNS issue on Windows:
        let options =
        ClientOptions::parse_with_resolver_config(&client_uri, ResolverConfig::cloudflare())
            .await?;
        let client = Client::with_options(options)?;

        println!("Successfully Connected to Database!");

        println!("Databases:");
        for name in client.list_database_names(None, None).await? {
            println!("- {}", name);
        }

        Ok( client )
    }

    pub async fn get_session_key() -> Result<Key, anyhow::Error> {

        let key = Key::generate();

        Ok( key ) 
    }
}