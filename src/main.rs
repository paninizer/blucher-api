mod helper;

use std::env;

use actix_cors::Cors;
use actix_session::Session;
use actix_session::config::PersistentSession;
use actix_web::{http, put};
use actix_web::web::Redirect;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder, cookie::time};
use actix_session::{SessionMiddleware, storage::CookieSessionStore};

use bson::Document;
//use actix_web::http::StatusCode;
use mongodb::{Client, Collection};
use mongodb::bson::doc;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthorizationCode, CsrfToken, Scope, TokenResponse, 
    //reqwest,
};


use oauth2::basic::BasicClient;
use reqwest;
use dotenv::dotenv;
use tokio;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct Info {
    code: String,
    //state : String
}

#[derive(Deserialize, Serialize, Clone)]
struct Guild {
    id : String,
    owner : bool,
    permissions : u64
}

#[derive(Serialize, Deserialize)]
struct User {
    id : String,
    username : String,
    discriminator : String
}

#[derive(Serialize, Deserialize)]
pub struct UserDoc {
    #[serde(rename = "_id")]
    id: bson::oid::ObjectId,
    user: User,
    guilds: Vec<Guild>
}

#[derive(Clone)]
pub struct State {
    client : BasicClient,
    request : reqwest::Client,
    mongo : Client
}

#[derive(Serialize, Deserialize)]
pub struct PrefixURLHandler {
    guild_id: String
}

#[get("/auth/discord")]
async fn callback(params: Option<web::Query<Info>>, data: web::Data<State>, session: Session) -> impl Responder {
    // returns 400 if bad / no params
    match params {
        Some(info) => {
            let client = &data.client;
            let request = &data.request;
            let mongo = &data.mongo;

            let token_result = client
                .exchange_code(AuthorizationCode::new(info.code.clone()))
                // Set the PKCE code verifier.
                .request_async(async_http_client)
                .await.unwrap();

            // get token string
            let mut base = "Bearer ".to_owned();
            let token : &str = token_result.access_token().secret();

            base.push_str(token);
            // go get /oauth2/@me and others for data
            let user_json =
                request.get("https://discord.com/api/users/@me")
                .header("Authorization", base.clone())
                .send()
                .await
                .expect("failed to get response")
                .json::<User>()
                .await
                .expect("failed to get user payload");

            let guilds_list = 
                request.get("https://discord.com/api/users/@me/guilds")
                .header("Authorization", base.clone())
                .send()
                .await
                .expect("failed to get response")
                .json::<Vec<Guild>>()
                .await
                .expect("failed to get guild payload");

            // insert into MongoDB if doesn't exist, update if anything is different
            /*
                @TODO create cookies
            */

            let db = mongo.database("test");
            let users : Collection<Document> = db.collection("users");

            let query = doc! {
                "user.id": user_json.id.clone()
            };

            let search = users
                .find_one(query, None)
                .await
                .unwrap();

            match search {
                Some(_doc) => {
                    println!("User found!");

                    users.update_one(
                        doc! {
                            "user.id": user_json.id.clone(),
                        },

                        doc! {
                            "$set": {
                                "user": {
                                    "username": user_json.username.clone(),
                                    "discriminator": user_json.discriminator.clone(),
                                    "id": user_json.id.clone()
                                },
                                "guilds": bson::to_bson(&guilds_list.clone()).unwrap()
                            }
                        },

                        None
                    ).await.expect("Did not update successfully");
                },
                None => {
                    let doc_ins = UserDoc {
                        id: bson::oid::ObjectId::new(),
                        user: User {
                            username: user_json.username.clone().to_string(),
                            id: user_json.id.clone().to_string(),
                            discriminator: user_json.discriminator.clone().to_string()
                        },
                        guilds: guilds_list.clone()
                    };

                    let bson_obj = bson::to_bson(&doc_ins).unwrap();

                    // println!("No user found, creating document.");
                    users.insert_one(
                        bson::from_bson::<Document>(bson_obj).unwrap(),
                        None
                    ).await.expect("Did not create new user successfully");
                    // println!("A document with the ID {} has been created.", insert_res.inserted_id)
                }
            }
            
            // set session
            // Insert user_json into cookie
            session.insert("user", user_json.username.clone()).unwrap();
            session.insert("user_id", user_json.id.clone()).unwrap();
            
            println!("Session: {:?}", session.get::<String>("user"));
            //println!("{:?}", session.get::<String>("user_id"));
            //
            //Redirect::to("https://dashboard-client.panzer-chan.repl.co/menu");
        },
        None => {
            Redirect::to("http://127.0.0.1:8080/auth/discord/redirect");
        } // if no params, redirect to regain authentication
    }

    HttpResponse::Ok().body("Authenticated!")
}



#[get("/auth/discord/redirect")]
pub async fn authenticate(data: web::Data<State>) -> impl Responder {
    let client = &data.client;

    let (auth_url, _csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new("identify".to_string()))
        .add_scope(Scope::new("guilds".to_string()))
        .url();

    let redirect_url = auth_url.to_string().replace("+", "%20");
    // redirect to auth_url, where the user will authenticate
    Redirect::to(redirect_url)
}

#[put("/api/guilds/{guild_id}/prefix")]
pub async fn prefix(data: web::Data<State>, path_var: web::Path<PrefixURLHandler>) -> impl Responder {

    // future impl mongodb update query and handler if no cookie

    HttpResponse::Ok().body(format!("{}", &path_var.guild_id))
}

#[get("/api/guilds")]
pub async fn guilds(data: web::Data<State>, session: Session) -> impl Responder {
    let request = &data.request;
    let mut base = "Bot ".to_string();
    let token = env::var("TOKEN").unwrap();
    base.push_str(&token);
    let list = request.get("https://discord.com/api/v6/users/@me/guilds")
        .header("Authorization", base);

    let bot_guilds = list.send().await.unwrap().json::<Vec<Guild>>().await.unwrap();
    
    let user_guilds = session.get::<Vec<Guild>>("guilds").unwrap();

    if user_guilds.is_none() {
        HttpResponse::Unauthorized().body("Unauthorized");
    }

    let mutual_guilds = bot_guilds
        .into_iter()
        .filter(|g| g.permissions & 8 == 8)
        .collect::<Vec<Guild>>();

    HttpResponse::Ok().json(mutual_guilds)
}


//#[actix_web::main]
#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    
    let session_key = helper::helper::get_session_key().await.expect("Missing session key.");
    let state = State { 
        client: helper::helper::client_create().unwrap(),
        request : reqwest::Client::new(),
        mongo : helper::helper::mongo_init().await.unwrap()
    };

    HttpServer::new(move || {

        let cors = Cors::default()
            .allowed_origin("https://dashboard-client.panzer-chan.repl.co")
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
            .allowed_header(http::header::CONTENT_TYPE)
            .supports_credentials()
            .max_age(60*60*24); // one day max age 


        App::new()
            .wrap(SessionMiddleware::builder
                (
                    CookieSessionStore::default(),
                    session_key.clone()
                )
                .cookie_name("user".to_string())
                .cookie_http_only(false)
                .cookie_same_site(actix_web::cookie::SameSite::None)
                .cookie_secure(true)
                .session_lifecycle( 
                    PersistentSession::default()
                    .session_ttl(time::Duration::days(1))
                )
                .build()
            )
            .wrap(cors)
            .app_data(web::Data::new(state.clone()))
            .service(authenticate)
            .service(callback)
            .service(prefix)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}