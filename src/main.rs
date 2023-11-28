mod helper;

use actix_web::web::Redirect;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};

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


#[get("/")]
pub async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[post("/echo")]
pub async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

pub async fn manual_hello() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}

#[get("/callback")]
async fn callback(info: web::Query<Info>, data: web::Data<State>) -> impl Responder {
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
        .expect("failed to get payload");

    let guilds_list = 
        request.get("https://discord.com/api/users/@me/guilds")
        .header("Authorization", base.clone())
        .send()
        .await
        .expect("failed to get response")
        .json::<Vec<Guild>>()
        .await
        .expect("failed to get payload");

    // insert into MongoDB if doesn't exist, update if anything is different
    /*
        @TODO write doc types
     */

    let db = mongo.database("test");
    let users : Collection<Document> = db.collection("users");

    let search = 
    users.find_one(
        Some(doc! {
            "user": {
                "id": user_json.id.clone()
            }
        }),
        None
    ).await.unwrap();

    match search {
        Some(_doc) => {
            println!("User found!");

            users.update_one(
                doc! {
                    "user_id": user_json.id.clone(),
                },

                doc! {
                    "$set": {
                        "user": {
                            "username": user_json.username.clone(),
                            "discriminator": user_json.discriminator.clone()
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
                    username: user_json.username.clone(),
                    id: user_json.id.clone(),
                    discriminator: user_json.discriminator.clone()
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


    HttpResponse::Ok().body("request success")
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
    // helper::helper::handler(auth_url).await;
    Redirect::to(redirect_url)
}


//#[actix_web::main]
#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let state = State { 
        client: helper::helper::client_create().unwrap(),
        request : reqwest::Client::new(),
        mongo : helper::helper::mongo_init().await.unwrap()
    };

    HttpServer::new(move || {

        App::new()
            .app_data(web::Data::new(state.clone()))
            .service(hello)
            .service(authenticate)
            .service(echo)
            .service(callback)
            .route("/hey", web::get().to(manual_hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}