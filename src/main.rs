use rustystore::api::routes;
#[macro_use] extern crate rocket;

#[get("/")]
fn api_home() -> &'static str {
    "Rustystore Api home"
}

#[get("/")]
fn home() -> &'static str {
    "Please use /api to access API"
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    let _rocket = rocket::build()
        .mount("/", routes![home])
        .mount("/api", routes![api_home])
        .mount("/api", routes![routes::create_identity, routes::grant_access,
               routes::create_sym_key, routes::get_sym_key, routes::revoke_access])
        .ignite().await?
        .launch().await?;
    Ok(())
}