use rocket::serde::json::{Json};
use rocket::serde::{Serialize, Deserialize};
use serde_json::{Map, Value};
use crate::api::services;

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct Msg {
    pub message: String,
}

#[rocket::get("/user/create-identity")]
pub fn create_identity() -> Json<Map<String, Value>> {
    Json(services::create_identity())
}
//Final route - /user/grant-access/<idx>/<idy>
#[rocket::get("/user/grant-access")]
pub fn grant_access() -> Json<Msg> {
    Json(services::get_msg("/user/grant-access/<idx>/<idy>"))
}

//Final route - /user/create-symmetric-key/<idx>
#[rocket::get("/user/create-symmetric-key")]
pub fn create_sym_key() -> Json<Msg> {
    Json(services::get_msg("/user/create-symmetric-key/<idx>"))
}

//Final route - /user/get-symmetric-key/<idx>/<idy>/<idk>
#[rocket::get("/user/get-symmetric-key")]
pub fn get_sym_key() -> Json<Msg> {
    Json(services::get_msg("/user/get-symmetric-key/<idx>/<idy>/<idk>"))
}

//Final route - /user/revoke-access/<idx>/<idy>
#[rocket::get("/user/revoke-access")]
pub fn revoke_access() -> Json<Msg> {
    Json(services::get_msg("/user/revoke-access/<idx>/<idy>"))
}
