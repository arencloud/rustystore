use uuid::{Uuid};
use serde_json::{Value, Map};
use crate::api::routes::Msg;
use crate::datacrypt::datacrypt;

pub fn create_identity() -> Map<String, Value> {
    let mut identity: Map<String, Value> = serde_json::from_str(&datacrypt::create_identity()).unwrap();
    let id = Uuid::new_v4();
    let mut new_map = Map::new();
    new_map.insert("uuid".to_string(), Value::String(id.to_string()));
    new_map.append(&mut identity);
    new_map
}

pub fn get_msg(m: &str) -> Msg {
    Msg {
        message: format!("Route: {} CURRENTLY API IS UNDER DEVELOPMENT PHASE!!!", m)
    }
}