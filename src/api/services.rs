use crate::api::routes::Msg;

pub fn get_msg(m: &str) -> Msg {
    Msg {
        message: format!("Route: {} CURRENTLY API IS UNDER DEVELOPMENT PHASE!!!", m)
    }
}