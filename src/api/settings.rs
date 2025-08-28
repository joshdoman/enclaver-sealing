use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json as AxumJson},
};
use std::sync::Arc;

use crate::AppState;

pub async fn get_settings_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.settings.get() {
        Some(settings) => (StatusCode::OK, AxumJson(settings)).into_response(),
        None => (StatusCode::NOT_FOUND, "Settings not set.").into_response(),
    }
}
