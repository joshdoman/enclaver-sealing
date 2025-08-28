use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json as AxumJson},
};
use std::sync::Arc;

use crate::{settings::Settings, AppState};

pub async fn get_settings_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let settings = match state.settings.get() {
        Some(settings) => settings.clone(),
        None => Settings::default(),
    };

    (StatusCode::OK, AxumJson(settings))
}

pub async fn update_settings_handler(
    State(state): State<Arc<AppState>>,
    AxumJson(payload): AxumJson<Settings>,
) -> impl IntoResponse {
    if state.settings.set(payload).is_err() {
        return (StatusCode::CONFLICT, "Settings have already been set.").into_response();
    }

    (StatusCode::OK, "Settings updated successfully.").into_response()
}
