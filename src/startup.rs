use std::sync::Arc;

use axum::{Router, routing::post};
use sqlx::PgPool;
use tower_http::trace::TraceLayer;
use tracing::{Level, event, instrument};

use crate::{
    configuration::Settings,
    handlers::{login, register_user},
};

#[derive(Debug)]
pub struct Application {
    listener: tokio::net::TcpListener,
    state: Arc<AppState>,
}

impl Application {
    #[instrument(name = "build_server")]
    pub async fn build(cfg: &Settings) -> anyhow::Result<Self> {
        let host = &cfg.server.host;
        let port = cfg.server.port;
        let db_url = &cfg.database.url;

        // Create the TCPListener for further usage
        let lst = tokio::net::TcpListener::bind(format!("{}:{}", host, port)).await?;

        // connect to database and get the pool
        let pool = PgPool::connect(db_url).await?;

        // apply migrations
        sqlx::migrate!("./migrations").run(&pool).await?;

        // Initial state
        let state = AppState { pool };

        let state = Arc::new(state);

        Ok(Self {
            listener: lst,
            state,
        })
    }

    #[instrument(name = "mainloop", skip(self))]
    pub async fn run_until_stopped(mut self) -> std::io::Result<()> {
        let addr = self.listener.local_addr()?;
        let host = addr.ip().to_string();
        let port = addr.port();

        // Create the router
        let router = self.create_app_router();

        event!(Level::INFO, "Serving at {}:{}", host, port);

        // Serve the server
        axum::serve(self.listener, router).await
    }

    fn create_app_router(&mut self) -> Router {
        // Initial router with state
        Router::new()
            .layer(TraceLayer::new_for_http())
            .route("/user/register", post(register_user))
            .route("/user/login", post(login))
            .with_state(self.state.clone())
    }
}

#[derive(Debug)]
pub struct AppState {
    pub pool: PgPool,
}
