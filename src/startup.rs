use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};
use sqlx::PgPool;
use tower_http::trace::TraceLayer;
use tracing::{Level, event, instrument};

use crate::{
    configuration::Settings,
    handlers::{create_post_reply, create_topic, login, refresh_token, register_user, user_info},
};

#[derive(Debug)]
pub struct Application {
    listener: tokio::net::TcpListener,
    state: Arc<AppState>,
    port: u16,
}

impl Application {
    #[instrument(name = "build_server", skip(cfg))]
    pub async fn build(cfg: &Settings) -> anyhow::Result<Self> {
        let host = &cfg.server.host;
        let port = cfg.server.port;
        let db_url = &cfg.database.url;

        // Create the TCPListener for further usage
        let lst = tokio::net::TcpListener::bind(format!("{}:{}", host, port)).await?;
        let port = lst.local_addr()?.port();

        // connect to database and get the pool
        let pool = PgPool::connect(db_url).await?;

        // apply migrations
        sqlx::migrate!("./migrations").run(&pool).await?;

        // Initial state
        let state = AppState {
            db: pool,
            auth: AuthState {
                jwt_secret: cfg.auth.jwt_secret.clone(),
                refresh_token_ttl: cfg.auth.refresh_token_ttl,
                access_token_ttl: cfg.auth.access_token_ttl,
            },
        };

        let state = Arc::new(state);

        Ok(Self {
            listener: lst,
            state,
            port,
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
            .route("/user/refresh", post(refresh_token))
            .route("/user/info", get(user_info))
            .route("/topics/new", post(create_topic))
            .route("/topics/{topic_id}/reply", post(create_post_reply))
            .with_state(self.state.clone())
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Debug)]
pub struct AppState {
    pub db: PgPool,
    pub auth: AuthState,
}

#[derive(Debug)]
pub struct AuthState {
    pub jwt_secret: String,
    pub refresh_token_ttl: std::time::Duration,
    pub access_token_ttl: std::time::Duration,
}
