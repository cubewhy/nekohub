use sqlx::Executor;
use std::sync::LazyLock;

use nekohub::{
    configuration::Settings,
    startup::Application,
    telemetry::{get_subscriber, init_subscriber},
};
use sqlx::{Connection, PgConnection, PgPool};
use tokio::task::JoinHandle;
use url::Url;
use uuid::Uuid;

static TRACING: LazyLock<()> = LazyLock::new(|| {
    let default_filter_level = "info";
    if std::env::var("TEST_LOG").is_ok() {
        let subscriber = get_subscriber(default_filter_level, std::io::stdout);
        init_subscriber(subscriber);
    } else {
        let subscriber = get_subscriber(default_filter_level, std::io::sink);
        init_subscriber(subscriber);
    }
});

pub struct TestApp {
    _db_guard: DbGuard,
    pub base_url: String,
    pub http_client: reqwest::Client,
    pub db: PgPool,
    _handle: JoinHandle<Result<(), std::io::Error>>,
}

impl TestApp {
    pub async fn new() -> Self {
        // only init logger once
        LazyLock::force(&TRACING);

        // build the configuration
        let cfg = {
            let mut orig =
                Settings::try_load(&["configuration/application.toml", "configuration/test.toml"])
                    .expect("Failed to load test config");

            // apply random port cfg
            orig.server.port = 0;

            // apply random db name
            let new_db_name = Uuid::new_v4().to_string().replace("-", "");
            let orig_url = &orig.database.url;
            orig.database.url = replace_db_name(orig_url, &new_db_name);

            orig
        };

        let db_url = &cfg.database.url;

        // init the random database
        let db = setup_database(db_url).await;
        // also init the db guard
        let db_guard = DbGuard {
            db_url: db_url.clone(),
        };

        // build the server
        let app = Application::build(&cfg)
            .await
            .expect("Failed to create test app");

        let port = app.port();

        // run the server in another thread
        let handle = tokio::spawn(app.run_until_stopped());

        let base_url = format!("http://127.0.0.1:{port}");

        // create the http client
        let http_client = reqwest::Client::new();

        Self {
            _handle: handle,
            base_url,
            http_client,
            db,
            _db_guard: db_guard,
        }
    }
}

async fn setup_database(db_url: &str) -> PgPool {
    // get db name from url
    let database_name = get_db_name_from_url(db_url);
    // replace url with db name "postgres"
    let maintaince_db_url = replace_db_name(db_url, "postgres");
    let mut connection = PgConnection::connect(&maintaince_db_url)
        .await
        .expect("Failed to connect to database \"postgres\"");

    // create database
    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, database_name).as_str())
        .await
        .expect("Failed to create database");

    // Run migrations
    let pool = PgPool::connect(db_url)
        .await
        .expect("Failed to connect to database");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to migrate the database");

    pool
}

fn replace_db_name(db_url: &str, new_db_name: &str) -> String {
    let mut url = Url::parse(db_url).expect("Failed to parse database url");
    // replace the path part
    url.set_path(new_db_name);

    url.to_string()
}

fn get_db_name_from_url(db_url: &str) -> String {
    let url = Url::parse(db_url).expect("Failed to parse database url");

    url.path().strip_prefix("/").unwrap().to_string()
}

struct DbGuard {
    db_url: String,
}

impl DbGuard {
    async fn cleanup(&self) {
        // connect to the maintaince db (postgres)
        // get db name from url
        let database_name = get_db_name_from_url(&self.db_url);
        // replace url with db name "postgres"
        let maintaince_db_url = replace_db_name(&self.db_url, "postgres");
        let mut connection = PgConnection::connect(&maintaince_db_url)
            .await
            .expect("Failed to connect to database \"postgres\"");

        // disconnect other clients
        let disconnect_query = format!(
            r#"
        SELECT pg_terminate_backend(pg_stat_activity.pid)
        FROM pg_stat_activity
        WHERE pg_stat_activity.datname = '{}'
          AND pid <> pg_backend_pid();
        "#,
            database_name,
        );

        let _ = sqlx::query(&disconnect_query)
            .execute(&mut connection)
            .await;

        // delete database
        connection
            .execute(format!(r#"DROP DATABASE "{}";"#, database_name).as_str())
            .await
            .expect("Failed to drop database");
    }
}

impl Drop for DbGuard {
    fn drop(&mut self) {
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(h) => h,
            Err(_) => {
                std::thread::spawn(move || {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap()
                        .block_on(async { /* self.cleanup().await */ });
                })
                .join()
                .unwrap();
                return;
            }
        };

        match handle.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        self.cleanup().await;
                    });
                });
            }

            _ => {
                std::thread::scope(|s| {
                    s.spawn(|| {
                        tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .unwrap()
                            .block_on(async {
                                self.cleanup().await;
                            });
                    });
                });
            }
        }
    }
}
