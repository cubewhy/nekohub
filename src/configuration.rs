use config::Config;

#[derive(Debug, serde::Deserialize)]
pub struct Settings {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
}

impl Settings {
    pub fn try_load(path: &str) -> Result<Self, config::ConfigError> {
        let settings = Config::builder()
            .add_source(config::File::with_name(path))
            .add_source(config::Environment::with_prefix("APP"))
            .build()?;

        settings.try_deserialize::<Self>()
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

#[derive(Debug, serde::Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}
