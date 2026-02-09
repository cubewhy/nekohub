use config::Config;

#[derive(Debug, serde::Deserialize)]
pub struct Settings {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
}

impl Settings {
    pub fn try_load_single(file: &str) -> Result<Self, config::ConfigError> {
        Self::try_load(&[file.to_string()])
    }

    pub fn try_load(files: &[String]) -> Result<Self, config::ConfigError> {
        let mut settings = Config::builder().add_source(config::Environment::with_prefix("APP"));

        for file_name in files {
            settings = settings.add_source(config::File::with_name(file_name));
        }

        let settings = settings.build()?;

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
