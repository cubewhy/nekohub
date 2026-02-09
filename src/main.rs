use std::path::PathBuf;

use nekohub::{
    configuration::Settings,
    startup::Application,
    telemetry::{get_subscriber, init_subscriber},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // init logger
    let subscriber = get_subscriber("info", std::io::stdout);
    init_subscriber(subscriber);

    // probe config files
    let config_files = probe_config();
    let cfg = Settings::try_load(&config_files)?;

    let app = Application::build(&cfg).await?;

    app.run_until_stopped().await?;

    Ok(())
}

fn probe_config() -> Vec<String> {
    let mut config_files = vec!["configuration/application.toml".to_string()];

    // try to probe dev override[.toml,.yaml]
    let override_file = "configuration/override";
    if PathBuf::from(format!("{override_file}.toml")).exists()
        || PathBuf::from(format!("{override_file}.yaml")).exists()
    {
        tracing::info!("override[.toml, .yaml] config files will be loaded.");
        config_files.push(override_file.to_string());
    }

    config_files
}
