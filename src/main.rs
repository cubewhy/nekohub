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

    let cfg = Settings::try_load_single("configuration/application.toml")?;

    let app = Application::build(&cfg).await?;

    app.run_until_stopped().await?;

    Ok(())
}
