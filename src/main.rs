use nekohub::{configuration::Settings, startup::Application, telemetry::init_logger};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logger();

    let cfg = Settings::try_load("configuration/application.toml")?;

    let app = Application::build(&cfg).await?;

    app.run_until_stopped().await?;

    Ok(())
}
