use anyhow::Result;
use confidential_script::run;

#[tokio::main]
async fn main() -> Result<()> {
    run().await
}
