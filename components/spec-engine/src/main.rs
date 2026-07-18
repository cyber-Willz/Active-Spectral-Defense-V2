#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    spec_engine::run().await
}
