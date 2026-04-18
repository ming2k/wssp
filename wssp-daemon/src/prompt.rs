use tracing::info;
use zbus::interface;
use zbus::zvariant::Value;

pub struct Prompt {
    pub id: String,
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    async fn prompt(&self, window_id: &str) -> zbus::fdo::Result<()> {
        info!("Prompt {} called with window_id: {}", self.id, window_id);
        Ok(())
    }

    async fn dismiss(&self) -> zbus::fdo::Result<()> {
        info!("Prompt {} dismissed", self.id);
        Ok(())
    }

    #[zbus(signal)]
    pub async fn completed(
        emitter: &zbus::object_server::SignalEmitter<'_>,
        dismissed: bool,
        result: Value<'_>,
    ) -> zbus::Result<()>;
}
