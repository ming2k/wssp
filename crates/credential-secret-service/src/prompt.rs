use zbus::interface;
use zbus::zvariant::{ObjectPath, OwnedValue};

pub struct Prompt {
    pub path: ObjectPath<'static>,
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    async fn prompt(&self, _window_id: &str) -> zbus::fdo::Result<()> {
        Ok(())
    }

    async fn dismiss(&self) -> zbus::fdo::Result<()> {
        Ok(())
    }

    #[zbus(signal)]
    pub async fn completed(
        emitter: &zbus::object_server::SignalEmitter<'_>,
        dismissed: bool,
        result: OwnedValue,
    ) -> zbus::Result<()>;
}
