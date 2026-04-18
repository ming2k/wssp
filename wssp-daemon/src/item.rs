use crate::state::State;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use zbus::interface;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

#[derive(Clone)]
pub struct Item {
    pub id: String,
    pub label: Arc<RwLock<String>>,
    pub attributes: Arc<RwLock<HashMap<String, String>>>,
    pub secret: Arc<RwLock<Vec<u8>>>,
    pub is_deleted: Arc<RwLock<bool>>,
    pub state: Arc<RwLock<State>>,
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    async fn delete(&self) -> zbus::fdo::Result<OwnedObjectPath> {
        info!("Delete item: {}", self.id);
        *self.is_deleted.write().await = true;
        self.state.read().await.sync_to_vault().await;
        Ok(OwnedObjectPath::try_from("/").unwrap())
    }

    async fn get_secret(
        &self,
        session_path: ObjectPath<'_>,
    ) -> zbus::fdo::Result<(OwnedObjectPath, Vec<u8>, Vec<u8>, String)> {
        info!("GetSecret: {}", self.id);
        let state_guard = self.state.read().await;
        let session = state_guard
            .sessions
            .get(&OwnedObjectPath::from(session_path.clone()))
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("Invalid session".into()))?;

        let secret_raw = self.secret.read().await.clone();
        let (params, encrypted) = session
            .encrypt(&secret_raw)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok((session_path.into(), params, encrypted, "text/plain".into()))
    }

    async fn set_secret(
        &self,
        secret: (OwnedObjectPath, Vec<u8>, Vec<u8>, String),
    ) -> zbus::fdo::Result<()> {
        info!("SetSecret: {}", self.id);
        *self.secret.write().await = secret.2;
        self.state.read().await.sync_to_vault().await;
        Ok(())
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        self.label.read().await.clone()
    }

    #[zbus(property)]
    async fn set_label(&self, label: String) {
        *self.label.write().await = label;
    }

    #[zbus(property)]
    async fn attributes(&self) -> HashMap<String, String> {
        self.attributes.read().await.clone()
    }

    #[zbus(property)]
    async fn set_attributes(&self, attributes: HashMap<String, String>) {
        *self.attributes.write().await = attributes;
    }

    #[zbus(property)]
    fn created(&self) -> u64 {
        0
    }

    #[zbus(property)]
    fn modified(&self) -> u64 {
        0
    }
}
