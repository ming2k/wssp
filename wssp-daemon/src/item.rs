use crate::state::State;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use zbus::interface;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

#[derive(serde::Serialize, serde::Deserialize, zbus::zvariant::Type)]
pub struct SecretStruct {
    pub session: OwnedObjectPath,
    pub parameters: Vec<u8>,
    pub value: Vec<u8>,
    pub content_type: String,
}

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
        if !self.state.read().await.is_unlocked {
            return Err(zbus::fdo::Error::Failed(
                "org.freedesktop.Secret.Error.IsLocked".into(),
            ));
        }
        *self.is_deleted.write().await = true;
        self.state.read().await.sync_to_vault().await;
        Ok(OwnedObjectPath::try_from("/").unwrap())
    }

    async fn get_secret(&self, session_path: ObjectPath<'_>) -> zbus::fdo::Result<(SecretStruct,)> {
        info!("GetSecret: {}", self.id);
        let state_guard = self.state.read().await;
        if !state_guard.is_unlocked {
            return Err(zbus::fdo::Error::Failed(
                "org.freedesktop.Secret.Error.IsLocked".into(),
            ));
        }
        let session = state_guard
            .sessions
            .get(&OwnedObjectPath::from(session_path.clone()))
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("Invalid session".into()))?;

        let secret_raw = self.secret.read().await.clone();
        let (params, encrypted) = session
            .encrypt(&secret_raw)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok((SecretStruct {
            session: session_path.into(),
            parameters: params,
            value: encrypted,
            content_type: "text/plain".into(),
        },))
    }

    async fn set_secret(
        &self,
        secret: (OwnedObjectPath, Vec<u8>, Vec<u8>, String),
    ) -> zbus::fdo::Result<()> {
        info!("SetSecret: {}", self.id);
        let state_guard = self.state.read().await;
        if !state_guard.is_unlocked {
            return Err(zbus::fdo::Error::Failed(
                "org.freedesktop.Secret.Error.IsLocked".into(),
            ));
        }
        let session = state_guard
            .sessions
            .get(&secret.0)
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("Invalid session".into()))?;

        let decrypted_secret = session
            .decrypt(&secret.1, &secret.2)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        drop(state_guard);

        *self.secret.write().await = decrypted_secret;
        self.state.read().await.sync_to_vault().await;
        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        !self.state.read().await.is_unlocked
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
