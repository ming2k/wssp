use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};
use zbus::interface;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Value};

use crate::item::Item;
use crate::state::State;

#[derive(Clone)]
pub struct Collection {
    pub id: String,
    pub label: Arc<RwLock<String>>,
    pub items: Arc<RwLock<HashMap<String, Item>>>,
    pub is_deleted: Arc<RwLock<bool>>,
    pub state: Arc<RwLock<State>>,
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    async fn delete(&self) -> zbus::fdo::Result<OwnedObjectPath> {
        info!("Delete collection: {}", self.id);
        *self.is_deleted.write().await = true;
        self.state.read().await.sync_to_vault().await;
        Ok(ObjectPath::from_static_str("/").unwrap().into())
    }

    async fn search_items(
        &self,
        attributes: HashMap<&str, &str>,
    ) -> zbus::fdo::Result<Vec<OwnedObjectPath>> {
        debug!("Collection::SearchItems called for collection: {} with {} attributes", self.id, attributes.len());
        let items = self.items.read().await;
        let mut matched = Vec::new();
        for (id, item) in items.iter() {
            if *item.is_deleted.read().await {
                continue;
            }
            let item_attrs = item.attributes.read().await;
            let matches = attributes
                .iter()
                .all(|(k, v)| item_attrs.get(*k).map(String::as_str) == Some(*v));
            if matches {
                let path = format!("/org/freedesktop/secrets/collection/{}/{}", self.id, id);
                if let Ok(p) = OwnedObjectPath::try_from(path) {
                    matched.push(p);
                }
            }
        }
        Ok(matched)
    }

    async fn create_item(
        &self,
        #[zbus(object_server)] server: &zbus::ObjectServer,
        properties: HashMap<&str, Value<'_>>,
        secret: (OwnedObjectPath, Vec<u8>, Vec<u8>, String),
        _replace: bool,
    ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        info!("CreateItem in collection: {}", self.id);

        let session_path = &secret.0;
        let params = &secret.1;
        let ciphertext = &secret.2;

        let decrypted_secret = {
            let state_guard = self.state.read().await;
            let session = state_guard
                .sessions
                .get(session_path)
                .ok_or_else(|| zbus::fdo::Error::InvalidArgs("Invalid session".into()))?;
            session
                .decrypt(params, ciphertext)
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?
        };

        let item_id = generate_id();
        let item_path = format!(
            "/org/freedesktop/secrets/collection/{}/{}",
            self.id, item_id
        );
        let owned_path = OwnedObjectPath::try_from(item_path)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;

        let label = match properties.get("org.freedesktop.Secret.Item.Label") {
            Some(Value::Str(l)) => l.as_str().to_string(),
            _ => "New Item".to_string(),
        };

        let mut attributes = HashMap::new();
        if let Some(Value::Dict(dict)) = properties.get("org.freedesktop.Secret.Item.Attributes") {
            for (k, v) in dict.iter() {
                if let (Value::Str(k_str), Value::Str(v_str)) = (k, v) {
                    attributes.insert(k_str.as_str().to_string(), v_str.as_str().to_string());
                }
            }
        }

        let item = Item {
            id: item_id.clone(),
            label: Arc::new(RwLock::new(label)),
            attributes: Arc::new(RwLock::new(attributes)),
            secret: Arc::new(RwLock::new(decrypted_secret)),
            is_deleted: Arc::new(RwLock::new(false)),
            state: self.state.clone(),
        };

        self.items.write().await.insert(item_id.clone(), item.clone());

        if let Err(e) = server.at(owned_path.clone(), item).await {
            error!("Failed to register item on D-Bus: {}", e);
            return Err(zbus::fdo::Error::Failed("D-Bus registration failed".into()));
        }

        self.state.read().await.sync_to_vault().await;

        Ok((owned_path, OwnedObjectPath::try_from("/").unwrap()))
    }

    #[zbus(property)]
    async fn items(&self) -> Vec<OwnedObjectPath> {
        let items = self.items.read().await;
        let mut paths = Vec::new();
        for (id, item) in items.iter() {
            if !*item.is_deleted.read().await {
                let path = format!("/org/freedesktop/secrets/collection/{}/{}", self.id, id);
                if let Ok(p) = OwnedObjectPath::try_from(path) {
                    paths.push(p);
                }
            }
        }
        paths
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
    fn created(&self) -> u64 {
        0
    }

    #[zbus(property)]
    fn modified(&self) -> u64 {
        0
    }
}

fn generate_id() -> String {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
