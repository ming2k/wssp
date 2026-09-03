use crate::item::{Item, SecretStruct};
use crate::session::Session;
use sigil_service::SigilService;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use zbus::interface;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Value};

pub struct Collection {
    pub id: String,
    pub service: SigilService,
    pub sessions: Arc<RwLock<HashMap<OwnedObjectPath, Arc<Session>>>>,
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    async fn delete(&self) -> zbus::fdo::Result<ObjectPath<'_>> {
        self.service
            .delete_collection(&self.id)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(ObjectPath::from_static_str("/").unwrap())
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> zbus::fdo::Result<Vec<OwnedObjectPath>> {
        let matches = self
            .service
            .search_items(Some(&self.id), &attributes)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let mut paths = Vec::new();
        for (col_id, item_id) in matches {
            if let Ok(p) = OwnedObjectPath::try_from(format!(
                "/org/freedesktop/secrets/collection/{col_id}/{item_id}"
            )) {
                paths.push(p);
            }
        }
        Ok(paths)
    }

    async fn create_item(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        properties: HashMap<String, Value<'_>>,
        secret: SecretStruct,
        replace: bool,
    ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        let label = properties
            .get("org.freedesktop.Secret.Item.Label")
            .and_then(|v| match v {
                Value::Str(s) => Some(s.to_string()),
                _ => None,
            })
            .unwrap_or_else(|| "Secret".into());

        let mut attributes = HashMap::new();
        if let Some(Value::Dict(d)) = properties.get("org.freedesktop.Secret.Item.Attributes") {
            for (k, v) in d.iter() {
                if let (Value::Str(ks), Value::Str(vs)) = (k, v) {
                    attributes.insert(ks.to_string(), vs.to_string());
                }
            }
        }

        let sessions = self.sessions.read().await;
        let session = sessions
            .get(&secret.session)
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("Session not found".into()))?;

        let plain_bytes = session
            .decrypt(&secret.parameters, &secret.value)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let item_id = format!("i_{}", rand::thread_rng().next_u64());

        self.service
            .set_item(
                &self.id,
                &item_id,
                &label,
                attributes,
                &plain_bytes,
                &secret.content_type,
                replace,
            )
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let item_path = OwnedObjectPath::try_from(format!(
            "/org/freedesktop/secrets/collection/{}/{item_id}",
            self.id
        ))
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let item_obj = Item {
            collection_id: self.id.clone(),
            item_id,
            service: self.service.clone(),
            sessions: self.sessions.clone(),
        };

        let _ = conn.object_server().at(&item_path, item_obj).await;

        let prompt_path = OwnedObjectPath::try_from("/").unwrap();
        Ok((item_path, prompt_path))
    }

    #[zbus(property)]
    async fn items(&self) -> zbus::fdo::Result<Vec<OwnedObjectPath>> {
        let col = self
            .service
            .get_collection(&self.id)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let mut paths = Vec::new();
        for item_id in col.items.keys() {
            if let Ok(p) = OwnedObjectPath::try_from(format!(
                "/org/freedesktop/secrets/collection/{}/{item_id}",
                self.id
            )) {
                paths.push(p);
            }
        }
        Ok(paths)
    }

    #[zbus(property)]
    async fn label(&self) -> zbus::fdo::Result<String> {
        let col = self
            .service
            .get_collection(&self.id)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(col.label)
    }

    #[zbus(property)]
    async fn set_label(&self, new_label: String) -> zbus::Result<()> {
        self.service
            .create_collection(&self.id, &new_label)
            .await
            .map_err(|e| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(e.to_string()))))?;
        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> zbus::fdo::Result<bool> {
        Ok(self.service.is_locked().await)
    }

    #[zbus(property)]
    async fn created(&self) -> zbus::fdo::Result<u64> {
        Ok(0)
    }

    #[zbus(property)]
    async fn modified(&self) -> zbus::fdo::Result<u64> {
        Ok(0)
    }
}
