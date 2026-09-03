use crate::session::Session;
use sigil_service::SigilService;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use zbus::interface;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

#[derive(serde::Serialize, serde::Deserialize, zbus::zvariant::Type)]
pub struct SecretStruct {
    pub session: OwnedObjectPath,
    pub parameters: Vec<u8>,
    pub value: Vec<u8>,
    pub content_type: String,
}

pub struct Item {
    pub collection_id: String,
    pub item_id: String,
    pub service: SigilService,
    pub sessions: Arc<RwLock<HashMap<OwnedObjectPath, Arc<Session>>>>,
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    async fn delete(&self) -> zbus::fdo::Result<ObjectPath<'_>> {
        self.service
            .delete_item(&self.collection_id, &self.item_id)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(ObjectPath::from_static_str("/").unwrap())
    }

    async fn get_secret(
        &self,
        session_path: OwnedObjectPath,
    ) -> zbus::fdo::Result<SecretStruct> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(&session_path)
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("Session not found".into()))?;

        let record = self
            .service
            .get_item(&self.collection_id, &self.item_id)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let (iv, enc_val) = session
            .encrypt(&record.secret)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok(SecretStruct {
            session: session_path,
            parameters: iv,
            value: enc_val,
            content_type: record.content_type,
        })
    }

    async fn set_secret(&self, secret: SecretStruct) -> zbus::fdo::Result<()> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(&secret.session)
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("Session not found".into()))?;

        let plain = session
            .decrypt(&secret.parameters, &secret.value)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let current = self
            .service
            .get_item(&self.collection_id, &self.item_id)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        self.service
            .set_item(
                &self.collection_id,
                &self.item_id,
                &current.label,
                current.attributes,
                &plain,
                &secret.content_type,
                true,
            )
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> zbus::fdo::Result<bool> {
        Ok(self.service.is_locked().await)
    }

    #[zbus(property)]
    async fn label(&self) -> zbus::fdo::Result<String> {
        let record = self
            .service
            .get_item(&self.collection_id, &self.item_id)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(record.label)
    }

    #[zbus(property)]
    async fn set_label(&self, new_label: String) -> zbus::Result<()> {
        let record = self
            .service
            .get_item(&self.collection_id, &self.item_id)
            .await
            .map_err(|e| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(e.to_string()))))?;

        self.service
            .set_item(
                &self.collection_id,
                &self.item_id,
                &new_label,
                record.attributes,
                &record.secret,
                &record.content_type,
                true,
            )
            .await
            .map_err(|e| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(e.to_string()))))?;
        Ok(())
    }

    #[zbus(property)]
    async fn attributes(&self) -> zbus::fdo::Result<HashMap<String, String>> {
        let record = self
            .service
            .get_item(&self.collection_id, &self.item_id)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(record.attributes)
    }

    #[zbus(property)]
    async fn set_attributes(&self, new_attrs: HashMap<String, String>) -> zbus::Result<()> {
        let record = self
            .service
            .get_item(&self.collection_id, &self.item_id)
            .await
            .map_err(|e| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(e.to_string()))))?;

        self.service
            .set_item(
                &self.collection_id,
                &self.item_id,
                &record.label,
                new_attrs,
                &record.secret,
                &record.content_type,
                true,
            )
            .await
            .map_err(|e| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(e.to_string()))))?;
        Ok(())
    }

    #[zbus(property)]
    async fn created(&self) -> zbus::fdo::Result<u64> {
        let record = self
            .service
            .get_item(&self.collection_id, &self.item_id)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(record.created_at)
    }

    #[zbus(property)]
    async fn modified(&self) -> zbus::fdo::Result<u64> {
        let record = self
            .service
            .get_item(&self.collection_id, &self.item_id)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(record.modified_at)
    }
}
