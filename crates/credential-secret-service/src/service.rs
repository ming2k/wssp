use crate::collection::Collection;
use crate::item::SecretStruct;
use crate::session::{Session, SessionAlgorithm};
use credential_crypto::DhSession;
use credential_service::CredentialService;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use zbus::interface;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

pub struct SecretServiceDbus {
    pub service: CredentialService,
    pub sessions: Arc<RwLock<HashMap<OwnedObjectPath, Arc<Session>>>>,
}

impl SecretServiceDbus {
    pub fn new(service: CredentialService) -> Self {
        Self {
            service,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl SecretServiceDbus {
    async fn open_session(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        algorithm: &str,
        input: Value<'_>,
    ) -> zbus::fdo::Result<(OwnedValue, OwnedObjectPath)> {
        let mut rng = OsRng;
        let session_id = format!("s_{}", rng.next_u64());
        let session_path = OwnedObjectPath::try_from(format!(
            "/org/freedesktop/secrets/session/{session_id}"
        ))
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let (output_val, session_algo) = match algorithm {
            "plain" => {
                let v = Value::from("");
                let ov = v.try_into_owned()
                    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
                (ov, SessionAlgorithm::Plain)
            }
            "dh-ietf1024-sha256-aes128-cbc-pkcs7" => {
                let peer_pub = match input {
                    Value::Array(a) => {
                        let mut bytes = Vec::new();
                        for v in a.iter() {
                            if let Value::U8(b) = v {
                                bytes.push(*b);
                            }
                        }
                        bytes
                    }
                    _ => return Err(zbus::fdo::Error::InvalidArgs("Expected array of bytes".into())),
                };

                let dh = DhSession::generate()
                    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
                let aes_key = dh
                    .derive_shared_key(&peer_pub)
                    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

                let out_bytes = Value::from(dh.public_key.clone());
                let ov = out_bytes.try_into_owned()
                    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
                (ov, SessionAlgorithm::Dh(aes_key))
            }
            _ => return Err(zbus::fdo::Error::NotSupported("Algorithm not supported".into())),
        };

        let session = Arc::new(Session {
            id: session_path.clone(),
            algorithm: session_algo,
        });

        self.sessions
            .write()
            .await
            .insert(session_path.clone(), session.clone());

        conn.object_server()
            .at(&session_path, (*session).clone())
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        info!("Created Secret Service Session: {:?}", session_path);
        Ok((output_val, session_path))
    }

    async fn create_collection(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        properties: HashMap<String, Value<'_>>,
        _alias: &str,
    ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        let label = properties
            .get("org.freedesktop.Secret.Collection.Label")
            .and_then(|v| match v {
                Value::Str(s) => Some(s.to_string()),
                _ => None,
            })
            .unwrap_or_else(|| "New Collection".into());

        let mut rng = OsRng;
        let col_id = format!("c_{}", rng.next_u64());
        self.service
            .create_collection(&col_id, &label)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let col_path = OwnedObjectPath::try_from(format!(
            "/org/freedesktop/secrets/collection/{col_id}"
        ))
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let col_obj = Collection {
            id: col_id,
            service: self.service.clone(),
            sessions: self.sessions.clone(),
        };

        let _ = conn.object_server().at(&col_path, col_obj).await;

        let prompt_path = OwnedObjectPath::try_from("/").unwrap();
        Ok((col_path, prompt_path))
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        let is_locked = self.service.is_locked().await;
        if is_locked {
            return Ok((Vec::new(), Vec::new()));
        }

        let matches = self
            .service
            .search_items(None, &attributes)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let mut unlocked = Vec::new();
        for (col_id, item_id) in matches {
            if let Ok(p) = OwnedObjectPath::try_from(format!(
                "/org/freedesktop/secrets/collection/{col_id}/{item_id}"
            )) {
                unlocked.push(p);
            }
        }

        Ok((unlocked, Vec::new()))
    }

    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let is_locked = self.service.is_locked().await;
        let prompt_path = OwnedObjectPath::try_from("/").unwrap();
        if !is_locked {
            return Ok((objects, prompt_path));
        }

        // If locked, in fully automatic mode we return empty unlocked list or prompt
        Ok((Vec::new(), prompt_path))
    }

    async fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let _ = self.service.lock().await;
        let prompt_path = OwnedObjectPath::try_from("/").unwrap();
        Ok((objects, prompt_path))
    }

    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session_path: OwnedObjectPath,
    ) -> zbus::fdo::Result<HashMap<OwnedObjectPath, SecretStruct>> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(&session_path)
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("Session not found".into()))?;

        let mut secrets = HashMap::new();
        for item_path in items {
            let path_str = item_path.as_str();
            let segments: Vec<&str> = path_str.trim_matches('/').split('/').collect();
            if segments.len() == 6 && segments[3] == "collection" {
                let col_id = segments[4];
                let item_id = segments[5];
                if let Ok(record) = self.service.get_item(col_id, item_id).await {
                    if let Ok((iv, enc_val)) = session.encrypt(&record.secret) {
                        secrets.insert(
                            item_path.clone(),
                            SecretStruct {
                                session: session_path.clone(),
                                parameters: iv,
                                value: enc_val,
                                content_type: record.content_type,
                            },
                        );
                    }
                }
            }
        }

        Ok(secrets)
    }

    async fn read_alias(&self, name: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        if name == "default" {
            Ok(OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/login").unwrap())
        } else {
            Ok(OwnedObjectPath::try_from("/").unwrap())
        }
    }

    async fn set_alias(&self, _name: &str, _collection: OwnedObjectPath) -> zbus::fdo::Result<()> {
        Ok(())
    }

    #[zbus(property)]
    async fn collections(&self) -> zbus::fdo::Result<Vec<OwnedObjectPath>> {
        let ids = self.service.get_collection_ids().await;
        let mut paths = Vec::new();
        for id in ids {
            if let Ok(p) = OwnedObjectPath::try_from(format!(
                "/org/freedesktop/secrets/collection/{id}"
            )) {
                paths.push(p);
            }
        }
        Ok(paths)
    }
}
