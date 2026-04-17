use crate::error::WssDaemonError;
use crate::state::{build_collections, State};
use crate::vault::{Vault, VaultData};
use rand::rngs::OsRng;
use rand::RngCore;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};
use zbus::interface;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

pub struct Service {
    state: Arc<RwLock<State>>,
}

impl Service {
    pub fn new(state: Arc<RwLock<State>>) -> Self {
        Self { state }
    }
}

fn generate_id() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    async fn open_session(
        &self,
        algorithm: &str,
        input: zbus::zvariant::Value<'_>,
    ) -> std::result::Result<(zbus::zvariant::Value<'static>, OwnedObjectPath), zbus::fdo::Error>
    {
        info!("OpenSession: algorithm={}", algorithm);

        let (result_val, algo) = match algorithm {
            "plain" => (
                zbus::zvariant::Value::from(""),
                crate::session::SessionAlgorithm::Plain,
            ),
            "dh-ietf1024-sha256-aes128-cbc-pkcs7" => {
                let client_pub: Vec<u8> = input
                    .try_into()
                    .map_err(|_| WssDaemonError::InvalidArgs("Invalid DH input".into()))?;
                let (server_pub, sym_key) =
                    crate::session::calculate_dh_shared_secret(&client_pub)
                        .map_err(|e| WssDaemonError::InvalidArgs(e.to_string()))?;
                (
                    zbus::zvariant::Value::from(server_pub),
                    crate::session::SessionAlgorithm::Dh(sym_key),
                )
            }
            _ => return Err(WssDaemonError::InvalidArgs("Unsupported algorithm".into()).into()),
        };

        let session_path = OwnedObjectPath::try_from(format!(
            "/org/freedesktop/secrets/session/s{}",
            generate_id()
        ))
        .map_err(|e| WssDaemonError::InvalidArgs(e.to_string()))?;

        let session = Arc::new(crate::session::Session {
            id: session_path.clone(),
            algorithm: algo,
        });
        self.state
            .write()
            .await
            .sessions
            .insert(session_path.clone(), session);

        Ok((result_val, session_path))
    }

    async fn create_collection(
        &self,
        #[zbus(object_server)] server: &zbus::ObjectServer,
        _properties: std::collections::HashMap<&str, zbus::zvariant::Value<'_>>,
        alias: &str,
    ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        info!("CreateCollection: alias={}", alias);

        let col_id = if alias.is_empty() {
            format!("c{}", generate_id())
        } else {
            alias.to_string()
        };
        let col_path_str = format!("/org/freedesktop/secrets/collection/{}", col_id);
        let col_path = OwnedObjectPath::try_from(col_path_str.clone())
            .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;

        let mut state = self.state.write().await;
        if !state.collections.contains_key(&col_id) {
            let col = crate::collection::Collection {
                id: col_id.clone(),
                label: Arc::new(RwLock::new("New Collection".into())),
                items: Arc::new(RwLock::new(std::collections::HashMap::new())),
                is_deleted: Arc::new(RwLock::new(false)),
                state: self.state.clone(),
            };
            state.collections.insert(col_id.clone(), col.clone());
            drop(state);
            if let Err(e) = server.at(col_path_str, col).await {
                error!("Failed to register collection on D-Bus: {}", e);
            }
        }

        Ok((col_path, OwnedObjectPath::try_from("/").unwrap()))
    }

    async fn search_items(
        &self,
        attributes: std::collections::HashMap<&str, &str>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        let state = self.state.read().await;
        let mut matched = Vec::new();

        for (col_id, col) in state.collections.iter() {
            if *col.is_deleted.read().await {
                continue;
            }
            for (item_id, item) in col.items.read().await.iter() {
                if *item.is_deleted.read().await {
                    continue;
                }
                let item_attrs = item.attributes.read().await;
                let matches = attributes
                    .iter()
                    .all(|(k, v)| item_attrs.get(*k).map(String::as_str) == Some(*v));
                if matches {
                    if let Ok(p) = OwnedObjectPath::try_from(format!(
                        "/org/freedesktop/secrets/collection/{}/{}",
                        col_id, item_id
                    )) {
                        matched.push(p);
                    }
                }
            }
        }

        Ok((matched.clone(), matched))
    }

    async fn unlock(
        &self,
        #[zbus(object_server)] server: &zbus::ObjectServer,
        #[zbus(connection)] conn: &zbus::Connection,
        objects: Vec<ObjectPath<'_>>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        info!("Unlock called for {} objects", objects.len());

        // Atomically check state and claim the unlock slot
        let prompt_id = {
            let mut state = self.state.write().await;

            if state.is_unlocked {
                let unlocked = objects
                    .iter()
                    .map(|o| OwnedObjectPath::from(o.clone()))
                    .collect();
                return Ok((unlocked, OwnedObjectPath::try_from("/").unwrap()));
            }
            if state.is_unlocking {
                return Ok((
                    vec![],
                    OwnedObjectPath::try_from("/org/freedesktop/secrets/prompt/pending").unwrap(),
                ));
            }

            state.is_unlocking = true;
            generate_id()
        };

        let prompt_path = OwnedObjectPath::try_from(format!(
            "/org/freedesktop/secrets/prompt/p{}",
            prompt_id
        ))
        .map_err(|e| WssDaemonError::InvalidArgs(e.to_string()))?;

        let prompt = crate::prompt::Prompt {
            id: prompt_path.as_str().to_string(),
        };
        server
            .at(prompt_path.clone(), prompt)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        let state_clone = self.state.clone();
        let conn_clone = conn.clone();
        let prompt_path_clone = prompt_path.clone();
        let objects_to_unlock: Vec<OwnedObjectPath> =
            objects.iter().map(|o| OwnedObjectPath::from(o.clone())).collect();

        tokio::spawn(async move {
            let (vault_path, salt_path, is_initial) = {
                let st = state_clone.read().await;
                (
                    st.vault_path.clone(),
                    st.salt_path.clone(),
                    !st.vault_path.exists(),
                )
            };

            let mut dismissed = true;

            if let Ok(password) = crate::ipc::request_password(is_initial)
                .await
                .map_err(|e| error!("Failed to get password: {}", e))
            {
                match load_vault(&password, &vault_path, &salt_path, is_initial) {
                    Ok((vault, data)) => {
                        let cols = build_collections(&data, state_clone.clone());
                        let server = conn_clone.object_server();
                        let mut st = state_clone.write().await;

                        for (col_id, col) in cols {
                            // Register items
                            for (item_id, item) in col.items.read().await.iter() {
                                if let Ok(p) = OwnedObjectPath::try_from(format!(
                                    "/org/freedesktop/secrets/collection/{}/{}",
                                    col_id, item_id
                                )) {
                                    let _ = server.at(p, item.clone()).await;
                                }
                            }
                            // Merge with or register collection
                            if let Some(existing) = st.collections.get(&col_id) {
                                *existing.label.write().await = col.label.read().await.clone();
                                *existing.items.write().await = col.items.read().await.clone();
                            } else {
                                if let Ok(p) = OwnedObjectPath::try_from(format!(
                                    "/org/freedesktop/secrets/collection/{}",
                                    col_id
                                )) {
                                    let _ = server.at(p, col.clone()).await;
                                }
                                st.collections.insert(col_id, col);
                            }
                        }

                        st.vault = Some(vault);
                        st.is_unlocked = true;
                        dismissed = false;
                        info!("Vault unlocked successfully.");
                    }
                    Err(e) => error!("Vault unlock failed: {}", e),
                }
            }

            {
                let mut st = state_clone.write().await;
                st.is_unlocking = false;
            }

            if let Ok(emitter) =
                zbus::object_server::SignalEmitter::new(&conn_clone, &prompt_path_clone)
            {
                let result = if dismissed {
                    zbus::zvariant::Value::from(zbus::zvariant::Array::from(
                        Vec::<OwnedObjectPath>::new(),
                    ))
                } else {
                    zbus::zvariant::Value::from(zbus::zvariant::Array::from(objects_to_unlock))
                };
                let _ = crate::prompt::Prompt::completed(&emitter, dismissed, result).await;
            }
        });

        Ok((vec![], prompt_path))
    }

    async fn lock(
        &self,
        _objects: Vec<ObjectPath<'_>>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        Ok((vec![], OwnedObjectPath::try_from("/").unwrap()))
    }

    async fn get_secrets(
        &self,
        items: Vec<ObjectPath<'_>>,
        session_path: ObjectPath<'_>,
    ) -> zbus::fdo::Result<
        std::collections::HashMap<OwnedObjectPath, (OwnedObjectPath, Vec<u8>, Vec<u8>, String)>,
    > {
        let state = self.state.read().await;
        let session = state
            .sessions
            .get(&OwnedObjectPath::from(session_path.clone()))
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("Invalid session".into()))?;

        let mut result = std::collections::HashMap::new();

        for item_path in &items {
            let path_str = item_path.as_str();
            let parts: Vec<&str> = path_str.split('/').collect();
            if parts.len() < 7 || parts[4] != "collection" {
                continue;
            }
            let (col_id, item_id) = (parts[5], parts[6]);

            let col = match state.collections.get(col_id) {
                Some(c) => c,
                None => continue,
            };
            if *col.is_deleted.read().await {
                continue;
            }

            let items_guard = col.items.read().await;
            let item = match items_guard.get(item_id) {
                Some(i) => i,
                None => continue,
            };
            if *item.is_deleted.read().await {
                continue;
            }

            let secret_raw = item.secret.read().await.clone();
            match session.encrypt(&secret_raw) {
                Ok((params, encrypted)) => {
                    if let Ok(p) = OwnedObjectPath::try_from(path_str.to_string()) {
                        result.insert(
                            p,
                            (
                                session_path.clone().into(),
                                params,
                                encrypted,
                                "text/plain".into(),
                            ),
                        );
                    }
                }
                Err(e) => error!("Failed to encrypt secret for {}: {}", path_str, e),
            }
        }

        Ok(result)
    }

    async fn read_alias(&self, alias: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        let state = self.state.read().await;
        let target = if alias == "default" && !state.collections.contains_key("default") {
            "login"
        } else {
            alias
        };
        if state.collections.contains_key(target) {
            OwnedObjectPath::try_from(format!(
                "/org/freedesktop/secrets/collection/{}",
                target
            ))
            .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))
        } else {
            Ok(OwnedObjectPath::try_from("/").unwrap())
        }
    }

    async fn set_alias(&self, _alias: &str, _collection: ObjectPath<'_>) -> zbus::fdo::Result<()> {
        Ok(())
    }

    #[zbus(property)]
    async fn collections(&self) -> Vec<OwnedObjectPath> {
        let state = self.state.read().await;
        let mut paths = Vec::new();
        for (id, col) in state.collections.iter() {
            if !*col.is_deleted.read().await {
                if let Ok(p) = OwnedObjectPath::try_from(format!(
                    "/org/freedesktop/secrets/collection/{}",
                    id
                )) {
                    paths.push(p);
                }
            }
        }
        paths
    }
}

/// Derive the vault key and load (or initialise) vault data.
/// On first run (`is_initial`), writes a fresh salt and returns empty data.
pub fn load_vault(
    password: &str,
    vault_path: &std::path::Path,
    salt_path: &std::path::Path,
    is_initial: bool,
) -> Result<(Vault, VaultData), Box<dyn std::error::Error + Send + Sync>> {
    if is_initial {
        let salt = Vault::generate_salt();
        std::fs::write(salt_path, &salt)?;
        let key = Vault::derive_key(password, &salt)?;
        let vault = Vault::new(vault_path.to_path_buf(), key);
        return Ok((vault, VaultData { collections: vec![] }));
    }

    let salt = std::fs::read_to_string(salt_path)?;
    let key = Vault::derive_key(password, salt.trim())?;
    let vault = Vault::new(vault_path.to_path_buf(), key);
    let data = vault.load()?;
    Ok((vault, data))
}
