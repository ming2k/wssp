use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct DomainItem {
    pub id: String,
    pub label: Arc<RwLock<String>>,
    pub attributes: Arc<RwLock<HashMap<String, String>>>,
    pub secret: Arc<RwLock<Vec<u8>>>,
    pub is_deleted: Arc<RwLock<bool>>,
}

#[derive(Clone)]
pub struct DomainCollection {
    pub id: String,
    pub label: Arc<RwLock<String>>,
    pub items: Arc<RwLock<HashMap<String, DomainItem>>>,
    pub is_deleted: Arc<RwLock<bool>>,
}
