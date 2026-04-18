use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct PromptResponse {
    pub password: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prompt_response_roundtrip() {
        let resp = PromptResponse {
            password: Some("test-password".into()),
        };
        let s = serde_json::to_string(&resp).unwrap();
        let d: PromptResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(resp.password, d.password);
    }

    #[test]
    fn test_prompt_response_none() {
        let resp = PromptResponse { password: None };
        let s = serde_json::to_string(&resp).unwrap();
        let d: PromptResponse = serde_json::from_str(&s).unwrap();
        assert!(d.password.is_none());
    }
}
