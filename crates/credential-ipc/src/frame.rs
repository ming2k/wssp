use crate::protocol::{IpcRequest, IpcResponse};
use credential_core::{CredentialError, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_FRAME_SIZE: usize = 64 * 1024; // 64 KB limit for safety

pub async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    req: &IpcRequest,
) -> Result<()> {
    let payload = serde_json::to_vec(req)
        .map_err(|e| CredentialError::Internal(format!("Serialization error: {e}")))?;

    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<IpcRequest> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > MAX_FRAME_SIZE {
        return Err(CredentialError::InvalidRequest("Frame size exceeds limit".into()));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;

    let req: IpcRequest = serde_json::from_slice(&buf)
        .map_err(|e| CredentialError::InvalidRequest(format!("Deserialization error: {e}")))?;

    Ok(req)
}

pub async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    resp: &IpcResponse,
) -> Result<()> {
    let payload = serde_json::to_vec(resp)
        .map_err(|e| CredentialError::Internal(format!("Serialization error: {e}")))?;

    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_response<R: AsyncRead + Unpin>(reader: &mut R) -> Result<IpcResponse> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > MAX_FRAME_SIZE {
        return Err(CredentialError::InvalidRequest("Frame size exceeds limit".into()));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;

    let resp: IpcResponse = serde_json::from_slice(&buf)
        .map_err(|e| CredentialError::InvalidRequest(format!("Deserialization error: {e}")))?;

    Ok(resp)
}
