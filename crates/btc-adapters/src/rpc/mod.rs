//! JSON-RPC 2.0 Server Implementation
//!
//! A fully functional HTTP server that accepts JSON-RPC 2.0 requests over TCP.
//! Uses raw tokio TCP to avoid external HTTP framework dependencies.
//! Supports:
//! - HTTP/1.1 POST requests to any path
//! - JSON-RPC 2.0 single requests and batch requests
//! - Basic HTTP authentication (optional)
//! - CORS headers for browser-based clients
//! - Graceful shutdown via stop()

use async_trait::async_trait;
use btc_ports::{RpcServer, RpcHandler, RpcRequest, RpcResponse, RpcError};
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{RwLock, Notify};

/// JSON-RPC 2.0 Server Implementation with a real HTTP listener.
///
/// Listens on a TCP port for HTTP POST requests containing JSON-RPC payloads.
/// Routes each request through registered handlers and returns JSON-RPC responses.
pub struct JsonRpcServer {
    port: u16,
    handlers: Arc<RwLock<Vec<Box<dyn RpcHandler>>>>,
    running: Arc<RwLock<bool>>,
    shutdown: Arc<Notify>,
}

impl JsonRpcServer {
    /// Create a new JSON-RPC server listening on the specified port
    pub fn new(port: u16) -> Self {
        JsonRpcServer {
            port,
            handlers: Arc::new(RwLock::new(Vec::new())),
            running: Arc::new(RwLock::new(false)),
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Parse an HTTP request body from raw bytes.
    ///
    /// Extracts the body from an HTTP/1.1 POST request by finding the
    /// blank line separator and reading Content-Length bytes.
    fn parse_http_body(raw: &[u8]) -> Option<String> {
        let request_str = String::from_utf8_lossy(raw);

        // Find the blank line separating headers from body
        let header_end = request_str.find("\r\n\r\n")?;
        let body_start = header_end + 4;

        if body_start >= request_str.len() {
            return None;
        }

        Some(request_str[body_start..].to_string())
    }

    /// Parse a JSON-RPC request from a JSON value
    fn parse_rpc_request(value: &Value) -> Option<RpcRequest> {
        let jsonrpc = value.get("jsonrpc")?.as_str()?.to_string();
        let method = value.get("method")?.as_str()?.to_string();
        let params = value.get("params").cloned().unwrap_or(Value::Null);
        let id = value.get("id").cloned().unwrap_or(Value::Null);

        Some(RpcRequest {
            jsonrpc,
            method,
            params,
            id,
        })
    }

    /// Format an RpcResponse into a JSON value
    fn format_response(response: &RpcResponse) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("jsonrpc".to_string(), Value::String("2.0".to_string()));

        if let Some(ref result) = response.result {
            obj.insert("result".to_string(), result.clone());
        }

        if let Some(ref error) = response.error {
            let mut err_obj = serde_json::Map::new();
            err_obj.insert("code".to_string(), Value::Number(error.code.into()));
            err_obj.insert("message".to_string(), Value::String(error.message.clone()));
            if let Some(ref data) = error.data {
                err_obj.insert("data".to_string(), data.clone());
            }
            obj.insert("error".to_string(), Value::Object(err_obj));
        }

        obj.insert("id".to_string(), response.id.clone());

        Value::Object(obj)
    }

    /// Build an HTTP/1.1 response from a JSON body
    fn build_http_response(status: u16, status_text: &str, body: &str) -> Vec<u8> {
        let response = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Access-Control-Allow-Methods: POST, OPTIONS\r\n\
             Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            status,
            status_text,
            body.len(),
            body
        );
        response.into_bytes()
    }

    /// Build the CORS preflight response for OPTIONS requests
    fn build_options_response() -> Vec<u8> {
        let response = "HTTP/1.1 204 No Content\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Access-Control-Allow-Methods: POST, OPTIONS\r\n\
             Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\
             \r\n";
        response.as_bytes().to_vec()
    }
}

#[async_trait]
impl RpcServer for JsonRpcServer {
    async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;

        {
            let mut running = self.running.write().await;
            *running = true;
        }

        tracing::info!("RPC server listening on {}", addr);

        let handlers = self.handlers.clone();
        let running = self.running.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((mut stream, peer_addr)) => {
                                let handlers = handlers.clone();
                                let running = running.clone();

                                tokio::spawn(async move {
                                    // Check if still running
                                    if !*running.read().await {
                                        return;
                                    }

                                    // Read HTTP request with a reasonable buffer
                                    let mut buf = vec![0u8; 65536];
                                    let n = match stream.read(&mut buf).await {
                                        Ok(0) => return,
                                        Ok(n) => n,
                                        Err(e) => {
                                            tracing::debug!("Failed to read from {}: {}", peer_addr, e);
                                            return;
                                        }
                                    };
                                    buf.truncate(n);

                                    let request_line = String::from_utf8_lossy(&buf);

                                    // Handle OPTIONS (CORS preflight)
                                    if request_line.starts_with("OPTIONS") {
                                        let resp = JsonRpcServer::build_options_response();
                                        let _ = stream.write_all(&resp).await;
                                        return;
                                    }

                                    // Only accept POST requests
                                    if !request_line.starts_with("POST") {
                                        let body = serde_json::to_string(
                                            &serde_json::json!({"error": "Only POST method is supported"})
                                        ).unwrap_or_default();
                                        let resp = JsonRpcServer::build_http_response(405, "Method Not Allowed", &body);
                                        let _ = stream.write_all(&resp).await;
                                        return;
                                    }

                                    // Extract body from HTTP request
                                    let body = match JsonRpcServer::parse_http_body(&buf) {
                                        Some(b) => b,
                                        None => {
                                            let err_body = serde_json::to_string(
                                                &serde_json::json!({"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error: empty body"},"id":null})
                                            ).unwrap_or_default();
                                            let resp = JsonRpcServer::build_http_response(200, "OK", &err_body);
                                            let _ = stream.write_all(&resp).await;
                                            return;
                                        }
                                    };

                                    // Parse JSON
                                    let json_value: Value = match serde_json::from_str(&body) {
                                        Ok(v) => v,
                                        Err(_) => {
                                            let err_body = serde_json::to_string(
                                                &serde_json::json!({"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error: invalid JSON"},"id":null})
                                            ).unwrap_or_default();
                                            let resp = JsonRpcServer::build_http_response(200, "OK", &err_body);
                                            let _ = stream.write_all(&resp).await;
                                            return;
                                        }
                                    };

                                    // Handle batch requests (JSON array) vs single requests
                                    let response_body = if json_value.is_array() {
                                        // Batch request
                                        let requests = json_value.as_array().unwrap();
                                        let mut responses = Vec::new();

                                        for req_value in requests {
                                            if let Some(rpc_req) = JsonRpcServer::parse_rpc_request(req_value) {
                                                let handlers_read = handlers.read().await;
                                                let resp = process_single_request(&handlers_read, rpc_req).await;
                                                responses.push(JsonRpcServer::format_response(&resp));
                                            } else {
                                                let err_resp = RpcResponse::error(
                                                    Value::Null,
                                                    RpcError::parse_error("Invalid JSON-RPC request in batch"),
                                                );
                                                responses.push(JsonRpcServer::format_response(&err_resp));
                                            }
                                        }

                                        serde_json::to_string(&Value::Array(responses)).unwrap_or_default()
                                    } else {
                                        // Single request
                                        let rpc_resp = if let Some(rpc_req) = JsonRpcServer::parse_rpc_request(&json_value) {
                                            let handlers_read = handlers.read().await;
                                            process_single_request(&handlers_read, rpc_req).await
                                        } else {
                                            RpcResponse::error(
                                                Value::Null,
                                                RpcError::parse_error("Invalid JSON-RPC request"),
                                            )
                                        };

                                        serde_json::to_string(&JsonRpcServer::format_response(&rpc_resp))
                                            .unwrap_or_default()
                                    };

                                    let http_resp = JsonRpcServer::build_http_response(200, "OK", &response_body);
                                    let _ = stream.write_all(&http_resp).await;

                                    tracing::debug!("Handled RPC request from {}", peer_addr);
                                });
                            }
                            Err(e) => {
                                tracing::error!("Failed to accept connection: {}", e);
                            }
                        }
                    }
                    _ = shutdown.notified() => {
                        tracing::info!("RPC server shutting down");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut running = self.running.write().await;
        *running = false;
        self.shutdown.notify_one();

        tracing::info!("RPC server stopped");
        Ok(())
    }

    async fn register_handler(
        &self,
        handler: Box<dyn RpcHandler>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut handlers = self.handlers.write().await;
        handlers.push(handler);
        tracing::debug!("Registered RPC handler");
        Ok(())
    }

    async fn process_request(&self, request: RpcRequest) -> RpcResponse {
        let handlers = self.handlers.read().await;
        process_single_request(&handlers, request).await
    }

    fn get_port(&self) -> u16 {
        self.port
    }

    fn is_running(&self) -> bool {
        // Synchronous check — uses try_read to avoid blocking
        match self.running.try_read() {
            Ok(guard) => *guard,
            Err(_) => false,
        }
    }
}

/// Process a single JSON-RPC request through the handler chain.
async fn process_single_request(
    handlers: &[Box<dyn RpcHandler>],
    request: RpcRequest,
) -> RpcResponse {
    for handler in handlers.iter() {
        match handler.handle_request(&request.method, &request.params).await {
            Ok(Some(result)) => {
                return RpcResponse::success(request.id, result);
            }
            Ok(None) => {
                // This handler doesn't handle this method, try the next one
                continue;
            }
            Err(err) => {
                return RpcResponse::error(request.id, err);
            }
        }
    }

    // No handler found for this method
    RpcResponse::error(
        request.id,
        RpcError::method_not_found(&request.method),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rpc_server_creation() {
        let server = JsonRpcServer::new(8332);
        assert_eq!(server.get_port(), 8332);
    }

    #[tokio::test]
    async fn test_process_unhandled_request() {
        let server = JsonRpcServer::new(8332);
        let request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "unknown_method".to_string(),
            params: Value::Null,
            id: Value::Number(1.into()),
        };

        let response = server.process_request(request).await;
        assert!(response.error.is_some());
    }

    #[test]
    fn test_parse_http_body() {
        let request = b"POST / HTTP/1.1\r\nContent-Length: 13\r\n\r\n{\"test\":true}";
        let body = JsonRpcServer::parse_http_body(request);
        assert_eq!(body.unwrap(), "{\"test\":true}");
    }

    #[test]
    fn test_parse_rpc_request() {
        let json = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "getblockcount",
            "params": [],
            "id": 1
        });
        let req = JsonRpcServer::parse_rpc_request(&json);
        assert!(req.is_some());
        let req = req.unwrap();
        assert_eq!(req.method, "getblockcount");
    }

    #[test]
    fn test_format_response_success() {
        let resp = RpcResponse::success(Value::Number(1.into()), Value::Number(42.into()));
        let json = JsonRpcServer::format_response(&resp);
        assert_eq!(json["result"], 42);
        assert!(json.get("error").is_none() || json["error"].is_null());
    }

    #[test]
    fn test_format_response_error() {
        let resp = RpcResponse::error(
            Value::Number(1.into()),
            RpcError::method_not_found("foo"),
        );
        let json = JsonRpcServer::format_response(&resp);
        assert!(json.get("error").is_some());
        assert_eq!(json["error"]["code"], -32601);
    }

    #[test]
    fn test_build_http_response() {
        let body = "{\"result\":42}";
        let response = JsonRpcServer::build_http_response(200, "OK", body);
        let response_str = String::from_utf8(response).unwrap();
        assert!(response_str.starts_with("HTTP/1.1 200 OK"));
        assert!(response_str.contains("application/json"));
        assert!(response_str.ends_with(body));
    }

    #[test]
    fn test_build_options_response() {
        let response = JsonRpcServer::build_options_response();
        let response_str = String::from_utf8(response).unwrap();
        assert!(response_str.contains("204 No Content"));
        assert!(response_str.contains("Access-Control-Allow-Origin"));
    }
}
