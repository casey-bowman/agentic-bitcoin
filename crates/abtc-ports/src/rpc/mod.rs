//! RPC Port Definitions
//!
//! This module defines the port traits for JSON-RPC 2.0 server functionality.
//! Implementations provide HTTP/WebSocket endpoints for external clients.

use serde_json::Value;
use std::error::Error;

/// An RPC request following JSON-RPC 2.0 specification.
#[derive(Clone, Debug)]
pub struct RpcRequest {
    /// JSON-RPC version (always "2.0")
    pub jsonrpc: String,
    /// The method name to call
    pub method: String,
    /// Method parameters (usually an object or array)
    pub params: Value,
    /// Request ID (for matching responses to requests)
    pub id: Value,
}

/// An RPC response following JSON-RPC 2.0 specification.
#[derive(Clone, Debug)]
pub struct RpcResponse {
    /// JSON-RPC version (always "2.0")
    pub jsonrpc: String,
    /// The result of successful calls
    pub result: Option<Value>,
    /// Error if the call failed
    pub error: Option<RpcError>,
    /// Request ID (matches the request that triggered this response)
    pub id: Value,
}

impl RpcResponse {
    /// Creates a successful RPC response.
    pub fn success(id: Value, result: Value) -> Self {
        RpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Creates an error RPC response.
    pub fn error(id: Value, error: RpcError) -> Self {
        RpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

/// RPC error following JSON-RPC 2.0 specification.
#[derive(Clone, Debug)]
pub struct RpcError {
    /// Error code (typically -32000 to -32768 for RPC errors)
    pub code: i32,
    /// Human-readable error message
    pub message: String,
    /// Optional additional error data
    pub data: Option<Value>,
}

impl RpcError {
    /// Creates a new RPC error.
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        RpcError {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Adds data to the error.
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    /// Invalid JSON-RPC request (code -32700)
    pub fn parse_error(msg: impl Into<String>) -> Self {
        RpcError::new(-32700, msg)
    }

    /// Invalid method name (code -32601)
    pub fn method_not_found(method: &str) -> Self {
        RpcError::new(-32601, format!("Method not found: {}", method))
    }

    /// Invalid method parameters (code -32602)
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        RpcError::new(-32602, msg)
    }

    /// Internal server error (code -32603)
    pub fn internal_error(msg: impl Into<String>) -> Self {
        RpcError::new(-32603, msg)
    }

    /// Server error (code -32000 to -32099)
    pub fn server_error(code: i32, msg: impl Into<String>) -> Self {
        let code = if code >= -32099 && code <= -32000 {
            code
        } else {
            -32000
        };
        RpcError::new(code, msg)
    }
}

/// Port trait for handling individual RPC method calls.
///
/// Multiple handlers can be registered, each handling a set of RPC methods.
#[async_trait::async_trait]
pub trait RpcHandler: Send + Sync {
    /// Handles an RPC method call.
    ///
    /// # Arguments
    ///
    /// * `method` - The RPC method name (e.g., "getblockcount")
    /// * `params` - The method parameters as a JSON value
    ///
    /// # Returns
    ///
    /// Returns `Some(response)` if this handler handles the method,
    /// `None` if another handler should try.
    async fn handle_request(&self, method: &str, params: &Value)
        -> Result<Option<Value>, RpcError>;
}

/// Port trait for the RPC server.
///
/// Implementations provide HTTP/WebSocket endpoints for JSON-RPC 2.0 clients.
#[async_trait::async_trait]
pub trait RpcServer: Send + Sync {
    /// Starts the RPC server.
    ///
    /// The server should listen on the configured address and port
    /// and accept JSON-RPC 2.0 requests.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the server started successfully.
    async fn start(&self) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Stops the RPC server.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the server stopped successfully.
    async fn stop(&self) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Registers an RPC handler for a set of methods.
    ///
    /// # Arguments
    ///
    /// * `handler` - The handler to register
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the handler was registered.
    async fn register_handler(
        &self,
        handler: Box<dyn RpcHandler>,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Processes an RPC request.
    ///
    /// This is the main entry point for processing JSON-RPC 2.0 requests.
    /// It routes the request to the appropriate handler and returns the response.
    ///
    /// # Arguments
    ///
    /// * `request` - The RPC request to process
    ///
    /// # Returns
    ///
    /// Returns the RPC response.
    async fn process_request(&self, request: RpcRequest) -> RpcResponse;

    /// Gets the server's current port.
    ///
    /// # Returns
    ///
    /// Returns the port number the server is listening on.
    fn get_port(&self) -> u16;

    /// Checks if the server is running.
    ///
    /// # Returns
    ///
    /// Returns `true` if the server is currently running.
    fn is_running(&self) -> bool;
}

/// Common RPC error codes (JSON-RPC 2.0 spec and Bitcoin extensions)
pub mod rpc_errors {
    /// Parse error: Invalid JSON was received
    pub const PARSE_ERROR: i32 = -32700;
    /// Invalid Request: The JSON sent is not a valid Request object
    pub const INVALID_REQUEST: i32 = -32600;
    /// Method not found: The method does not exist or is not available
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// Invalid params: Invalid method parameter(s)
    pub const INVALID_PARAMS: i32 = -32602;
    /// Internal error
    pub const INTERNAL_ERROR: i32 = -32603;
    /// Server error (reserved for implementation-defined server errors)
    pub const SERVER_ERROR: i32 = -32000;

    // Bitcoin-specific RPC error codes
    /// Miscellaneous error
    pub const MISC_ERROR: i32 = -1;
    /// Type error
    pub const TYPE_ERROR: i32 = -3;
    /// Invalid address or key
    pub const INVALID_ADDRESS_OR_KEY: i32 = -5;
    /// Out of memory
    pub const OUT_OF_MEMORY: i32 = -7;
    /// Invalid parameter
    pub const INVALID_PARAMETER: i32 = -8;
    /// Database error
    pub const DATABASE_ERROR: i32 = -20;
    /// Deserialization error
    pub const DESERIALIZATION_ERROR: i32 = -22;
    /// Verify error
    pub const VERIFY_ERROR: i32 = -25;
    /// Verify rejected
    pub const VERIFY_REJECTED: i32 = -26;
    /// Verify already in chain
    pub const VERIFY_ALREADY_IN_CHAIN: i32 = -27;
    /// In warmup
    pub const IN_WARMUP: i32 = -28;
    /// RPC in warmup
    pub const RPC_IN_WARMUP: i32 = -32603;
}

/// Helper functions for common RPC operations
pub mod rpc_helpers {
    use serde_json::Value;

    /// Converts a JSON value to a string, or returns an error.
    pub fn to_string(value: &Value) -> Result<String, String> {
        value
            .as_str()
            .ok_or_else(|| "Expected string".to_string())
            .map(|s| s.to_string())
    }

    /// Converts a JSON value to an i64, or returns an error.
    pub fn to_i64(value: &Value) -> Result<i64, String> {
        value.as_i64().ok_or_else(|| "Expected integer".to_string())
    }

    /// Converts a JSON value to a u32, or returns an error.
    pub fn to_u32(value: &Value) -> Result<u32, String> {
        to_i64(value)
            .and_then(|v| u32::try_from(v).map_err(|_| "Value out of range for u32".to_string()))
    }

    /// Converts a JSON value to a bool, or returns an error.
    pub fn to_bool(value: &Value) -> Result<bool, String> {
        value
            .as_bool()
            .ok_or_else(|| "Expected boolean".to_string())
    }

    /// Converts a JSON value to an array, or returns an error.
    pub fn to_array(value: &Value) -> Result<Vec<Value>, String> {
        value
            .as_array()
            .ok_or_else(|| "Expected array".to_string())
            .map(|a| a.clone())
    }

    /// Converts a JSON value to an object, or returns an error.
    pub fn to_object(value: &Value) -> Result<serde_json::Map<String, Value>, String> {
        value
            .as_object()
            .ok_or_else(|| "Expected object".to_string())
            .map(|o| o.clone())
    }
}
