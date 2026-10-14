//! `receipts mcp`: a Model Context Protocol server over stdio (newline-delimited JSON-RPC).
//!
//! Lets an AI agent (Claude, Cursor, …) verify receipts and run proof requests against a
//! Receipts API. Configure it like any stdio MCP server:
//!
//! ```json
//! { "mcpServers": { "receipts": { "command": "receipts", "args": ["mcp"],
//!   "env": { "RECEIPTS_KEY": "rcpt_test_…", "RECEIPTS_URL": "http://127.0.0.1:8723" } } } }
//! ```

use receipts_client::{Client, CreateRequest, VerifyParams};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const PROTOCOL: &str = "2025-06-18";

fn tools() -> Value {
    json!([
        {
            "name": "verify_receipt",
            "description": "Verify a Zcash payment receipt (zrcpt1…, a zrcptb1… batch, or a link containing one) against the chain. Returns who was paid, how much, the memo, the block, and whether the sender proved spend authority. Optionally require a payee, a minimum amount and a challenge. With a test key, sandbox fixtures like zrcpt_test_valid work too.",
            "inputSchema": { "type": "object", "required": ["receipt"], "properties": {
                "receipt": { "type": "string" },
                "expect_address": { "type": "string", "description": "Unified address that must have been paid" },
                "min_zatoshis": { "type": "integer", "description": "Minimum paid to expect_address (1 ZEC = 100000000)" },
                "challenge": { "type": "string", "description": "Challenge the receipt must sign" } } }
        },
        {
            "name": "create_proof_request",
            "description": "Ask someone to prove they paid you. Returns a ZIP-321 payment URI, a receipt_link to send to the payer, and the CLI command they run.",
            "inputSchema": { "type": "object", "required": ["payee"], "properties": {
                "payee": { "type": "string", "description": "Your unified address" },
                "amount_zatoshis": { "type": "integer" },
                "label": { "type": "string" } } }
        },
        {
            "name": "get_proof_request",
            "description": "Get a proof request's status (open, fulfilled, expired) and, if fulfilled, the verified payment.",
            "inputSchema": { "type": "object", "required": ["id"], "properties": { "id": { "type": "string" } } }
        },
        {
            "name": "submit_receipt",
            "description": "Submit the payer's receipt for a proof request. Fulfills it if the receipt signs the request's challenge and paid the payee at least the amount.",
            "inputSchema": { "type": "object", "required": ["id", "receipt"], "properties": { "id": { "type": "string" }, "receipt": { "type": "string" } } }
        }
    ])
}

async fn call(client: &Client, name: &str, args: &Value) -> Result<Value, String> {
    let s = |k: &str| args[k].as_str().map(str::to_string);
    let r = match name {
        "verify_receipt" => {
            client
                .verify(&VerifyParams {
                    receipt: s("receipt").ok_or("receipt is required")?,
                    expect_address: s("expect_address"),
                    min_zatoshis: args["min_zatoshis"].as_u64(),
                    challenge: s("challenge"),
                })
                .await
        }
        "create_proof_request" => {
            client
                .create_request(&CreateRequest {
                    payee: s("payee").ok_or("payee is required")?,
                    amount_zatoshis: args["amount_zatoshis"].as_u64(),
                    label: s("label"),
                    ..Default::default()
                })
                .await
        }
        "get_proof_request" => client.get_request(&s("id").ok_or("id is required")?).await,
        "submit_receipt" => client.submit_receipt(&s("id").ok_or("id is required")?, &s("receipt").ok_or("receipt is required")?).await,
        other => return Err(format!("unknown tool {other}")),
    };
    r.map_err(|e| match e.code() {
        Some(code) => format!("{code}: {e}"),
        None => e.to_string(),
    })
}

pub async fn run(api_key: String, base_url: String) -> anyhow::Result<()> {
    let client = Client::new(api_key).base_url(base_url);
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        let Ok(msg) = serde_json::from_str::<Value>(&line) else { continue };
        let Some(id) = msg.get("id").cloned() else { continue }; // notifications need no reply
        let result = match msg["method"].as_str().unwrap_or("") {
            "initialize" => Ok(json!({
                "protocolVersion": msg["params"]["protocolVersion"].as_str().unwrap_or(PROTOCOL),
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "receipts", "version": env!("CARGO_PKG_VERSION") },
                "instructions": "Receipts verifies shielded Zcash payments without viewing keys. Use verify_receipt for any zrcpt1/zrcptb1 string or link; create_proof_request + submit_receipt to ask someone to prove a payment."
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": tools() })),
            "tools/call" => {
                let p = &msg["params"];
                Ok(match call(&client, p["name"].as_str().unwrap_or(""), &p["arguments"]).await {
                    Ok(v) => json!({ "content": [{ "type": "text", "text": serde_json::to_string_pretty(&v)? }], "structuredContent": v }),
                    Err(e) => json!({ "content": [{ "type": "text", "text": e }], "isError": true }),
                })
            }
            m => Err(json!({ "code": -32601, "message": format!("method not found: {m}") })),
        };
        let reply = match result {
            Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
            Err(e) => json!({ "jsonrpc": "2.0", "id": id, "error": e }),
        };
        out.write_all(format!("{reply}\n").as_bytes()).await?;
        out.flush().await?;
    }
    Ok(())
}
