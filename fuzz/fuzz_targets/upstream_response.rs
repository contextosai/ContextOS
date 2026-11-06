//! What an upstream MCP server sends back, which the gateway does not control: a JSON
//! or server-sent-event body. The first byte picks the content type.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&pick, body)) = data.split_first() else {
        return;
    };
    let content_type = if pick % 2 == 0 {
        "application/json"
    } else {
        "text/event-stream"
    };
    if let Some(response) = contextos_adapters::mcp::fuzz_rpc_response(content_type, body, "1", 1 << 20) {
        assert_eq!(response["id"], "1");
        assert!(response.get("result").is_some() ^ response.get("error").is_some());
    }
});
