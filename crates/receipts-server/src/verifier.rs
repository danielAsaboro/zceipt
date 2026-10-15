//! The browser verifier, built into the server at `/verify/`, so one `receipts serve` (or
//! `receipts demo`) gives payers and payees the page as well as the API. The files are the same
//! ones `scripts/build-web.sh` produces; verification still runs entirely in the browser.

use axum::{
    extract::Path,
    http::{header, StatusCode},
    response::{IntoResponse, Redirect, Response},
};

macro_rules! file {
    ($p:literal) => {
        include_bytes!(concat!("../../../", $p)) as &'static [u8]
    };
}

const FILES: &[(&str, &str, &[u8])] = &[
    ("", "text/html; charset=utf-8", file!("web/index.html")),
    ("index.html", "text/html; charset=utf-8", file!("web/index.html")),
    ("embed.html", "text/html; charset=utf-8", file!("web/embed.html")),
    ("app.js", "text/javascript", file!("web/app.js")),
    ("worker.js", "text/javascript", file!("web/worker.js")),
    ("zcash-receipts/index.js", "text/javascript", file!("packages/zcash-receipts/index.js")),
    ("zcash-receipts/grpc.js", "text/javascript", file!("packages/zcash-receipts/grpc.js")),
    ("zcash-receipts/widget.js", "text/javascript", file!("packages/zcash-receipts/widget.js")),
    ("zcash-receipts/worker.js", "text/javascript", file!("packages/zcash-receipts/worker.js")),
    ("zcash-receipts/background.js", "text/javascript", file!("packages/zcash-receipts/background.js")),
    ("zcash-receipts/pkg/receipts_wasm.js", "text/javascript", file!("packages/zcash-receipts/pkg/receipts_wasm.js")),
    ("zcash-receipts/pkg/receipts_wasm_bg.wasm", "application/wasm", file!("packages/zcash-receipts/pkg/receipts_wasm_bg.wasm")),
];

pub async fn root() -> Redirect {
    Redirect::permanent("/verify/")
}

pub async fn index() -> Response {
    serve("")
}

pub async fn file(Path(path): Path<String>) -> Response {
    serve(&path)
}

fn serve(path: &str) -> Response {
    match FILES.iter().find(|(p, _, _)| *p == path) {
        Some((_, ct, body)) => ([(header::CONTENT_TYPE, *ct), (header::CACHE_CONTROL, "no-cache")], *body).into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}
