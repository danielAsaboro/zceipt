//! The browser verifier, built into the server at `/verify/`, so one `zceipt serve` (or
//! `zceipt demo`) gives payers and payees the page as well as the API. The files are the same
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
    ("samples.js", "text/javascript", file!("web/samples.js")),
    ("cipher.js", "text/javascript", file!("web/cipher.js")),
    ("zceipt.css", "text/css; charset=utf-8", file!("web/zceipt.css")),
    ("worker.js", "text/javascript", file!("web/worker.js")),
    ("make.html", "text/html; charset=utf-8", file!("web/make.html")),
    ("make.js", "text/javascript", file!("web/make.js")),
    ("make-worker.js", "text/javascript", file!("web/make-worker.js")),
    ("zceipt/maker.js", "text/javascript", file!("packages/zceipt/maker.js")),
    ("zceipt/index.js", "text/javascript", file!("packages/zceipt/index.js")),
    ("zceipt/grpc.js", "text/javascript", file!("packages/zceipt/grpc.js")),
    ("zceipt/widget.js", "text/javascript", file!("packages/zceipt/widget.js")),
    ("zceipt/worker.js", "text/javascript", file!("packages/zceipt/worker.js")),
    ("zceipt/background.js", "text/javascript", file!("packages/zceipt/background.js")),
    ("zceipt/pkg/zceipt_wasm.js", "text/javascript", file!("packages/zceipt/pkg/zceipt_wasm.js")),
    ("zceipt/pkg/zceipt_wasm_bg.wasm", "application/wasm", file!("packages/zceipt/pkg/zceipt_wasm_bg.wasm")),
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
