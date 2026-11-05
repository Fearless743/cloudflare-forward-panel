use std::fs;
use std::path::Path;

/// rust-embed 在编译期要求 `frontend/dist` 目录存在。
/// 这里在干净 checkout 上自动生成一个占位 index.html，避免必须先构建前端才能编译后端。
fn main() {
    let dist = Path::new("frontend/dist");
    if !dist.exists() {
        let _ = fs::create_dir_all(dist);
    }

    let index = dist.join("index.html");
    if !index.exists() {
        let _ = fs::write(
            &index,
            "<!doctype html>\n<html lang=\"zh-CN\">\n<head><meta charset=\"UTF-8\" /><title>Cloudflare 转发面板</title></head>\n<body><p>前端静态资源尚未构建。请在 frontend/ 目录执行 <code>bun run build</code>，再重新执行 <code>make build</code>。</p></body>\n</html>\n",
        );
    }

    // 前端产物变化时重新编译，确保 rust-embed 内嵌的是最新资源。
    println!("cargo:rerun-if-changed=frontend/dist");
}
