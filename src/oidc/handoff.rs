const STYLE: &str = r#":root{color-scheme:light dark;--bg:#fafafa;--fg:#18181b;--muted:#71717a;--card:#fff;--well:#f4f4f5;--btn:#18181b;--btn-fg:#fafafa}
  @media (prefers-color-scheme:dark){:root{--bg:#09090b;--fg:#fafafa;--muted:#a1a1aa;--card:#18181b;--well:#27272a;--btn:#fafafa;--btn-fg:#18181b}}
  *{box-sizing:border-box}
  body{margin:0;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:1.5rem;background:var(--bg);color:var(--fg);font:16px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
  main{width:100%;max-width:26rem}
  .brand{display:flex;align-items:center;justify-content:center;gap:.625rem;margin-bottom:2rem}
  .brand img{display:block;width:28px;height:28px}
  .brand span{font-size:1.125rem;font-weight:650;letter-spacing:-.01em}
  .card{background:var(--card);border:0;border-radius:.75rem;padding:1.75rem;text-align:center}
  h1{margin:0;font-size:1.25rem;font-weight:650;letter-spacing:-.01em}
  p{margin:.5rem 0 0;font-size:.875rem;color:var(--muted)}
  .code{display:flex;align-items:center;gap:.5rem;margin-top:1.25rem}
  .code output{flex:1;min-width:0;padding:.75rem;border:0;border-radius:.5rem;background:var(--well);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:1.0625rem;letter-spacing:.15em;word-break:break-all}
  button{flex:none;height:2.75rem;padding:0 1rem;border:0;border-radius:.5rem;background:var(--btn);color:var(--btn-fg);font:inherit;font-size:.875rem;font-weight:500;cursor:pointer}
  button:hover{opacity:.9}
  .hint{margin-top:1.5rem;text-align:center;font-size:.8125rem;color:var(--muted)}"#;

const SCRIPT: &str = r#"const b=document.getElementById("b"),c=document.getElementById("c");
  b.addEventListener("click",async()=>{const t=c.textContent.trim();try{await navigator.clipboard.writeText(t)}catch{const s=document.createElement("textarea");s.value=t;document.body.append(s);s.select();document.execCommand("copy");s.remove()}b.textContent="Copied";setTimeout(()=>b.textContent="Copy",1600)});"#;

pub(crate) struct Page<'a> {
    pub(crate) app_name: &'a str,
    pub(crate) logo_url: &'a str,
    pub(crate) hint: &'a str,
    pub(crate) code: &'a str,
}

pub(crate) fn render(page: &Page<'_>) -> String {
    let logo = match page.logo_url {
        "" => String::new(),
        url => format!(r#"<img src="{}" alt="" onerror="this.remove()">"#, escape(url)),
    };
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<title>Signed in · {app}</title>\n<style>\n  {STYLE}\n</style>\n<main>\n  <div class=\"brand\">{logo}<span>{app}</span></div>\n  <div class=\"card\">\n    <h1>Signed in</h1>\n    <p>Paste this code into your terminal.</p>\n    <div class=\"code\"><output id=\"c\">{code}</output><button type=\"button\" id=\"b\">Copy</button></div>\n  </div>\n  <p class=\"hint\">{hint}</p>\n</main>\n<script>\n  {SCRIPT}\n</script>\n",
        app = escape(page.app_name),
        code = escape(page.code),
        hint = escape(page.hint),
    )
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&#34;").replace('\'', "&#39;")
}
