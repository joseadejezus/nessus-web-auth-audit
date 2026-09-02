"""Self-contained interactive HTML report.

Produces one file that opens straight from disk (``file://``) with no
server, no CDN, and no network access of any kind: CSS and JS are
inline and screenshots are embedded as base64 data URIs. That makes the
report a single artifact you can hand to a client or attach to a
ticket.

Untrusted-data handling: every value in the report originates in scan
data we do not control (hostnames, URLs, plugin text, page text). The
report data is embedded as JSON with ``<``, ``>`` and ``&`` escaped to
their \\u form so it cannot break out of the <script> element, and the
UI is built entirely with createElement/textContent — no innerHTML is
ever given report data.
"""
from __future__ import annotations

import base64
import html
import json
import logging
import mimetypes
import os
from pathlib import Path

logger = logging.getLogger("nwaa.html_report")

# Beyond this, a screenshot is linked rather than inlined, so one huge
# capture cannot produce an unopenable report file.
MAX_EMBED_BYTES = 8 * 1024 * 1024


def build_html_report(
    report: dict, embed_screenshots: bool = True, base_dir: str | Path | None = None
) -> str:
    """Render the JSON report dict (from report.build_json_report) as HTML.

    ``base_dir`` is the directory the HTML will be written to; linked
    (non-embedded) screenshots are made relative to it so the report
    stays portable alongside its screenshots folder.
    """
    payload = dict(report)
    payload["screenshots"] = [
        _augment_screenshot(shot, embed_screenshots, base_dir)
        for shot in report.get("screenshots", [])
    ]

    data_json = json.dumps(payload, default=str)
    # Valid JSON escapes, but inert inside an HTML <script> element.
    data_json = (
        data_json.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    )

    title = f"nwaa report — {Path(str(report.get('nessus_file', 'scan'))).name}"
    return (
        _TEMPLATE
        .replace("__NWAA_TITLE__", html.escape(title))
        .replace("__NWAA_DATA__", data_json)
    )


def write_html_report(report: dict, path: str | Path, embed_screenshots: bool = True) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        build_html_report(report, embed_screenshots, base_dir=path.parent), encoding="utf-8"
    )
    return path


def _relative_link(source: Path, base_dir: str | Path | None) -> str:
    if base_dir is None:
        return source.as_posix()
    try:
        return Path(os.path.relpath(source, Path(base_dir))).as_posix()
    except ValueError:  # different drive on Windows — fall back to absolute
        return source.as_posix()


def _augment_screenshot(shot: dict, embed: bool, base_dir: str | Path | None = None) -> dict:
    out = dict(shot)
    out["image"] = None
    raw_path = shot.get("path")
    if not shot.get("success") or not raw_path:
        return out

    source = Path(str(raw_path))
    if not embed:
        out["image"] = _relative_link(source, base_dir)
        return out

    try:
        size = source.stat().st_size
        if size > MAX_EMBED_BYTES:
            logger.warning(
                "Screenshot too large to embed; linking instead",
                extra={"path": str(source), "bytes": size},
            )
            out["image"] = _relative_link(source, base_dir)
            return out
        data = source.read_bytes()
    except OSError as exc:
        logger.warning("Could not read screenshot for embedding: %s", exc)
        return out

    mime = mimetypes.guess_type(source.name)[0] or "image/png"
    out["image"] = f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"
    return out


_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__NWAA_TITLE__</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #f6f7f9; --panel: #ffffff; --ink: #14181d; --muted: #5d6672;
  --line: #dfe3e8; --accent: #1f6feb; --ok: #1a7f37; --warn: #bf8700;
  --bad: #b42318; --info: #5d6672;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --panel: #161b22; --ink: #e6edf3; --muted: #9198a1;
    --line: #30363d; --accent: #4493f8; --ok: #3fb950; --warn: #d29922;
    --bad: #f85149; --info: #9198a1;
  }
}
* { box-sizing: border-box; }
/* An author `display` rule beats the UA stylesheet's [hidden] rule, so
   el.hidden = true silently does nothing on .chips/.controls without this. */
[hidden] { display: none !important; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
header { padding: 24px 28px 16px; border-bottom: 1px solid var(--line); background: var(--panel); }
h1 { margin: 0 0 4px; font-size: 20px; letter-spacing: -0.01em; }
.meta { color: var(--muted); font-size: 13px; }
.meta code { font-size: 12px; }
main { padding: 20px 28px 60px; max-width: 1200px; margin: 0 auto; }
.cards { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); margin-bottom: 22px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }
.card .n { font-size: 26px; font-weight: 650; letter-spacing: -0.02em; }
.card .k { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }
.card.alert .n { color: var(--bad); }
.tabs { display: flex; flex-wrap: wrap; gap: 6px; border-bottom: 1px solid var(--line); margin-bottom: 14px; }
.tab {
  background: none; border: 0; border-bottom: 2px solid transparent; color: var(--muted);
  padding: 9px 12px; font: inherit; font-size: 14px; cursor: pointer; border-radius: 6px 6px 0 0;
}
.tab:hover { color: var(--ink); }
.tab[aria-selected="true"] { color: var(--accent); border-bottom-color: var(--accent); font-weight: 600; }
.controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 16px; }
input[type="search"] {
  flex: 1 1 260px; min-width: 200px; padding: 9px 12px; border-radius: 8px;
  border: 1px solid var(--line); background: var(--panel); color: var(--ink); font: inherit; font-size: 14px;
}
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip {
  border: 1px solid var(--line); background: var(--panel); color: var(--muted);
  border-radius: 999px; padding: 5px 11px; font: inherit; font-size: 12px; cursor: pointer;
}
.chip[aria-pressed="true"] { border-color: var(--accent); color: var(--accent); font-weight: 600; }
.item { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; margin-bottom: 10px; }
.item h3 { margin: 0 0 6px; font-size: 15px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; word-break: break-all; }
/* Overview headlines are prose, not URLs — monospace reads as an error there. */
.item h3.plain { font-family: inherit; font-weight: 650; word-break: normal; }
.row { display: flex; flex-wrap: wrap; gap: 8px 18px; color: var(--muted); font-size: 13px; }
.badge { display: inline-block; border-radius: 6px; padding: 2px 8px; font-size: 11px; font-weight: 650; letter-spacing: 0.02em; border: 1px solid; }
.b-bad { color: var(--bad); border-color: var(--bad); }
.b-ok { color: var(--ok); border-color: var(--ok); }
.b-warn { color: var(--warn); border-color: var(--warn); }
.b-info { color: var(--info); border-color: var(--line); }
ul.evidence { margin: 8px 0 0; padding-left: 18px; color: var(--muted); font-size: 13px; }
ul.evidence li { word-break: break-word; }
table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--line); font-size: 13px; }
th { color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.04em; }
tr:last-child td { border-bottom: 0; }
td.mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; word-break: break-all; }
.shots { display: grid; gap: 14px; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); }
.shot { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
.shot img { display: block; width: 100%; height: 190px; object-fit: cover; object-position: top; cursor: zoom-in; background: #fff; }
.shot .cap { padding: 10px 12px; font-size: 12px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; word-break: break-all; }
.empty { color: var(--muted); font-style: italic; padding: 18px 2px; }
.note { color: var(--muted); font-size: 12px; margin-top: 26px; border-top: 1px solid var(--line); padding-top: 14px; }
dialog#lightbox { border: 0; padding: 0; background: transparent; max-width: 94vw; max-height: 94vh; }
dialog#lightbox::backdrop { background: rgba(0,0,0,0.82); }
dialog#lightbox img { max-width: 92vw; max-height: 82vh; display: block; border-radius: 8px; background: #fff; }
dialog#lightbox .cap { color: #fff; font-size: 12px; padding: 10px 2px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; word-break: break-all; }
@media print {
  .tabs, .controls, .tab { display: none !important; }
  body { background: #fff; }
  .item, .card, table { break-inside: avoid; }
}
</style>
</head>
<body>
<header>
  <h1 id="title"></h1>
  <div class="meta" id="subtitle"></div>
</header>
<main>
  <section class="cards" id="cards"></section>
  <nav class="tabs" id="tabs" role="tablist"></nav>
  <div class="controls" id="controls">
    <input type="search" id="q" placeholder="Filter by host, URL, plugin, username…" aria-label="Filter">
    <div class="chips" id="chips"></div>
  </div>
  <div id="view"></div>
  <p class="note" id="note"></p>
</main>
<dialog id="lightbox">
  <img id="lightbox-img" alt="Login page screenshot">
  <div class="cap" id="lightbox-cap"></div>
</dialog>
<script type="application/json" id="nwaa-data">__NWAA_DATA__</script>
<script>
(function () {
  "use strict";
  var DATA = JSON.parse(document.getElementById("nwaa-data").textContent);
  var S = DATA.summary || {};
  var view = document.getElementById("view");
  var query = "";
  var verdictFilter = null;
  var current = "overview";

  function el(tag, opts, kids) {
    var node = document.createElement(tag);
    opts = opts || {};
    if (opts.cls) { node.className = opts.cls; }
    if (opts.text != null) { node.textContent = String(opts.text); }
    Object.keys(opts.attrs || {}).forEach(function (k) { node.setAttribute(k, opts.attrs[k]); });
    (kids || []).forEach(function (kid) { if (kid) { node.appendChild(kid); } });
    return node;
  }

  function badge(text, kind) { return el("span", { cls: "badge b-" + kind, text: text }); }

  function matches(haystackParts) {
    if (!query) { return true; }
    return haystackParts.join(" | ").toLowerCase().indexOf(query) !== -1;
  }

  function empty(msg) { return el("p", { cls: "empty", text: msg }); }

  var VERDICT_STYLE = {
    default_credentials_successful: "bad",
    authentication_failed: "ok",
    inconclusive: "warn",
    connection_error: "info",
    not_tested: "info"
  };

  function renderCards() {
    var cards = [
      ["Web services", S.web_services, false],
      ["Plaintext HTTP", S.plaintext_http_services, (S.plaintext_http_services || 0) > 0],
      ["Login pages", S.login_pages, false],
      ["Devices identified", S.devices_fingerprinted, false],
      ["Screenshots", S.screenshots_captured, false],
      ["Cred attempts", S.credential_attempts, false],
      ["Default creds worked",
        (S.attempts_by_verdict || {}).default_credentials_successful || 0,
        ((S.attempts_by_verdict || {}).default_credentials_successful || 0) > 0]
    ];
    var wrap = document.getElementById("cards");
    cards.forEach(function (c) {
      wrap.appendChild(el("div", { cls: "card" + (c[2] ? " alert" : "") }, [
        el("div", { cls: "n", text: c[1] == null ? 0 : c[1] }),
        el("div", { cls: "k", text: c[0] })
      ]));
    });
  }

  var CONFIDENCE_STYLE = { high: "ok", medium: "warn", low: "info" };

  function deviceLabel(d) {
    return d ? d.display_name + " (" + d.confidence + ")" : "";
  }

  function loginPages() {
    var pages = (DATA.login_pages || []).filter(function (p) {
      return matches(
        [p.url, p.host_ip, p.hostname || "", String(p.port), deviceLabel(p.device)]
          .concat(p.evidence || [])
      );
    });
    if (!pages.length) { return [empty("No login pages match.")]; }
    return pages.map(function (p) {
      var meta = [
        p.plaintext_transmission ? badge("PLAINTEXT HTTP", "bad") : badge("TLS", "ok"),
        el("span", { text: p.host_ip + ":" + p.port }),
        el("span", { text: "detected via " + p.detection_method })
      ];
      if (p.device) {
        meta.push(badge(p.device.display_name, CONFIDENCE_STYLE[p.device.confidence] || "info"));
        meta.push(el("span", { text: "profile: " + p.device.profile_id }));
      }
      var kids = [
        el("h3", { text: p.url }),
        el("div", { cls: "row" }, meta)
      ];
      if ((p.evidence || []).length) {
        kids.push(el("ul", { cls: "evidence" }, p.evidence.map(function (e) {
          return el("li", { text: e });
        })));
      }
      return el("div", { cls: "item" }, kids);
    });
  }

  function plaintext() {
    var rows = (DATA.plaintext_http_services || []).filter(function (s) {
      return matches([s.base_url, s.host_ip, s.svc_name]);
    });
    if (!rows.length) { return [empty("No plaintext HTTP services match.")]; }
    return [table(["Service", "Host", "Port", "svc_name"], rows.map(function (s) {
      return [{ text: s.base_url, mono: true }, { text: s.host_ip }, { text: s.port }, { text: s.svc_name }];
    }))];
  }

  function services() {
    var rows = (DATA.web_services || []).filter(function (s) {
      return matches([s.base_url, s.host_ip, s.hostname || "", s.svc_name, String(s.port)]);
    });
    if (!rows.length) { return [empty("No web services match.")]; }
    return [table(["Service", "Hostname", "Transport", "Plugins"], rows.map(function (s) {
      return [
        { text: s.base_url, mono: true },
        { text: s.hostname || "—" },
        { text: s.transport, badge: s.plaintext_http ? "bad" : "ok" },
        { text: (s.plugin_ids || []).length }
      ];
    }))];
  }

  function attempts() {
    var rows = (DATA.credential_attempts || []).filter(function (a) {
      if (verdictFilter && a.verdict !== verdictFilter) { return false; }
      return matches([a.url, a.username, a.credential_label, a.verdict, a.detail,
                      a.credential_source || ""]);
    });
    if (!rows.length) { return [empty("No credential attempts match.")]; }
    return rows.map(function (a) {
      var head = [badge(a.verdict.replace(/_/g, " "), VERDICT_STYLE[a.verdict] || "info")];
      if (a.credential_source === "vendor_default") {
        head.push(badge("vendor default", "warn"));
      }
      return el("div", { cls: "item" }, [
        el("div", { cls: "row" }, head),
        el("h3", { text: a.url }),
        el("div", { cls: "row" }, [
          el("span", { text: "username: " + (a.username || "(blank)") }),
          el("span", { text: "set: " + a.credential_label }),
          el("span", { text: a.timestamp })
        ]),
        el("p", { cls: "row", text: a.detail })
      ]);
    });
  }

  function devices() {
    var rows = (DATA.devices || []).filter(function (d) {
      return matches([d.target, d.display_name, d.vendor, d.profile_id, d.category]);
    });
    if (!rows.length) { return [empty("No devices were fingerprinted.")]; }
    return [table(["Target", "Device", "Vendor", "Profile", "Confidence", "Source"],
      rows.map(function (d) {
        return [
          { text: d.target, mono: true },
          { text: d.display_name },
          { text: d.vendor },
          { text: d.profile_id, mono: true },
          { text: d.confidence, badge: CONFIDENCE_STYLE[d.confidence] || "info" },
          { text: d.source }
        ];
      }))];
  }

  function screenshots() {
    var shots = (DATA.screenshots || []).filter(function (s) {
      return matches([s.url, s.error || "", s.server || "", s.page_title || ""]);
    });
    if (!shots.length) { return [empty("No screenshots match.")]; }
    var grid = el("div", { cls: "shots" });
    shots.forEach(function (s) {
      var body = [];
      if (s.image) {
        var img = el("img", { attrs: { src: s.image, alt: "Screenshot of " + s.url, loading: "lazy" } });
        img.addEventListener("click", function () { openLightbox(s.image, s.url); });
        body.push(img);
      }
      var cap = [
        el("div", { text: s.url }),
        el("div", { cls: "row" }, [s.success ? badge("captured", "ok") : badge(s.error || "failed", "bad")])
      ];
      if (s.server) { cap.push(el("div", { cls: "row", text: "Server: " + s.server })); }
      body.push(el("div", { cls: "cap" }, cap));
      grid.appendChild(el("div", { cls: "shot" }, body));
    });
    return [grid];
  }

  function overview() {
    var out = [];
    var worked = (DATA.credential_attempts || []).filter(function (a) {
      return a.verdict === "default_credentials_successful";
    });
    if (worked.length) {
      out.push(el("div", { cls: "item" }, [
        el("div", { cls: "row" }, [badge("ACTION REQUIRED", "bad")]),
        el("h3", { cls: "plain", text: worked.length + " login(s) accepted configured credentials" }),
        el("ul", { cls: "evidence" }, worked.map(function (a) {
          return el("li", {
            text: a.url + "  (username: " + (a.username || "(blank)") + ", set: " +
                  a.credential_label + ")"
          });
        }))
      ]));
    }
    var plain = DATA.plaintext_http_services || [];
    if (plain.length) {
      out.push(el("div", { cls: "item" }, [
        el("div", { cls: "row" }, [badge("PLAINTEXT HTTP", "bad")]),
        el("h3", { cls: "plain", text: plain.length + " web service(s) carry traffic unencrypted" }),
        el("ul", { cls: "evidence" }, plain.map(function (s) { return el("li", { text: s.base_url }); }))
      ]));
    }
    (DATA.warnings || []).forEach(function (w) {
      out.push(el("div", { cls: "item" }, [
        el("div", { cls: "row" }, [badge("WARNING", "warn")]),
        el("p", { cls: "row", text: w })
      ]));
    });
    if (!out.length) {
      out.push(empty("No plaintext services, successful default credentials, or warnings recorded."));
    }
    return out;
  }

  function table(headers, rows) {
    var thead = el("tr", {}, headers.map(function (h) { return el("th", { text: h }); }));
    var body = rows.map(function (cells) {
      return el("tr", {}, cells.map(function (c) {
        var td = el("td", { cls: c.mono ? "mono" : "" });
        if (c.badge) { td.appendChild(badge(String(c.text), c.badge)); }
        else { td.textContent = String(c.text); }
        return td;
      }));
    });
    return el("table", {}, [el("thead", {}, [thead]), el("tbody", {}, body)]);
  }

  var TABS = [
    ["overview", "Overview", overview],
    ["logins", "Login pages", loginPages],
    ["devices", "Devices", devices],
    ["plaintext", "Plaintext HTTP", plaintext],
    ["attempts", "Credential attempts", attempts],
    ["screenshots", "Screenshots", screenshots],
    ["services", "Web services", services]
  ];

  function render() {
    view.textContent = "";
    var tab = TABS.filter(function (t) { return t[0] === current; })[0];
    tab[2]().forEach(function (node) { view.appendChild(node); });
    // Verdict chips only mean something on the attempts tab, and the Overview
    // tab renders a fixed summary that the text filter does not apply to.
    document.getElementById("chips").hidden = current !== "attempts";
    document.getElementById("controls").hidden = current === "overview";
  }

  function openLightbox(src, caption) {
    var dlg = document.getElementById("lightbox");
    document.getElementById("lightbox-img").src = src;
    document.getElementById("lightbox-cap").textContent = caption;
    if (typeof dlg.showModal === "function") { dlg.showModal(); }
  }

  function init() {
    document.getElementById("title").textContent =
      "Web authentication surface — " + (S.login_pages || 0) + " login page(s)";
    document.getElementById("subtitle").textContent =
      "Source: " + DATA.nessus_file + "   |   Generated: " + DATA.generated_at + "   |   nwaa " + DATA.version;
    document.getElementById("note").textContent =
      "Verdicts are heuristic. Verify any \\u201cdefault credentials successful\\u201d result manually before reporting it. " +
      "Passwords are never recorded in this report.";
    renderCards();

    var tabsEl = document.getElementById("tabs");
    TABS.forEach(function (t) {
      var selected = String(t[0] === current);
      var b = el("button", { cls: "tab", text: t[1], attrs: { role: "tab", "aria-selected": selected } });
      b.addEventListener("click", function () {
        current = t[0];
        Array.prototype.forEach.call(tabsEl.children, function (c) { c.setAttribute("aria-selected", "false"); });
        b.setAttribute("aria-selected", "true");
        render();
      });
      tabsEl.appendChild(b);
    });

    var chips = document.getElementById("chips");
    Object.keys(VERDICT_STYLE).forEach(function (v) {
      var c = el("button", { cls: "chip", text: v.replace(/_/g, " "), attrs: { "aria-pressed": "false" } });
      c.addEventListener("click", function () {
        var on = verdictFilter === v;
        verdictFilter = on ? null : v;
        Array.prototype.forEach.call(chips.children, function (x) { x.setAttribute("aria-pressed", "false"); });
        c.setAttribute("aria-pressed", on ? "false" : "true");
        render();
      });
      chips.appendChild(c);
    });

    document.getElementById("q").addEventListener("input", function (e) {
      query = e.target.value.trim().toLowerCase();
      render();
    });

    var dlg = document.getElementById("lightbox");
    dlg.addEventListener("click", function () { dlg.close(); });
    render();
  }

  init();
})();
</script>
</body>
</html>
"""
