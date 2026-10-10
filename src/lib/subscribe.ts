/**
 * 订阅链接解析与各客户端配置生成。
 *
 * 全部在浏览器本地运行：不请求任何第三方转换服务，订阅内容不会离开页面。
 * 支持解析：Shadowsocks、VMess（新版链接与旧版 base64 JSON）、VLESS、
 * Trojan、Hysteria2、TUIC；传输层覆盖 tcp / ws / grpc / h2 / xhttp 与 TLS、Reality。
 */

export type ProxyType = "ss" | "vmess" | "vless" | "trojan" | "hysteria2" | "tuic";

export interface ProxyNode {
  type: ProxyType;
  name: string;
  server: string;
  port: number;
  raw: string;
  password: string;
  cipher?: string | undefined;
  uuid?: string | undefined;
  alterId?: string | undefined;
  network?: string | undefined;
  tls?: boolean | undefined;
  sni?: string | undefined;
  alpn?: string | undefined;
  fingerprint?: string | undefined;
  publicKey?: string | undefined;
  shortId?: string | undefined;
  flow?: string | undefined;
  path?: string | undefined;
  host?: string | undefined;
  insecure?: boolean | undefined;
  obfs?: string | undefined;
  obfsPassword?: string | undefined;
  obfsHost?: string | undefined;
  pluginName?: "obfs" | "v2ray" | undefined;
}

export interface ParseResult {
  nodes: ProxyNode[];
  unknown: string[];
}

const SUPPORTED = new Set(["ss", "vmess", "vless", "trojan", "hysteria2", "hy2", "tuic"]);
const B64_RE = /^[A-Za-z0-9+/_=-]+$/;

/* ------------------------------------------------------------------ 编码工具 */

export function decodeBase64(input: string): string | null {
  const clean = input.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!clean || !B64_RE.test(clean)) return null;
  const padded = clean + "=".repeat((4 - (clean.length % 4)) % 4);
  try {
    const bin = atob(padded);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8").decode(bytes);
  } catch {
    return null;
  }
}

export function encodeBase64(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function looksLikeText(s: string): boolean {
  if (!s || s.includes("\uFFFD")) return false;
  for (const ch of s) {
    const code = ch.codePointAt(0) ?? 0;
    if (code < 9 || (code > 13 && code < 32)) return false;
  }
  return true;
}

function decodeMaybe(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/* ------------------------------------------------------------------ 结构解析 */

function splitHostPort(rest: string): { host: string; port: number } | null {
  const m = /^(?:\[([0-9a-fA-F:.]+)\]|([^:/?#\[\]]+)):(\d{1,5})$/.exec(rest.trim());
  if (!m) return null;
  const port = Number(m[3]);
  if (!Number.isFinite(port) || port < 1 || port > 65535) return null;
  return { host: m[1] ?? m[2] ?? "", port };
}

function parseQuery(q: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const pair of q.split("&")) {
    if (!pair) continue;
    const i = pair.indexOf("=");
    const key = (i < 0 ? pair : pair.slice(0, i)).trim();
    const value = i < 0 ? "" : pair.slice(i + 1);
    if (key) out[key] = decodeMaybe(value);
  }
  return out;
}

function applyParams(n: ProxyNode, p: Record<string, string>) {
  const get = (...keys: string[]) => {
    for (const k of keys) if (p[k]) return p[k];
    return undefined;
  };
  n.sni = get("sni", "peer", "tls-server-name", "tls-host", "tlsname");
  n.alpn = get("alpn");
  n.fingerprint = get("fp", "fingerprint");
  n.publicKey = get("pbk", "public-key", "pbid", "reality-pbk");
  n.shortId = get("sid", "short-id", "reality-sid");
  n.flow = get("flow");
  n.host = get("host", "service-name", "serviceName");
  n.path = get("path", "ws-path");
  n.obfs = get("obfs", "mode");
  n.obfsPassword = get("obfs-password");
  const security = get("security");
  if (security && security !== "none") n.tls = true;
  const network = get("type", "net");
  if (network) n.network = network;
  const insecure = get("insecure", "allowInsecure");
  if (insecure === "1" || insecure === "true") n.insecure = true;
}

function parseSS(main: string, query: Record<string, string>): ProxyNode | null {
  let cred = "";
  let hostPort = main;
  const at = main.lastIndexOf("@");
  if (at >= 0) {
    cred = main.slice(0, at);
    hostPort = main.slice(at + 1);
    const dec = decodeBase64(cred);
    if (dec && looksLikeText(dec) && dec.includes(":")) cred = dec;
  } else {
    const dec = decodeBase64(main);
    if (dec && looksLikeText(dec)) {
      const inner = dec.lastIndexOf("@");
      if (inner >= 0) {
        cred = dec.slice(0, inner);
        hostPort = dec.slice(inner + 1);
      }
    }
  }
  const hp = splitHostPort(hostPort);
  if (!hp) return null;
  let cipher = "aes-256-gcm";
  let password = cred;
  const ci = cred.indexOf(":");
  if (ci > 0 && /^[A-Za-z0-9._+-]+$/.test(cred.slice(0, ci))) {
    cipher = cred.slice(0, ci);
    password = cred.slice(ci + 1);
  }
  const node: ProxyNode = { type: "ss", name: "", server: hp.host, port: hp.port, raw: "", password, cipher };
  const plugin = query["plugin"] ?? query["plugin_opts"];
  if (plugin) {
    const parts = plugin.split(";");
    const params: Record<string, string> = {};
    for (const seg of parts.slice(1)) {
      const i = seg.indexOf("=");
      if (i > 0) params[seg.slice(0, i)] = seg.slice(i + 1);
    }
    node.obfs = params["obfs"] ?? params["mode"];
    node.obfsHost = params["obfs-host"] ?? params["host"];
    node.obfsPassword = params["obfs-password"] ?? params["password"];
    node.pluginName = (parts[0] ?? "").includes("v2ray") ? "v2ray" : "obfs";
  }
  return node;
}

function parseVmess(main: string, query: Record<string, string>): ProxyNode | null {
  const at = main.indexOf("@");
  if (at > 0) {
    const hp = splitHostPort(main.slice(at + 1));
    if (!hp) return null;
    const node: ProxyNode = {
      type: "vmess",
      name: "",
      server: hp.host,
      port: hp.port,
      raw: "",
      password: "",
      uuid: main.slice(0, at),
      alterId: query["aid"] ?? "0",
      cipher: "auto",
    };
    applyParams(node, query);
    const enc = query["encryption"];
    node.cipher = enc && enc !== "none" && enc !== "zero" ? enc : "auto";
    return node;
  }
  const json = decodeBase64(main);
  if (!json) return null;
  let data: Record<string, unknown>;
  try {
    data = JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
  const str = (k: string) => {
    const v = data[k];
    if (typeof v === "string") return v;
    if (typeof v === "number") return String(v);
    return "";
  };
  const hp = splitHostPort(`${str("add")}:${str("port")}`);
  if (!hp) return null;
  const node: ProxyNode = {
    type: "vmess",
    name: str("ps"),
    server: hp.host,
    port: hp.port,
    raw: "",
    password: "",
    uuid: str("id"),
    alterId: str("aid") || "0",
    cipher: str("scy") || "auto",
  };
  if (str("net")) node.network = str("net");
  if (str("host")) node.host = str("host");
  if (str("path")) node.path = str("path");
  if (str("tls") === "tls") node.tls = true;
  if (str("sni")) node.sni = str("sni");
  if (str("alpn")) node.alpn = str("alpn");
  if (str("fp")) node.fingerprint = str("fp");
  return node;
}

function parseCredential(type: ProxyType, main: string, query: Record<string, string>): ProxyNode | null {
  const at = main.lastIndexOf("@");
  if (at <= 0) return null;
  const cred = main.slice(0, at);
  const hp = splitHostPort(main.slice(at + 1));
  if (!hp) return null;
  const node: ProxyNode = { type, name: "", server: hp.host, port: hp.port, raw: "", password: "" };
  if (type === "vless") node.uuid = cred;
  else node.password = cred;
  applyParams(node, query);
  return node;
}

function parseTuic(main: string, query: Record<string, string>): ProxyNode | null {
  const at = main.lastIndexOf("@");
  if (at <= 0) return null;
  const cred = main.slice(0, at);
  const hp = splitHostPort(main.slice(at + 1));
  if (!hp) return null;
  const [id = "", ...rest] = cred.split(":");
  const node: ProxyNode = {
    type: "tuic",
    name: "",
    server: hp.host,
    port: hp.port,
    raw: "",
    password: rest.join(":") || query["token"] || query["password"] || id,
    uuid: id,
  };
  applyParams(node, query);
  if (!node.alpn) node.alpn = "h3";
  return node;
}

/** 解析单行节点链接，无法识别时返回 null。 */
export function parseLink(line: string): ProxyNode | null {
  const raw = line.trim();
  const m = /^([a-zA-Z][a-zA-Z0-9]*):\/\/(.+)$/.exec(raw);
  if (!m) return null;
  const scheme = (m[1] ?? "").toLowerCase();
  if (!SUPPORTED.has(scheme)) return null;

  let rest = m[2] ?? "";
  let name = "";
  const hash = rest.indexOf("#");
  if (hash >= 0) {
    name = decodeMaybe(rest.slice(hash + 1));
    rest = rest.slice(0, hash);
  }
  const qIdx = rest.indexOf("?");
  const query = qIdx >= 0 ? parseQuery(rest.slice(qIdx + 1)) : {};
  const main = (qIdx >= 0 ? rest.slice(0, qIdx) : rest).replace(/\/+$/, "");

  let node: ProxyNode | null = null;
  if (scheme === "ss") node = parseSS(main, query);
  else if (scheme === "vmess") node = parseVmess(main, query);
  else if (scheme === "vless") node = parseCredential("vless", main, query);
  else if (scheme === "trojan") node = parseCredential("trojan", main, query);
  else if (scheme === "hy2" || scheme === "hysteria2") node = parseCredential("hysteria2", main, query);
  else if (scheme === "tuic") node = parseTuic(main, query);
  if (!node) return null;

  node.name = name || node.name || `${node.type.toUpperCase()} ${node.server}:${node.port}`;
  node.raw = raw;
  return node;
}

/** 解析订阅内容：base64 整包、一行一个链接，或两者混合。 */
export function parseSubscription(text: string): ParseResult {
  const raw = (text ?? "").trim();
  if (!raw) return { nodes: [], unknown: [] };

  let body = raw;
  if (!/^(?:ss|ssr|vmess|vless|trojan|hysteria2?|hy2|tuic):\/\//i.test(raw)) {
    const dec = decodeBase64(raw);
    if (dec && looksLikeText(dec) && /:\/\//.test(dec)) body = dec;
    else if (raw.includes("%0A") || raw.includes("%2F")) body = decodeMaybe(raw);
  }

  const nodes: ProxyNode[] = [];
  const unknown: string[] = [];
  const seen = new Set<string>();
  for (const line of body.split(/\r?\n/)) {
    const line2 = line.trim();
    if (!line2) continue;
    const node = parseLink(line2);
    if (!node) {
      unknown.push(line2);
      continue;
    }
    if (seen.has(node.raw)) continue;
    seen.add(node.raw);
    nodes.push(node);
  }

  const used = new Set<string>();
  for (const node of nodes) {
    let name = node.name.replace(/[,="]/g, " ").trim() || node.type.toUpperCase();
    if (used.has(name)) {
      let i = 2;
      while (used.has(`${name} ${i}`)) i += 1;
      name = `${name} ${i}`;
    }
    used.add(name);
    node.name = name;
  }
  return { nodes, unknown };
}

/* --------------------------------------------------------------- Clash 输出 */

type Scalar = string | number | boolean;
type YamlValue = Scalar | YamlEntry[] | { list: Scalar[] };
type YamlEntry = [string, YamlValue];

const list = (items: Scalar[]) => ({ list: items });

function yamlVal(v: Scalar): string {
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v);
}

function emitYaml(entries: YamlEntry[], indent: number): string {
  const pad = " ".repeat(indent);
  return entries
    .map(([k, v]) => {
      if (Array.isArray(v)) return `${pad}${k}:\n${emitYaml(v, indent + 2)}`;
      if (typeof v === "object" && v !== null && "list" in v) {
        return `${pad}${k}:\n${v.list.map((i) => `${pad}  - ${yamlVal(i)}`).join("\n")}`;
      }
      return `${pad}${k}: ${yamlVal(v as Scalar)}`;
    })
    .join("\n");
}

function alpnList(alpn: string) {
  return list(alpn.split(",").map((s) => s.trim()).filter(Boolean));
}

function transportOpts(n: ProxyNode): YamlEntry[] {
  const net = n.network ?? "tcp";
  const out: YamlEntry[] = [];
  if (net === "ws") {
    const opts: YamlEntry[] = [];
    if (n.path) opts.push(["path", n.path]);
    if (n.host) opts.push(["headers", [["Host", n.host]]]);
    out.push(["ws-opts", opts]);
  } else if (net === "grpc") {
    out.push(["grpc-opts", [["grpc-service-name", n.host || n.path || ""]]]);
  } else if (net === "h2") {
    out.push(["h2-opts", [["host", n.host || ""], ["path", n.path || "/"]]]);
  } else if (net === "http" || net === "xhttp") {
    const opts: YamlEntry[] = [["path", n.path || "/"]];
    if (n.host) opts.push(["headers", [["Host", n.host]]]);
    out.push(["xhttp-opts", opts]);
  }
  return out;
}

function clashProxy(n: ProxyNode): string {
  const e: YamlEntry[] = [];
  const push = (k: string, v: YamlValue) => e.push([k, v]);
  push("name", n.name);
  push("type", n.type);
  push("server", n.server);
  push("port", n.port);

  if (n.type === "ss") {
    push("cipher", n.cipher ?? "aes-256-gcm");
    push("password", n.password);
    push("udp", true);
    if (n.obfs) {
      const opts: YamlEntry[] = [["mode", n.obfs]];
      if (n.obfsHost) opts.push(["host", n.obfsHost]);
      if (n.obfsPassword) opts.push(["password", n.obfsPassword]);
      push("plugin", n.pluginName ?? "obfs");
      push("plugin-opts", opts);
    }
  } else if (n.type === "vmess") {
    push("uuid", n.uuid ?? "");
    push("alterId", Number(n.alterId ?? 0) || 0);
    push("cipher", n.cipher && n.cipher !== "none" ? n.cipher : "auto");
    push("tls", !!n.tls);
    if (n.sni) push("servername", n.sni);
    if (n.alpn) push("alpn", alpnList(n.alpn));
    if (n.fingerprint) push("client-fingerprint", n.fingerprint);
    e.push(...transportOpts(n));
  } else if (n.type === "vless") {
    push("uuid", n.uuid ?? "");
    push("tls", !!n.tls);
    if (n.sni) push("servername", n.sni);
    if (n.publicKey) push("reality-opts", [["public-key", n.publicKey], ["short-id", n.shortId ?? ""]]);
    if (n.fingerprint) push("client-fingerprint", n.fingerprint);
    if (n.flow) push("flow", n.flow);
    if (n.alpn) push("alpn", alpnList(n.alpn));
    e.push(...transportOpts(n));
  } else if (n.type === "trojan") {
    push("password", n.password);
    if (n.sni) push("sni", n.sni);
    if (n.alpn) push("alpn", alpnList(n.alpn));
    if (n.publicKey) push("reality-opts", [["public-key", n.publicKey], ["short-id", n.shortId ?? ""]]);
    if (n.insecure) push("skip-cert-verify", true);
  } else if (n.type === "hysteria2") {
    push("password", n.password);
    if (n.sni) push("sni", n.sni);
    push("skip-cert-verify", !!n.insecure);
    if (n.obfs) {
      push("obfs", n.obfs);
      if (n.obfsPassword) push("obfs-password", n.obfsPassword);
    }
  } else if (n.type === "tuic") {
    push("uuid", n.uuid ?? "");
    push("password", n.password);
    if (n.sni) push("sni", n.sni);
    push("alpn", alpnList(n.alpn ?? "h3"));
    push("skip-cert-verify", !!n.insecure);
  }

  return emitYaml(e, 4).replace(/^ {4}/, "  - ");
}

export function toClash(result: ParseResult): string {
  if (!result.nodes.length) {
    return ["# 没有识别到可用节点。", "# 请确认订阅内容是否为 ss:// / vmess:// / vless:// / trojan:// 等节点链接。"].join("\n");
  }
  const names = result.nodes.map((n) => n.name);
  const lines: string[] = [
    "# 由 b1000mk 订阅链接转换生成",
    "mixed-port: 7890",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
    "unified-delay: true",
    "",
    "proxies:",
  ];
  for (const node of result.nodes) lines.push(clashProxy(node));
  for (const line of result.unknown) lines.push(`    # 已跳过（无法识别）: ${line.slice(0, 100)}`);
  lines.push(
    "",
    "proxy-groups:",
    "  - name: \"自动选择\"",
    "    type: url-test",
    "    url: \"http://www.gstatic.com/generate_204\"",
    "    interval: 600",
    "    proxies:",
  );
  for (const name of names) lines.push(`      - ${yamlVal(name)}`);
  lines.push("  - name: \"节点选择\"", "    type: select", "    proxies:", "      - \"自动选择\"");
  for (const name of names) lines.push(`      - ${yamlVal(name)}`);
  lines.push("", "rules:", "  - MATCH,节点选择");
  return lines.join("\n");
}

/* ------------------------------------------------------------- 通用 / V2Ray */

function allLinks(result: ParseResult): string[] {
  return [...result.nodes.map((n) => n.raw), ...result.unknown];
}

export function toPlainLinks(result: ParseResult): string {
  const links = allLinks(result);
  return links.length ? links.join("\n") : "没有识别到节点链接。";
}

export function toV2RaySubscription(result: ParseResult): string {
  const links = allLinks(result);
  return links.length ? encodeBase64(links.join("\n")) : "";
}

/* ------------------------------------------------------------ Surge / Quantumult */

function kv(parts: string[]): string {
  return parts.filter(Boolean).join(", ");
}

function surgeLine(n: ProxyNode): string {
  const name = n.name;
  if (n.type === "ss") {
    return kv([name, "ss", n.server, String(n.port), `encrypt-method=${n.cipher ?? "aes-256-gcm"}`, `password=${n.password}`, "udp-relay=true"]);
  }
  if (n.type === "vmess") {
    const parts = [name, "vmess", n.server, String(n.port), `username=${n.uuid ?? ""}`];
    if (n.cipher && n.cipher !== "none") parts.push(`method=${n.cipher}`);
    if (n.alterId && n.alterId !== "0") parts.push(`vmess-aead=${n.alterId}`);
    if (n.tls) {
      parts.push("tls=true");
      if (n.sni) parts.push(`tls-name=${n.sni}`);
    }
    if (n.network === "ws") {
      parts.push("ws=true");
      if (n.path) parts.push(`ws-path=${n.path}`);
      if (n.host) parts.push(`ws-headers=Host:${n.host}`);
    }
    if (n.network === "grpc") parts.push("over-tls=true");
    return kv(parts);
  }
  if (n.type === "vless") {
    const parts = [name, "vless", n.server, String(n.port), `password=${n.uuid ?? ""}`];
    if (n.tls) {
      parts.push("over-tls=true");
      if (n.sni) parts.push(`tls-name=${n.sni}`);
    }
    if (n.flow) parts.push(`vless-flow=${n.flow}`);
    if (n.network === "ws") {
      parts.push("ws=true");
      if (n.path) parts.push(`ws-path=${n.path}`);
      if (n.host) parts.push(`ws-headers=Host:${n.host}`);
    }
    return kv(parts);
  }
  if (n.type === "trojan") {
    const parts = [name, "trojan", n.server, String(n.port), `password=${n.password}`];
    if (n.sni) parts.push(`tls-name=${n.sni}`);
    if (n.insecure) parts.push("skip-cert-verify=true");
    return kv(parts);
  }
  if (n.type === "hysteria2") {
    const parts = [name, "hysteria2", n.server, String(n.port), `password=${n.password}`];
    if (n.sni) parts.push(`tls-name=${n.sni}`);
    if (n.obfs) parts.push(`obfs=${n.obfs}`);
    if (n.obfsPassword) parts.push(`obfs-password=${n.obfsPassword}`);
    return kv(parts);
  }
  return kv([name, "tuic", n.server, String(n.port), `password=${n.password}`, `uuid=${n.uuid ?? ""}`]);
}

export function toSurge(result: ParseResult): string {
  if (!result.nodes.length) return "; 没有识别到可用节点。";
  const names = result.nodes.map((n) => n.name);
  const lines = [
    "[General]",
    "log-level = notify",
    "skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, geosite:cn, geoip:cn",
    "dns-server = system, 223.5.5.5",
    "",
    "[Proxy]",
  ];
  for (const node of result.nodes) lines.push(surgeLine(node));
  for (const line of result.unknown) lines.push(`; 已跳过（无法识别）: ${line.slice(0, 100)}`);
  lines.push(
    "",
    "[Proxy Group]",
    `节点选择 = select, ${names.join(", ")}`,
    `自动选择 = auto, ${names.join(", ")}, interval=600, tolerance=50, url-http=http://www.gstatic.com/generate_204`,
    "",
    "[Rule]",
    "GEOIP,CN,DIRECT",
    "FINAL,节点选择",
  );
  return lines.join("\n");
}

function qxLine(n: ProxyNode): string {
  const tag = `tag=${n.name}`;
  const head = (type: string) => `${type} = ${n.server}:${n.port}`;
  if (n.type === "ss") {
    return `${head("ss")}, method=${n.cipher ?? "aes-256-gcm"}, password=${n.password}, ${tag}, udp-relay=true`;
  }
  if (n.type === "vmess") {
    const parts = [head("vmess"), `method=${n.cipher && n.cipher !== "none" ? n.cipher : "auto"}`, `password=${n.uuid ?? ""}`];
    if (n.network === "ws") {
      parts.push("obfs=websocket");
      if (n.path) parts.push(`obfs-uri=${n.path}`);
      if (n.host) parts.push(`obfs-host=${n.host}`);
    } else if (n.network === "grpc") {
      parts.push("obfs=grpc");
      if (n.host) parts.push(`obfs-host=${n.host}`);
    }
    if (n.tls) parts.push("over-tls=true", n.sni ? `tls-host=${n.sni}` : "");
    parts.push(tag);
    return parts.filter(Boolean).join(", ");
  }
  if (n.type === "vless") {
    const parts = [head("vless"), `password=${n.uuid ?? ""}`];
    if (n.tls) parts.push("over-tls=true", n.sni ? `tls-host=${n.sni}` : "");
    if (n.flow) parts.push(`vless-flow=${n.flow}`);
    if (n.network === "ws") {
      parts.push("obfs=websocket");
      if (n.path) parts.push(`obfs-uri=${n.path}`);
      if (n.host) parts.push(`obfs-host=${n.host}`);
    }
    parts.push(tag);
    return parts.filter(Boolean).join(", ");
  }
  if (n.type === "trojan") {
    return `${head("trojan")}, password=${n.password}, over-tls=true${n.sni ? `, tls-host=${n.sni}` : ""}, ${tag}`;
  }
  if (n.type === "hysteria2") {
    return `${head("hysteria2")}, password=${n.password}${n.sni ? `, tls-host=${n.sni}` : ""}, over-tls=true, ${tag}`;
  }
  return `${head("tuic")}, password=${n.password}${n.sni ? `, tls-host=${n.sni}` : ""}, ${tag}`;
}

export function toQuantumultX(result: ParseResult): string {
  if (!result.nodes.length) return "; 没有识别到可用节点。";
  const names = result.nodes.map((n) => n.name);
  const lines = [
    "[general]",
    "dns-server = system, 223.5.5.5",
    "skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost",
    "bypass-system = true",
    "filter-outgoing = en0",
    "",
    "[server_local]",
  ];
  for (const node of result.nodes) lines.push(qxLine(node));
  for (const line of result.unknown) lines.push(`; 已跳过（无法识别）: ${line.slice(0, 100)}`);
  lines.push(
    "",
    "[policy]",
    `static=节点选择, ${names.join(", ")}`,
    `auto=自动选择, ${names.join(", ")}, url=http://www.gstatic.com/generate_204, interval=600, tolerance=50`,
  );
  return lines.join("\n");
}

/* --------------------------------------------------------------------- 汇总 */

export type FormatId = "clash" | "v2ray" | "surge" | "quantumultx" | "plain";

interface FormatDef {
  id: FormatId;
  label: string;
  hint: string;
  file: string;
  render: (r: ParseResult) => string;
}

const CLASH: FormatDef = {
  id: "clash",
  label: "Clash / Clash Meta",
  hint: "YAML 配置，含自动选择与节点选择分组",
  file: "subscribe.yaml",
  render: toClash,
};

export const FORMATS: FormatDef[] = [
  CLASH,
  { id: "v2ray", label: "V2Ray 订阅", hint: "base64 订阅内容，粘贴进 V2RayN / v2rayNG", file: "subscribe.txt", render: toV2RaySubscription },
  { id: "surge", label: "Surge", hint: "INI 配置，含 [Proxy] 与策略组", file: "surge.conf", render: toSurge },
  { id: "quantumultx", label: "Quantumult X", hint: "含 [server_local] 与 [policy]", file: "quantumultx.conf", render: toQuantumultX },
  { id: "plain", label: "通用节点链接", hint: "一行一个原始链接，逐条导入用", file: "nodes.txt", render: toPlainLinks },
];

export function formatOf(id: FormatId): FormatDef {
  return FORMATS.find((f) => f.id === id) ?? CLASH;
}

export function renderFormat(result: ParseResult, format: FormatId): string {
  return formatOf(format).render(result);
}

export function summaryOf(result: ParseResult): string {
  const counts = new Map<ProxyType, number>();
  for (const n of result.nodes) counts.set(n.type, (counts.get(n.type) ?? 0) + 1);
  const label: Record<ProxyType, string> = {
    ss: "SS",
    vmess: "VMess",
    vless: "VLESS",
    trojan: "Trojan",
    hysteria2: "Hysteria2",
    tuic: "TUIC",
  };
  const parts = [...counts.entries()].map(([type, count]) => `${label[type]} ${count}`);
  const head = parts.length ? `识别到 ${result.nodes.length} 个节点（${parts.join(" · ")}）` : "没有识别到节点";
  return result.unknown.length ? `${head}；${result.unknown.length} 行未识别，将原样保留或跳过` : head;
}

/** 演示用的示例订阅内容（节点均为文档保留地址，不可连接）。 */
export function sampleSubscription(): string {
  const ss = `ss://${encodeBase64("aes-256-gcm:super_password")}@192.0.2.10:8388#${encodeURIComponent("示例 SS")}`;
  const vmessNew =
    "vmess://b5c1a0e2-2f3d-4a5b-8c9d-0e1f2a3b4c5d@192.0.2.11:443?encryption=auto&security=tls&sni=example.com&type=ws&path=%2Fws&host=example.com#" +
    encodeURIComponent("示例 VMess");
  const vmessOld = `vmess://${encodeBase64(
    JSON.stringify({
      v: "2",
      ps: "示例 VMess 旧版",
      add: "192.0.2.15",
      port: "10086",
      id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      aid: "0",
      scy: "auto",
      net: "ws",
      host: "example.com",
      path: "/ws",
      tls: "",
    }),
  )}`;
  const vless =
    "vless://9a8b7c6d-5e4f-4a3b-9c8d-7e6f5a4b3c2d@192.0.2.12:8443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=SbXXk6d6RLJtk3T5Ba7NcH8Q3Y7V1m2Z4x6K9J0H5G4&sid=abcd1234&type=tcp&flow=xtls-rprx-vision#" +
    encodeURIComponent("示例 VLESS Reality");
  const trojan = `trojan://trojan_secret@192.0.2.13:443?sni=example.com&type=tcp#${encodeURIComponent("示例 Trojan")}`;
  const hy2 = `hy2://hysteria_secret@192.0.2.14:8443/?sni=example.com&insecure=0#${encodeURIComponent("示例 Hysteria2")}`;
  return [ss, vmessNew, vmessOld, vless, trojan, hy2].join("\n");
}
