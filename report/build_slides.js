const pptxgen = require("pptxgenjs");
const path = require("path");

const IMG = path.join(__dirname, "diagrams_png");
const ip = f => path.join(IMG, f);

// ---- palette ----
const DARK = "0E1B2B", INK = "1F2937", MUTED = "667085";
const ACCENT = "2F6FED", GREEN = "1F9D55", AMBER = "B7791F", RED = "C0392B";
const CARD = "F3F7FD", CARD2 = "F2F8F4", LINEC = "E3E9F2", LIGHT = "DCE7F5";
const FONT = "Calibri", MONO = "Consolas";

// image aspect ratios (h / w)
const AR = {
  "system_architecture.png": 760 / 1360,
  "handshake_sequence.png": 1120 / 1360,
  "message_flow.png": 880 / 1360,
  "replay_window.png": 800 / 1360,
};

const pres = new pptxgen();
pres.layout = "LAYOUT_16x9";           // 10 x 5.625 in
pres.author = "COMP5355 Group";
pres.title = "End-to-End Encrypted Messaging — Cryptographic Design";

const shadow = () => ({ type: "outer", color: "9AA7B8", blur: 7, offset: 2, angle: 90, opacity: 0.28 });

function head(slide, n, title, dark) {
  slide.addShape(pres.shapes.OVAL, { x: 0.5, y: 0.43, w: 0.44, h: 0.44, fill: { color: ACCENT } });
  slide.addText(String(n).padStart(2, "0"), { x: 0.5, y: 0.43, w: 0.44, h: 0.44, align: "center", valign: "middle", color: "FFFFFF", fontSize: 13, bold: true, fontFace: FONT, margin: 0 });
  slide.addText(title, { x: 1.08, y: 0.4, w: 8.4, h: 0.5, fontSize: 23, bold: true, color: dark ? "FFFFFF" : INK, fontFace: FONT, valign: "middle", margin: 0 });
}
function card(slide, x, y, w, h, fill) {
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, fill: { color: fill || "FFFFFF" }, line: { color: LINEC, width: 1 }, rectRadius: 0.09, shadow: shadow() });
}
function footer(slide, dark) {
  slide.addText("COMP 5355 · E2EE Messaging (Task 1)", { x: 0.5, y: 5.28, w: 6, h: 0.3, fontSize: 9, color: dark ? "7E8CA0" : MUTED, fontFace: FONT, margin: 0 });
}
function bl(items) {
  return items.map((t, i) => ({ text: t, options: { bullet: { code: "2022", indent: 14 }, breakLine: true, paraSpaceAfter: 6 } }));
}
function img(slide, file, x, y, w) {
  slide.addImage({ path: ip(file), x, y, w, h: +(w * AR[file]).toFixed(2), altText: file });
  return +(w * AR[file]).toFixed(2);
}

// ============================================================ 1 TITLE
let s = pres.addSlide();
s.background = { color: DARK };
s.addShape(pres.shapes.OVAL, { x: 8.55, y: -1.1, w: 3.2, h: 3.2, fill: { color: "16314F" } });
s.addShape(pres.shapes.OVAL, { x: -0.9, y: 4.0, w: 2.6, h: 2.6, fill: { color: "13284A" }, line: { color: "1B3A5C", width: 1 } });
s.addText("COMP 5355  ·  CYBER AND INTERNET SECURITY  ·  2025/2026", { x: 0.7, y: 1.05, w: 8.6, h: 0.35, fontSize: 12, color: "8FB0E6", bold: true, charSpacing: 2, fontFace: FONT });
s.addText("End-to-End Encrypted\nMessaging System", { x: 0.66, y: 1.45, w: 8.8, h: 1.7, fontSize: 40, bold: true, color: "FFFFFF", fontFace: FONT, lineSpacingMultiple: 1.0 });
s.addText("Cryptographic Design & Per-Adversary Defense", { x: 0.7, y: 3.2, w: 8.6, h: 0.5, fontSize: 19, color: "C7D6EE", italic: true, fontFace: FONT });
s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.7, y: 4.05, w: 7.2, h: 0.55, fill: { color: "16314F" }, line: { color: ACCENT, width: 1 }, rectRadius: 0.1 });
s.addText("Ed25519  ·  X25519  ·  HKDF-SHA256  ·  ChaCha20-Poly1305", { x: 0.7, y: 4.05, w: 7.2, h: 0.55, align: "center", valign: "middle", fontSize: 13.5, color: "DCE9FF", bold: true, fontFace: MONO, margin: 0 });
s.addText("Task 1 · One-to-one E2EE messaging", { x: 0.7, y: 4.85, w: 8.6, h: 0.3, fontSize: 12, color: "7E8CA0", fontFace: FONT });

// ============================================================ 2 THREAT MODEL & GOALS
s = pres.addSlide(); s.background = { color: "FFFFFF" };
head(s, 2, "Threat Model & Security Goals");
card(s, 0.5, 1.3, 4.45, 3.8, CARD);
s.addText("Adversaries", { x: 0.75, y: 1.5, w: 4, h: 0.4, fontSize: 16, bold: true, color: ACCENT, fontFace: FONT, margin: 0 });
s.addText(bl([
  "A1  Passive network — records all ciphertext & metadata",
  "A2  Active network — tamper, replay, inject, MitM",
  "A3  Honest-but-curious server — reads all it relays",
  "A4  Transient endpoint compromise   (bonus)",
  "A5  Malicious server — fake keys, tampering   (bonus)",
]), { x: 0.78, y: 1.95, w: 4.05, h: 3.05, fontSize: 12.5, color: INK, fontFace: FONT, valign: "top" });

card(s, 5.05, 1.3, 4.45, 3.8, CARD2);
s.addText("Security Requirements", { x: 5.3, y: 1.5, w: 4, h: 0.4, fontSize: 16, bold: true, color: GREEN, fontFace: FONT, margin: 0 });
s.addText(bl([
  "SR1  Confidentiality — plaintext only at endpoints",
  "SR2  Integrity — reject any altered ciphertext",
  "SR3  Authenticity — verify the real sender",
  "SR4  Replay protection — no duplicate effect",
  "SR5  Forward secrecy   (bonus)",
  "SR6  Malicious-server resistance   (bonus)",
]), { x: 5.33, y: 1.95, w: 4.05, h: 3.05, fontSize: 12.5, color: INK, fontFace: FONT, valign: "top" });
footer(s);

// ============================================================ 3 ARCHITECTURE
s = pres.addSlide(); s.background = { color: "FFFFFF" };
head(s, 3, "System Architecture & Trust Boundaries");
s.addText(bl([
  "Endpoints are the sole trust anchors — only they hold keys and see plaintext.",
  "Relay server is honest-but-curious: it sees only ciphertext + routing metadata.",
  "Network is fully adversarial — all security is established cryptographically.",
  "No TLS assumed: signed handshake protects key distribution against A2.",
]), { x: 0.55, y: 1.45, w: 3.95, h: 3.4, fontSize: 13.5, color: INK, fontFace: FONT, valign: "top" });
img(s, "system_architecture.png", 4.75, 1.75, 4.85);
footer(s);

// ============================================================ 4 PRIMITIVES
s = pres.addSlide(); s.background = { color: "FFFFFF" };
head(s, 4, "Cryptographic Primitives");
const hdr = (t) => ({ text: t, options: { bold: true, color: "FFFFFF", fill: { color: DARK }, fontFace: FONT, fontSize: 13, valign: "middle" } });
const rows = [
  [hdr("Purpose"), hdr("Primitive"), hdr("Role")],
  ["Identity", "Ed25519", "Sign handshake transcript → establish identity"],
  ["Key agreement", "X25519 (ephemeral)", "ECDH shared secret; one-time → forward secrecy"],
  ["Key derivation", "HKDF-SHA256", "Derive uniform, purpose-bound session keys"],
  ["Authenticated encryption", "ChaCha20-Poly1305", "Confidentiality + integrity + authenticity"],
  ["Password storage", "scrypt (salted)", "Memory-hard one-way hash for accounts"],
];
s.addTable(rows, {
  x: 0.5, y: 1.45, w: 9.0, colW: [2.1, 2.5, 4.4],
  rowH: [0.45, 0.62, 0.62, 0.62, 0.62, 0.62],
  fontSize: 12.5, fontFace: FONT, color: INK, valign: "middle",
  border: { pt: 1, color: LINEC }, align: "left",
  margin: [4, 8, 4, 8],
  fill: { color: "FFFFFF" },
});
card(s, 0.5, 5.0, 9.0, 0.5, "FFF7E6");
s.addText("Vetted library only (Python cryptography) — no primitive is hand-rolled; design = composing standard building blocks.", { x: 0.5, y: 5.0, w: 9.0, h: 0.5, align: "center", valign: "middle", fontSize: 12, italic: true, color: AMBER, fontFace: FONT, margin: 0 });

// ============================================================ 5 KEY HIERARCHY
s = pres.addSlide(); s.background = { color: "FFFFFF" };
head(s, 5, "Key Hierarchy & Lifecycle");
const kx = [0.5, 3.68, 6.86], kw = 2.96;
const kdata = [
  ["1", "Identity key", "Ed25519", "Long-term. Generated at registration, stored locally (never uploaded). Signs handshakes.", ACCENT],
  ["2", "Ephemeral key", "X25519", "Per session. Fresh each handshake, discarded right after — the basis of forward secrecy.", GREEN],
  ["3", "Session keys", "HKDF-SHA256", "Two directional AEAD keys (k_i2r, k_r2i) per session. Live only for the conversation.", AMBER],
];
kdata.forEach((d, i) => {
  card(s, kx[i], 1.45, kw, 3.5, "FFFFFF");
  s.addShape(pres.shapes.OVAL, { x: kx[i] + 0.22, y: 1.7, w: 0.5, h: 0.5, fill: { color: d[4] } });
  s.addText(d[0], { x: kx[i] + 0.22, y: 1.7, w: 0.5, h: 0.5, align: "center", valign: "middle", color: "FFFFFF", bold: true, fontSize: 16, fontFace: FONT, margin: 0 });
  s.addText(d[1], { x: kx[i] + 0.22, y: 2.32, w: kw - 0.44, h: 0.4, fontSize: 16, bold: true, color: INK, fontFace: FONT, margin: 0 });
  s.addText(d[2], { x: kx[i] + 0.22, y: 2.72, w: kw - 0.44, h: 0.35, fontSize: 12.5, bold: true, color: d[4], fontFace: MONO, margin: 0 });
  s.addText(d[3], { x: kx[i] + 0.22, y: 3.12, w: kw - 0.44, h: 1.7, fontSize: 12.5, color: "44505F", fontFace: FONT, valign: "top", margin: 0 });
});
footer(s);

// ============================================================ 6 HANDSHAKE
s = pres.addSlide(); s.background = { color: "FFFFFF" };
head(s, 6, "Authenticated Key Exchange");
const hh = img(s, "handshake_sequence.png", 0.5, 1.4, 4.45);
s.addText(bl([
  "Each party signs its handshake transcript with its Ed25519 identity key.",
  "Both signatures cover BOTH identity keys → blocks identity-misbinding / UKS.",
  "Responder also signs the initiator's ephemeral key → binds the whole transcript.",
  "Verify-or-reject: an attacker without the identity key cannot complete it → MitM (A2) defeated, satisfying SR3.",
]), { x: 5.15, y: 1.5, w: 4.35, h: 3.4, fontSize: 13, color: INK, fontFace: FONT, valign: "top" });
footer(s);

// ============================================================ 7 FORWARD SECRECY
s = pres.addSlide(); s.background = { color: "FFFFFF" };
head(s, 7, "Forward Secrecy  (B1, SR5)");
s.addText(bl([
  "Session keys come from ephemeral X25519, not from the long-term key.",
  "Ephemeral private keys are destroyed once the handshake completes.",
  "Stealing an identity key later cannot recompute past shared secrets — recorded ciphertext stays unreadable.",
]), { x: 0.55, y: 1.45, w: 4.5, h: 3.4, fontSize: 13.5, color: INK, fontFace: FONT, valign: "top" });
card(s, 5.2, 1.45, 4.3, 2.35, "0E1B2B");
s.addText("Directional key derivation", { x: 5.42, y: 1.6, w: 4, h: 0.35, fontSize: 12.5, bold: true, color: "8FB0E6", fontFace: FONT, margin: 0 });
s.addText([
  { text: "shared = X25519(my_eph, peer_eph)\n", options: { breakLine: true } },
  { text: "salt   = init_eph || resp_eph\n", options: { breakLine: true } },
  { text: "k_i2r  = HKDF(shared, salt, \"…|i2r\")\n", options: { breakLine: true } },
  { text: "k_r2i  = HKDF(shared, salt, \"…|r2i\")", options: {} },
], { x: 5.42, y: 2.0, w: 3.95, h: 1.7, fontSize: 11.5, color: "D7E6FF", fontFace: MONO, valign: "top", margin: 0 });
card(s, 5.2, 3.95, 4.3, 1.0, "F2F8F4");
s.addText([
  { text: "Why two keys?  ", options: { bold: true, color: GREEN } },
  { text: "Each direction has its own key, so both counters can start at 0 without ever reusing a (key, nonce) pair.", options: { color: "44505F" } },
], { x: 5.42, y: 4.05, w: 3.9, h: 0.8, fontSize: 12, fontFace: FONT, valign: "middle", margin: 0 });
footer(s);

// ============================================================ 8 AEAD MESSAGES
s = pres.addSlide(); s.background = { color: "FFFFFF" };
head(s, 8, "Authenticated Message Encryption");
s.addText(bl([
  "ChaCha20-Poly1305 AEAD → confidentiality (SR1) + integrity (SR2).",
  "Associated data binds from‖to‖session_id‖counter (0x1f-separated).",
  "Nonce = counter; per-direction key ⇒ nonce never reused.",
  "Strict order: verify tag → check replay window → deliver.",
]), { x: 0.55, y: 1.45, w: 3.95, h: 3.4, fontSize: 13, color: INK, fontFace: FONT, valign: "top" });
img(s, "message_flow.png", 4.7, 1.55, 4.9);
footer(s);

// ============================================================ 9 REPLAY
s = pres.addSlide(); s.background = { color: "FFFFFF" };
head(s, 9, "Replay Protection  (SR4)");
s.addText("Monotonic counter + RFC 6479-style sliding bitmap window; tag is verified before the window updates, so forged frames cannot poison it.", { x: 0.6, y: 1.18, w: 8.8, h: 0.5, fontSize: 12.5, color: MUTED, italic: true, fontFace: FONT, align: "center", margin: 0 });
img(s, "replay_window.png", 2.03, 1.6, 5.95);
footer(s);

// ============================================================ 10 MALICIOUS SERVER
s = pres.addSlide(); s.background = { color: "FFFFFF" };
head(s, 10, "Malicious-Server Resistance  (B2, SR6)");
card(s, 0.5, 1.45, 4.45, 3.5, "FFFFFF");
s.addText("Integrity survives a bad server", { x: 0.75, y: 1.62, w: 4, h: 0.4, fontSize: 15, bold: true, color: ACCENT, fontFace: FONT, margin: 0 });
s.addText(bl([
  "Messages are end-to-end AEAD-protected.",
  "Server tampering / injection fails the Poly1305 tag → rejected.",
  "SR2 holds without trusting the server.",
]), { x: 0.78, y: 2.05, w: 3.95, h: 2.8, fontSize: 13, color: INK, fontFace: FONT, valign: "top" });

card(s, 5.05, 1.45, 4.45, 3.5, "FFFFFF");
s.addText("Detecting fake keys", { x: 5.3, y: 1.62, w: 4, h: 0.4, fontSize: 15, bold: true, color: GREEN, fontFace: FONT, margin: 0 });
s.addText(bl([
  "Safety number = order-independent hash of both identity keys.",
  "Users compare it out of band; a match rules out a MitM.",
  "Limitation: manual compare, no persistent TOFU store yet.",
]), { x: 5.33, y: 2.05, w: 3.95, h: 2.8, fontSize: 13, color: INK, fontFace: FONT, valign: "top" });
footer(s);

// ============================================================ 11 DEFENSE MAPPING
s = pres.addSlide(); s.background = { color: "FFFFFF" };
head(s, 11, "Per-Adversary Defense Mapping");
const H = t => ({ text: t, options: { bold: true, color: "FFFFFF", fill: { color: DARK }, fontFace: FONT, fontSize: 13 } });
const map = [
  [H("Adversary / Attack"), H("Mechanism"), H("Satisfies")],
  ["A1  Passive eavesdrop", "ChaCha20-Poly1305 encryption", "SR1"],
  ["A2  Tamper", "Poly1305 authentication tag", "SR2"],
  ["A2  Forge / inject", "No session key ⇒ no valid tag", "SR3"],
  ["A2  Man-in-the-middle", "Signed handshake + identity binding", "SR3"],
  ["A2  Replay", "Counter + sliding window + AD", "SR4"],
  ["A3  Curious server", "End-to-end encryption (no keys at server)", "SR1"],
  ["A4  Key compromise", "Ephemeral keys, discarded per session", "SR5 / B1"],
  ["A5  Malicious server", "AEAD integrity + out-of-band safety number", "SR6 / B2"],
];
s.addTable(map, {
  x: 0.5, y: 1.4, w: 9.0, colW: [3.2, 4.3, 1.5],
  rowH: 0.4, fontSize: 12, fontFace: FONT, color: INK, valign: "middle",
  border: { pt: 1, color: LINEC }, margin: [3, 8, 3, 8],
  fill: { color: "FFFFFF" },
});
footer(s);

// ============================================================ 12 CONCLUSION
s = pres.addSlide(); s.background = { color: DARK };
s.addText("Validation & Takeaways", { x: 0.6, y: 0.6, w: 9, h: 0.7, fontSize: 28, bold: true, color: "FFFFFF", fontFace: FONT });
const stats = [["68", "automated tests passing"], ["5", "vetted primitives, 0 home-made"], ["B1+B2", "bonus goals covered"]];
const sx = [0.6, 3.78, 6.96];
stats.forEach((st, i) => {
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: sx[i], y: 1.6, w: 2.86, h: 1.55, fill: { color: "16314F" }, line: { color: "27496E", width: 1 }, rectRadius: 0.1 });
  s.addText(st[0], { x: sx[i], y: 1.72, w: 2.86, h: 0.85, align: "center", color: "6FA8FF", bold: true, fontSize: 38, fontFace: FONT, margin: 0 });
  s.addText(st[1], { x: sx[i] + 0.15, y: 2.58, w: 2.56, h: 0.5, align: "center", color: "C7D6EE", fontSize: 12.5, fontFace: FONT, margin: 0 });
});
s.addText(bl([
  "A precise threat model with a per-adversary, mechanism-level defense argument.",
  "Correct composition of standard primitives — nonce-safe, HKDF-bound, replay-hard.",
  "Verified by a real WebSocket full-stack test and a live two-client browser demo.",
]), { x: 0.62, y: 3.5, w: 8.9, h: 1.5, fontSize: 13.5, color: "DCE7F5", fontFace: FONT, valign: "top" });
s.addText("Thank you — questions welcome.", { x: 0.62, y: 4.95, w: 8.9, h: 0.4, fontSize: 13, italic: true, color: "8FB0E6", fontFace: FONT });

pres.writeFile({ fileName: path.join(__dirname, "COMP5355_E2EE_Defense_EN.pptx") }).then(f => console.log("written:", f));
