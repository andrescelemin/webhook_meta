// app.js
import express from "express";
import crypto from "crypto";

const app = express();

// --- Config ---
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || "changeme-verify-token";
const APP_SECRET = process.env.APP_SECRET || ""; // Opcional (para validar firma)
const PORT = process.env.PORT || 3000;

// Necesitamos el body en RAW para validar la firma. Luego parseamos JSON manualmente.
app.use(
  express.raw({
    type: "*/*",
    limit: "2mb",
  })
);

// --- Helpers ---
function validateSignature(req) {
  if (!APP_SECRET) return true; // si no seteas APP_SECRET, saltamos validación
  const signature = req.header("X-Hub-Signature-256");
  if (!signature) return false;

  // Firma: sha256=...
  const expected = "sha256=" + crypto.createHmac("sha256", APP_SECRET).update(req.body).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

// --- GET /webhook (Verificación de Meta) ---
app.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === VERIFY_TOKEN) {
    console.log("[Webhook] Verificado correctamente");
    return res.status(200).send(challenge);
  } else {
    console.warn("[Webhook] Verificación fallida");
    return res.sendStatus(403);
  }
});

// --- POST /webhook (Eventos de Meta) ---
app.post("/webhook", (req, res) => {
  // Valida firma si hay APP_SECRET
  if (!validateSignature(req)) {
    console.warn("[Webhook] Firma inválida");
    return res.sendStatus(401);
  }

  // Intenta parsear body a JSON
  let payload = {};
  try {
    payload = JSON.parse(req.body.toString("utf8") || "{}");
  } catch (e) {
    console.error("[Webhook] JSON inválido", e);
  }

  console.log("[Webhook] Evento recibido:", JSON.stringify(payload, null, 2));

  // Responde 200 de inmediato para no reintentos
  res.sendStatus(200);

  // Aquí maneja tus casos (WhatsApp o Messenger)
  // Ejemplo WhatsApp Business:
  // payload.entry?.forEach(entry => {
  //   entry.changes?.forEach(change => {
  //     const value = change.value;
  //     const messages = value.messages;
  //     if (messages && messages.length) {
  //       const msg = messages[0];
  //       console.log("Mensaje entrante:", msg.from, msg.type, msg.text?.body);
  //       // TODO: responder usando tu proveedor (Cloud API) si corresponde
  //     }
  //   });
  // });
});

// --- Healthcheck ---
app.get("/", (_req, res) => {
  res.status(200).send("OK - Meta Webhook up");
});

// --- Start ---
app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
});
