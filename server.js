import http from "node:http";
import crypto from "node:crypto";
import { createClient } from "@libsql/client";

const PORT = Number(process.env.PORT || 10000);

const TURSO_DATABASE_URL = process.env.TURSO_DATABASE_URL;
const TURSO_AUTH_TOKEN = process.env.TURSO_AUTH_TOKEN;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";

const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

if (!TURSO_DATABASE_URL) {
  throw new Error("Missing env variable: TURSO_DATABASE_URL");
}

if (!TURSO_AUTH_TOKEN) {
  throw new Error("Missing env variable: TURSO_AUTH_TOKEN");
}

const db = createClient({
  url: TURSO_DATABASE_URL,
  authToken: TURSO_AUTH_TOKEN
});

const allowedRarities = new Set([
  "common",
  "uncommon",
  "rare",
  "epic",
  "legendary",
  "mythic",
  "exotic"
]);

function getCorsOrigin(req) {
  if (CORS_ORIGIN === "*") {
    return "*";
  }

  const origin = req.headers.origin || "";
  const allowedOrigins = CORS_ORIGIN
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

  if (allowedOrigins.includes(origin)) {
    return origin;
  }

  return allowedOrigins[0] || "*";
}

function sendJson(req, res, statusCode, data) {
  const body = JSON.stringify(data);

  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": getCorsOrigin(req),
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Token",
    "Access-Control-Max-Age": "86400"
  });

  res.end(body);
}

function sendOptions(req, res) {
  res.writeHead(204, {
    "Access-Control-Allow-Origin": getCorsOrigin(req),
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Token",
    "Access-Control-Max-Age": "86400"
  });

  res.end();
}

function readBody(req, maxBytes = 8_000_000) {
  return new Promise((resolve, reject) => {
    let body = "";
    let received = 0;
    let failed = false;

    req.on("data", (chunk) => {
      if (failed) {
        return;
      }

      received += chunk.length;

      if (received > maxBytes) {
        failed = true;
        const error = new Error("Request body too large.");
        error.statusCode = 413;
        reject(error);
        req.pause();
        return;
      }

      body += chunk;
    });

    req.on("end", () => {
      if (!failed) {
        resolve(body);
      }
    });

    req.on("error", reject);
  });
}

function normalizeCardPayload(payload) {
  if (payload && typeof payload === "object" && payload.card) {
    return payload.card;
  }

  return payload;
}

function validateCard(card) {
  const errors = [];

  if (!card || typeof card !== "object" || Array.isArray(card)) {
    errors.push("Card must be an object.");
    return errors;
  }

  if (typeof card.id !== "string" || !card.id.trim()) {
    errors.push("Card id is required.");
  }

  if (typeof card.name !== "string" || !card.name.trim()) {
    errors.push("Card name is required.");
  }

  if (!Number.isFinite(Number(card.attack))) {
    errors.push("Card attack must be a number.");
  }

  if (!Number.isFinite(Number(card.defense))) {
    errors.push("Card defense must be a number.");
  }

  if (typeof card.rarity !== "string" || !allowedRarities.has(card.rarity)) {
    errors.push("Card rarity is invalid.");
  }

  if (typeof card.description !== "string" || !card.description.trim()) {
    errors.push("Card description is required.");
  }

  if (typeof card.image !== "string" || !card.image.trim()) {
    errors.push("Card image path is required.");
  }

  if (card.effects !== undefined) {
    if (!Array.isArray(card.effects)) {
      errors.push("Card effects must be an array.");
    } else {
      for (const effect of card.effects) {
        if (!effect || typeof effect !== "object" || Array.isArray(effect)) {
          errors.push("Every effect must be an object.");
          break;
        }

        if (typeof effect.type !== "string" || !effect.type.trim()) {
          errors.push("Every effect needs a type.");
          break;
        }
      }
    }
  }

  if (card.image_base64 !== undefined) {
    if (
      typeof card.image_base64 !== "string" ||
      !card.image_base64.startsWith("data:image/")
    ) {
      errors.push("image_base64 must be a valid image data URL.");
    }

    if (typeof card.image_base64 === "string" && card.image_base64.length > 7_000_000) {
      errors.push("image_base64 is too large.");
    }
  }

  if (card.image_filename !== undefined && typeof card.image_filename !== "string") {
    errors.push("image_filename must be a string.");
  }

  if (card.image_mime !== undefined && typeof card.image_mime !== "string") {
    errors.push("image_mime must be a string.");
  }

  if (
    card.image_size_bytes !== undefined &&
    !Number.isFinite(Number(card.image_size_bytes))
  ) {
    errors.push("image_size_bytes must be a number.");
  }

  return errors;
}

function isAdmin(req) {
  if (!ADMIN_TOKEN) {
    return false;
  }

  const auth = req.headers.authorization || "";
  const bearerToken = auth.startsWith("Bearer ")
    ? auth.slice("Bearer ".length)
    : "";

  const headerToken = req.headers["x-admin-token"] || "";

  return bearerToken === ADMIN_TOKEN || headerToken === ADMIN_TOKEN;
}

async function migrate() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS card_submissions (
      id TEXT PRIMARY KEY,
      card_id TEXT NOT NULL,
      card_name TEXT NOT NULL,
      rarity TEXT NOT NULL,
      raw_json TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.execute(`
    CREATE INDEX IF NOT EXISTS idx_card_submissions_created_at
    ON card_submissions(created_at)
  `);

  await db.execute(`
    CREATE INDEX IF NOT EXISTS idx_card_submissions_status
    ON card_submissions(status)
  `);

  await db.execute(`
    CREATE INDEX IF NOT EXISTS idx_card_submissions_card_id
    ON card_submissions(card_id)
  `);
}

async function handleSubmitCard(req, res) {
  const rawBody = await readBody(req);

  let payload;

  try {
    payload = JSON.parse(rawBody);
  } catch {
    return sendJson(req, res, 400, {
      ok: false,
      error: "Invalid JSON body."
    });
  }

  const card = normalizeCardPayload(payload);
  const errors = validateCard(card);

  if (errors.length > 0) {
    return sendJson(req, res, 400, {
      ok: false,
      errors
    });
  }

  const normalizedCard = {
    ...card,
    id: card.id.trim(),
    name: card.name.trim(),
    attack: Number(card.attack),
    defense: Number(card.defense),
    rarity: card.rarity.trim(),
    description: card.description.trim(),
    image: card.image.trim()
  };

  if (card.image_base64) {
    normalizedCard.image_base64 = card.image_base64;
  }

  if (card.image_filename) {
    normalizedCard.image_filename = card.image_filename;
  }

  if (card.image_mime) {
    normalizedCard.image_mime = card.image_mime;
  }

  if (card.image_size_bytes !== undefined) {
    normalizedCard.image_size_bytes = Number(card.image_size_bytes);
  }

  const submissionId = crypto.randomUUID();
  const rawJson = JSON.stringify(normalizedCard, null, 2);

  await db.execute({
    sql: `
      INSERT INTO card_submissions (
        id,
        card_id,
        card_name,
        rarity,
        raw_json,
        status
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `,
    args: [
      submissionId,
      normalizedCard.id,
      normalizedCard.name,
      normalizedCard.rarity,
      rawJson,
      "pending"
    ]
  });

  return sendJson(req, res, 201, {
    ok: true,
    message: "Card submitted.",
    submission: {
      id: submissionId,
      card_id: normalizedCard.id,
      card_name: normalizedCard.name,
      rarity: normalizedCard.rarity,
      status: "pending"
    }
  });
}

async function handleListCards(req, res) {
  if (!isAdmin(req)) {
    return sendJson(req, res, 401, {
      ok: false,
      error: "Admin token required."
    });
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const status = url.searchParams.get("status") || "";
  const limitRaw = Number(url.searchParams.get("limit") || 100);
  const limit = Math.min(Math.max(limitRaw, 1), 500);

  let result;

  if (status) {
    result = await db.execute({
      sql: `
        SELECT id, card_id, card_name, rarity, raw_json, status, created_at
        FROM card_submissions
        WHERE status = ?
        ORDER BY created_at DESC
        LIMIT ?
      `,
      args: [status, limit]
    });
  } else {
    result = await db.execute({
      sql: `
        SELECT id, card_id, card_name, rarity, raw_json, status, created_at
        FROM card_submissions
        ORDER BY created_at DESC
        LIMIT ?
      `,
      args: [limit]
    });
  }

  return sendJson(req, res, 200, {
    ok: true,
    cards: result.rows
  });
}

async function handleExportCards(req, res) {
  if (!isAdmin(req)) {
    return sendJson(req, res, 401, {
      ok: false,
      error: "Admin token required."
    });
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const status = url.searchParams.get("status") || "";

  let result;

  if (status) {
    result = await db.execute({
      sql: `
        SELECT raw_json
        FROM card_submissions
        WHERE status = ?
        ORDER BY created_at DESC
      `,
      args: [status]
    });
  } else {
    result = await db.execute(`
      SELECT raw_json
      FROM card_submissions
      ORDER BY created_at DESC
    `);
  }

  const cards = result.rows.map((row) => JSON.parse(row.raw_json));

  return sendJson(req, res, 200, {
    ok: true,
    cards
  });
}

async function handleUpdateStatus(req, res) {
  if (!isAdmin(req)) {
    return sendJson(req, res, 401, {
      ok: false,
      error: "Admin token required."
    });
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  const id = decodeURIComponent(
    pathname.slice("/api/cards/".length, -"/status".length)
  );

  const rawBody = await readBody(req);

  let payload;

  try {
    payload = JSON.parse(rawBody);
  } catch {
    return sendJson(req, res, 400, {
      ok: false,
      error: "Invalid JSON body."
    });
  }

  const allowedStatuses = new Set(["pending", "approved", "rejected"]);
  const status = String(payload.status || "").trim();

  if (!allowedStatuses.has(status)) {
    return sendJson(req, res, 400, {
      ok: false,
      error: "Invalid status. Use pending, approved, or rejected."
    });
  }

  await db.execute({
    sql: `
      UPDATE card_submissions
      SET status = ?
      WHERE id = ?
    `,
    args: [status, id]
  });

  return sendJson(req, res, 200, {
    ok: true,
    id,
    status
  });
}

async function router(req, res) {
  if (req.method === "OPTIONS") {
    return sendOptions(req, res);
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  try {
    if (req.method === "GET" && pathname === "/health") {
      return sendJson(req, res, 200, {
        ok: true,
        service: "darkest-cards-api"
      });
    }

    if (req.method === "POST" && pathname === "/api/cards") {
      return await handleSubmitCard(req, res);
    }

    if (req.method === "GET" && pathname === "/api/cards") {
      return await handleListCards(req, res);
    }

    if (req.method === "GET" && pathname === "/api/cards/export") {
      return await handleExportCards(req, res);
    }

    if (
      req.method === "POST" &&
      pathname.startsWith("/api/cards/") &&
      pathname.endsWith("/status")
    ) {
      return await handleUpdateStatus(req, res);
    }

    return sendJson(req, res, 404, {
      ok: false,
      error: "Not found."
    });
  } catch (error) {
    console.error(error);

    return sendJson(req, res, error.statusCode || 500, {
      ok: false,
      error: error.statusCode === 413
        ? "Request body too large."
        : "Internal server error."
    });
  }
}

await migrate();

const server = http.createServer(router);

server.listen(PORT, () => {
  console.log(`Darkest Cards API running on port ${PORT}`);
});