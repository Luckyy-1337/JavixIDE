import http from "node:http";
import crypto from "node:crypto";

const port = Number(process.env.PORT) || 8080;
const requireHttps = process.env.ALLOW_HTTP !== "1";
const wsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const deviceIdPattern = /^jvx-[0-9a-f]{16}$/;
const routePattern = /^\/u\/(jvx-[0-9a-f]{16})(\/.*)?$/;
const wellKnownRoutePattern = /^\/(\.well-known\/[^/]+)\/u\/(jvx-[0-9a-f]{16})(\/.*)?$/;

const sessions = new Map();

const baseHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS, DELETE",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept, Mcp-Session-Id, Mcp-Protocol-Version",
  "Access-Control-Expose-Headers": "Mcp-Session-Id, WWW-Authenticate",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
};

function hashToken(token) {
  return crypto.createHash("sha256").update(token, "utf8").digest("hex");
}

function writeJson(res, status, data) {
  const payload = Buffer.from(JSON.stringify(data), "utf8");
  res.writeHead(status, {
    ...baseHeaders,
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": payload.length,
  });
  res.end(payload);
}

function writeFrame(socket, opcode, data) {
  if (!socket || socket.destroyed) return;
  const len = data.length;
  let head;
  if (len <= 125) {
    head = Buffer.from([0x80 | opcode, len]);
  } else if (len <= 65535) {
    head = Buffer.alloc(4);
    head[0] = 0x80 | opcode;
    head[1] = 126;
    head.writeUInt16BE(len, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 0x80 | opcode;
    head[1] = 127;
    head.writeBigUInt64BE(BigInt(len), 2);
  }
  socket.write(Buffer.concat([head, data]));
}

function sendJsonFrame(socket, obj) {
  writeFrame(socket, 0x1, Buffer.from(JSON.stringify(obj), "utf8"));
}

function bindSocketReader(socket, onText, onDrop) {
  let buffer = Buffer.alloc(0);
  let fragments = [];
  let fragmentedOpcode = 0;

  socket.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (buffer.length >= 2) {
      const fin = (buffer[0] & 0x80) !== 0;
      const opcode = buffer[0] & 0x0f;
      const masked = (buffer[1] & 0x80) !== 0;
      let length = buffer[1] & 0x7f;
      let pos = 2;

      if (length === 126) {
        if (buffer.length < 4) return;
        length = buffer.readUInt16BE(2);
        pos = 4;
      } else if (length === 127) {
        if (buffer.length < 10) return;
        length = Number(buffer.readBigUInt64BE(2));
        pos = 10;
      }

      const maskSize = masked ? 4 : 0;
      if (buffer.length < pos + maskSize + length) return;

      let body = buffer.subarray(pos + maskSize, pos + maskSize + length);
      if (masked) {
        const mask = buffer.subarray(pos, pos + 4);
        const out = Buffer.alloc(length);
        for (let i = 0; i < length; i++) {
          out[i] = body[i] ^ mask[i & 3];
        }
        body = out;
      }
      buffer = buffer.subarray(pos + maskSize + length);

      if (opcode === 0x8) {
        socket.end();
        return;
      }
      if (opcode === 0x9) {
        writeFrame(socket, 0x0a, body);
        continue;
      }
      if (opcode === 0x0a) {
        continue;
      }

      if (opcode === 0x1 || opcode === 0x2) {
        if (fin && fragmentedOpcode === 0) {
          onText(body.toString("utf8"));
        } else {
          fragmentedOpcode = opcode;
          fragments = [Buffer.from(body)];
        }
      } else if (opcode === 0x0 && fragmentedOpcode !== 0) {
        fragments.push(Buffer.from(body));
        if (fin) {
          const merged = Buffer.concat(fragments);
          fragments = [];
          fragmentedOpcode = 0;
          onText(merged.toString("utf8"));
        }
      }
    }
  });

  socket.on("close", onDrop);
  socket.on("error", onDrop);
}

function hasSecretInUrl(url) {
  return (
    url.pathname.includes("jvx_live_") ||
    url.pathname.includes("jvx_oauth_") ||
    url.searchParams.has("token") ||
    url.searchParams.has("access_token") ||
    url.searchParams.has("key")
  );
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const parts = [];
    req.on("data", (c) => parts.push(c));
    req.on("end", () => resolve(Buffer.concat(parts).toString("utf8")));
    req.on("error", reject);
  });
}

function normalizeHeaders(raw) {
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    out[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v ?? "");
  }
  return out;
}

function resolveRoute(pathname) {
  const direct = pathname.match(routePattern);
  if (direct) {
    return { deviceId: direct[1], path: direct[2] || "/mcp" };
  }
  const wk = pathname.match(wellKnownRoutePattern);
  if (wk) {
    return { deviceId: wk[2], path: "/" + wk[1] };
  }
  return null;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", `https://${req.headers.host || "localhost"}`);

  if (req.method === "OPTIONS") {
    res.writeHead(204, baseHeaders);
    res.end();
    return;
  }

  const proto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
  if (requireHttps && proto && proto !== "https") {
    writeJson(res, 403, { error: "https_required" });
    return;
  }

  if (hasSecretInUrl(url)) {
    writeJson(res, 400, { error: "token_in_url_forbidden" });
    return;
  }

  const target = resolveRoute(url.pathname);
  if (!target) {
    writeJson(res, 200, { ok: true });
    return;
  }

  const { deviceId, path } = target;
  const session = sessions.get(deviceId);

  if (!session || !session.socket || session.socket.destroyed) {
    writeJson(res, 503, {
      jsonrpc: "2.0",
      error: { code: -32000, message: "Device offline" },
    });
    return;
  }

  try {
    const body = await readBody(req);
    const reqId = crypto.randomUUID();
    const headers = normalizeHeaders(req.headers);

    const reply = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        session.inflight.delete(reqId);
        reject(new Error("Request timeout"));
      }, 60000);

      session.inflight.set(reqId, { resolve, reject, timer });
      sendJsonFrame(session.socket, {
        type: "mcp_request",
        reqId,
        method: req.method || "POST",
        path,
        query: url.search ? url.search.slice(1) : "",
        sourceIp: headers["x-forwarded-for"] || req.socket.remoteAddress || "",
        headers,
        body,
      });
    });

    const outBody = reply.isBase64 && reply.body
      ? Buffer.from(reply.body, "base64")
      : Buffer.from(reply.body || "", "utf8");

    res.writeHead(reply.status || 200, {
      ...baseHeaders,
      ...(reply.headers || {}),
      "Content-Length": outBody.length,
    });
    res.end(outBody);
  } catch (err) {
    writeJson(res, 504, {
      jsonrpc: "2.0",
      error: { code: -32603, message: String(err.message || err) },
    });
  }
});

server.on("upgrade", (req, socket) => {
  const url = new URL(req.url || "/", `https://${req.headers.host || "localhost"}`);
  if (url.pathname !== "/ws/device") {
    socket.end("HTTP/1.1 404 Not Found\r\n\r\n");
    return;
  }

  const deviceId = String(req.headers["x-javix-device-id"] || "");
  const auth = String(req.headers["authorization"] || "");
  const wsKey = String(req.headers["sec-websocket-key"] || "");
  const tokenGen = Number(req.headers["x-javix-token-gen"]) || 1;

  if (!deviceIdPattern.test(deviceId) || !auth.startsWith("Bearer jvx_live_") || !wsKey) {
    socket.end("HTTP/1.1 401 Unauthorized\r\n\r\n");
    return;
  }

  const tokenHash = hashToken(auth.slice(7).trim());
  const prev = sessions.get(deviceId);
  if (prev && tokenGen < prev.tokenGen && tokenHash !== prev.tokenHash) {
    socket.end("HTTP/1.1 401 Unauthorized\r\n\r\n");
    return;
  }

  if (prev && prev.socket && !prev.socket.destroyed) {
    prev.socket.destroy();
  }

  const accept = crypto.createHash("sha1").update(wsKey + wsMagic).digest("base64");
  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );

  const session = {
    socket,
    tokenHash,
    tokenGen,
    inflight: new Map(),
  };
  sessions.set(deviceId, session);

  bindSocketReader(
    socket,
    (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw);
      } catch {
        return;
      }

      if (msg.type === "ping") {
        sendJsonFrame(socket, { type: "pong", ts: msg.ts || Date.now() });
        return;
      }

      if (msg.type === "register" || msg.type === "token_rotate") {
        const nextHash = msg.newTokenSha256 || msg.tokenSha256;
        if (nextHash) {
          session.tokenHash = nextHash;
          session.tokenGen = msg.tokenGen || session.tokenGen + 1;
        }
        return;
      }

      if (msg.type === "mcp_response" && msg.reqId) {
        const item = session.inflight.get(msg.reqId);
        if (item) {
          clearTimeout(item.timer);
          session.inflight.delete(msg.reqId);
          item.resolve(msg);
        }
      }
    },
    () => {
      if (sessions.get(deviceId) !== session) return;
      for (const item of session.inflight.values()) {
        clearTimeout(item.timer);
        item.reject(new Error("Device disconnected"));
      }
      session.inflight.clear();
      session.socket = null;
    }
  );
});

server.listen(port, "0.0.0.0");
