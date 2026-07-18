// Stand-in for n8n's Webhook node -- same HTTP contract (POST JSON,
// 200 OK) -- used only to prove ingest.mjs's webhook leg end-to-end in
// this sandbox, where installing real n8n hits a blocked CDN dependency.
import { createServer } from "node:http";
createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    console.log("[webhook-stub] received:", body);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
  });
}).listen(5678, () => console.log("webhook-stub listening on :5678"));
