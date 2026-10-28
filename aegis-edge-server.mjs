#!/usr/bin/env node
/**
 * DoNotEncode.ai — Hardened Edge Protection Server, Live URL Scanner & Threat Radar
 */

import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compileProtectedBundle } from './aegis-compiler.mjs';
import { AegisEdgeGate } from './aegis-edge-gate.mjs';
import { AegisDiagnosticAuditEngine, validateSafeAuditUrl } from './aegis-audit-engine.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const HARDENED_SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-Aegis-Shield': 'v6.0-SOVEREIGN',
};

const MAX_JSON_BODY_BYTES = 16 * 1024; // 16 KB strict cap against OOM body floods
const BODY_READ_TIMEOUT_MS = 5000;

function safeJsonParse(rawText) {
  return JSON.parse(rawText, (key, value) => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return undefined;
    }
    return value;
  });
}

async function readBoundedBody(req, maxBytes = MAX_JSON_BODY_BYTES) {
  let total = 0;
  const chunks = [];
  let timer = null;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const err = new Error('REQUEST_BODY_TIMEOUT');
      err.statusCode = 408;
      try { req.destroy(err); } catch {}
      reject(err);
    }, BODY_READ_TIMEOUT_MS);
    if (timer.unref) timer.unref();
  });

  const readPromise = (async () => {
    for await (const chunk of req) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buf.byteLength;
      if (total > maxBytes) {
        const err = new Error('PAYLOAD_TOO_LARGE');
        err.statusCode = 413;
        try { req.destroy(); } catch {}
        throw err;
      }
      chunks.push(buf);
    }
    return Buffer.concat(chunks).toString('utf8');
  })();

  try {
    return await Promise.race([readPromise, timeoutPromise]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function createAegisDemoServer(opts = {}) {
  const { rawBundleCode = '', rawHtml = '' } = opts && typeof opts === 'object' ? opts : {};
  const safeBundleStr = typeof rawBundleCode === 'string' ? rawBundleCode : '';
  const safeHtmlStr = typeof rawHtml === 'string' ? rawHtml : '';
  const gate = new AegisEdgeGate('aegis-live-edge-secret-2026');
  const auditEngine = new AegisDiagnosticAuditEngine();
  const compiled = safeBundleStr ? compileProtectedBundle(safeBundleStr.replace(/\bexport\s+/g, '')) : { stats: {} };
  const apiRateBuckets = new Map();

  // Pre-load static public assets into memory to eliminate synchronous fs.readFileSync event-loop blocking DoS
  const cachedLandingHtml = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
  const cachedTemplateCss = fs.readFileSync(path.join(__dirname, 'public', 'template.css'));
  const cachedGeistFont = fs.readFileSync(path.join(__dirname, 'public', 'geist-latin.woff2'));

  function checkApiRateLimit(ip) {
    const now = Date.now();
    if (apiRateBuckets.size >= 5000 && !apiRateBuckets.has(ip)) {
      const oldestIp = apiRateBuckets.keys().next().value;
      if (oldestIp !== undefined) apiRateBuckets.delete(oldestIp);
    }
    const bucket = apiRateBuckets.get(ip) || { count: 0, resetAt: now + 60000 };
    if (now > bucket.resetAt) {
      bucket.count = 0;
      bucket.resetAt = now + 60000;
    }
    bucket.count += 1;
    apiRateBuckets.set(ip, bucket);
    return bucket.count <= 90;
  }

  const server = http.createServer(async (req, res) => {
    try {
      const rawReqUrl = typeof req.url === 'string' && req.url.length <= 4096 ? req.url : '/';
      let urlObj;
      try {
        // Reject double-slash open-redirect / authority confusion in request path
        const safeRelUrl = rawReqUrl.startsWith('//') ? '/' + rawReqUrl.replace(/^\/+/, '') : rawReqUrl;
        urlObj = new URL(safeRelUrl || '/', 'http://127.0.0.1');
      } catch {
        res.writeHead(400, { ...HARDENED_SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: 'MALFORMED_REQUEST_URL' }));
        return;
      }
      const pathname = urlObj.pathname;
      const clientIp = req.socket?.remoteAddress || '127.0.0.1';

      // Serve Hardened Landing Page & Static Template Assets from memory cache
      if (pathname === '/' || pathname === '/audit' || pathname === '/index.html') {
        res.writeHead(200, {
          ...HARDENED_SECURITY_HEADERS,
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-cache',
        });
        res.end(cachedLandingHtml);
        return;
      }

      if (pathname === '/template.css') {
        res.writeHead(200, {
          ...HARDENED_SECURITY_HEADERS,
          'Content-Type': 'text/css; charset=utf-8',
          'Cache-Control': 'public, max-age=3600',
        });
        res.end(cachedTemplateCss);
        return;
      }

      if (pathname === '/geist-latin.woff2') {
        res.writeHead(200, {
          ...HARDENED_SECURITY_HEADERS,
          'Content-Type': 'font/woff2',
          'Cache-Control': 'public, max-age=86400',
        });
        res.end(cachedGeistFont);
        return;
      }

      // Live Diagnostic URL Audit API (POST /api/audit or GET /api/audit?url=...)
      if (pathname === '/api/audit') {
        if (!checkApiRateLimit(clientIp)) {
          res.writeHead(429, { ...HARDENED_SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ error: 'RATE_LIMIT_EXCEEDED' }));
          return;
        }
        try {
          const bodyText = await readBoundedBody(req);
          let targetUrl = urlObj.searchParams.get('url') || 'https://acme-nexus.io';
          if (bodyText) {
            try {
              const parsed = safeJsonParse(bodyText);
              if (parsed && typeof parsed === 'object' && typeof parsed.url === 'string') {
                targetUrl = parsed.url.trim();
              }
            } catch {}
          }
          const normalizedCandidate = /^https?:\/\//i.test(targetUrl) ? targetUrl : `https://${targetUrl}`;
          const safety = validateSafeAuditUrl(normalizedCandidate, { allowLocalhostDev: true });
          if (!safety.safe) {
            res.writeHead(403, { ...HARDENED_SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ error: `BLOCKED_UNSAFE_TARGET:${safety.reason}` }));
            return;
          }

          const dossier = await auditEngine.runLiveUrlAudit(normalizedCandidate);
          res.writeHead(200, { ...HARDENED_SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify(dossier, null, 2));
        } catch (err) {
          const code = err?.statusCode === 413 ? 413 : err?.statusCode === 408 ? 408 : 500;
          res.writeHead(code, { ...HARDENED_SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ error: String(err?.message || err) }));
        }
        return;
      }

      // Live 1-Click Shield Simulation API (POST /api/simulate-shield)
      if (pathname === '/api/simulate-shield') {
        if (!checkApiRateLimit(clientIp)) {
          res.writeHead(429, { ...HARDENED_SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ error: 'RATE_LIMIT_EXCEEDED' }));
          return;
        }
        try {
          const bodyText = await readBoundedBody(req);
          let targetUrl = urlObj.searchParams.get('url') || 'https://acme-nexus.io';
          if (bodyText) {
            try {
              const parsed = safeJsonParse(bodyText);
              if (parsed && typeof parsed === 'object' && typeof parsed.url === 'string') {
                targetUrl = parsed.url.trim();
              }
            } catch {}
          }
          const normalizedCandidate = /^https?:\/\//i.test(targetUrl) ? targetUrl : `https://${targetUrl}`;
          const safety = validateSafeAuditUrl(normalizedCandidate, { allowLocalhostDev: true });
          if (!safety.safe) {
            res.writeHead(403, { ...HARDENED_SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ error: `BLOCKED_UNSAFE_TARGET:${safety.reason}` }));
            return;
          }
          const simulation = auditEngine.simulateAegisShieldOnTarget(normalizedCandidate);
          res.writeHead(200, { ...HARDENED_SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify(simulation, null, 2));
        } catch (err) {
          const code = err?.statusCode === 413 ? 413 : err?.statusCode === 408 ? 408 : 500;
          res.writeHead(code, { ...HARDENED_SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ error: String(err?.message || err) }));
        }
        return;
      }

    // Threat Radar status endpoint (gated by Layer 0 inspection & rate limiter)
    if (pathname === '/_aegis/status') {
      const statusCheck = gate.inspectRequest(req);
      if (!statusCheck.allowed) {
        res.writeHead(statusCheck.status, statusCheck.headers);
        res.end(statusCheck.body);
        return;
      }
      res.writeHead(200, { ...HARDENED_SECURITY_HEADERS, 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify(
          {
            active: true,
            version: '6.0.0',
            blockedClients: Array.from(gate.blockedIps.entries()).map(([ip, info]) => ({ ip, ...info })),
            recentTelemetry: gate.telemetryEvents.slice(-25),
            compilerStats: compiled.stats,
          },
          null,
          2
        )
      );
      return;
    }

    // Live AI & SEO Manifests
    if (pathname === '/llms.txt') {
      res.writeHead(200, { ...HARDENED_SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(gate.livingGeo.publishedManifests.get('/llms.txt')?.content || gate.generateAiRecommendationLlmsTxt());
      return;
    }

      // Canary trap triggered by explore.py or client-side CDP/eval firewall
      if (pathname === '/_aegis/canary-trap' || pathname === '/_aegis/telemetry') {
        const ip = req.socket?.remoteAddress || '127.0.0.1';
        const rawTrigger = urlObj.searchParams.get('trigger') || req.headers['x-aegis-trap'] || 'CLIENT_CANARY_TRIPPED';
        const trigger = String(Array.isArray(rawTrigger) ? rawTrigger[0] : rawTrigger).slice(0, 128);
        gate.blockClient(ip, `CANARY_TRAP:${trigger}`, { path: pathname });
        const fatal = gate.buildFatalBlockResponse(trigger);
        res.writeHead(fatal.status, fatal.headers);
        res.end(fatal.body);
        return;
      }

      // Layer 0 inspection on all protected routes
      const inspection = gate.inspectRequest(req);
      if (!inspection.allowed) {
        res.writeHead(inspection.status, inspection.headers);
        res.end(inspection.body);
        return;
      }

      const sessionId = 'sess-demo';

      // Serve protected JS bundle only if valid single-use cryptographic ticket is presented
      if (pathname === '/assets/app-bundle.js' && compiled.code) {
        const ticket = urlObj.searchParams.get('_at');
        const check = gate.verifyAndConsumeScriptTicket(ticket, sessionId, pathname, req.headers, inspection.ip);
        if (!check.ok) {
          const fatal = gate.buildFatalBlockResponse(check.reason);
          res.writeHead(fatal.status, fatal.headers);
          res.end(fatal.body);
          return;
        }
        res.writeHead(
          200,
          gate.sanitizeResponseHeaders({
            'Content-Type': 'application/javascript; charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
          })
        );
        res.end(compiled.code);
        return;
      }

      // Serve protected HTML demo page
      if (pathname === '/demo-target' && safeHtmlStr) {
        const { html } = gate.scrubAndProtectHtml(safeHtmlStr, sessionId);
        res.writeHead(
          200,
          gate.sanitizeResponseHeaders({
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store',
            'X-Aegis-Protection': 'ACTIVE',
          })
        );
        res.end(html);
        return;
      }

      res.writeHead(404, HARDENED_SECURITY_HEADERS);
      res.end('Not Found');
    } catch (unhandledErr) {
      if (!res.headersSent) {
        res.writeHead(500, { ...HARDENED_SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
      }
      res.end(JSON.stringify({ error: 'INTERNAL_EDGE_ERROR' }));
    }
  });

  // Harden HTTP Server against Slowloris header-trickle & socket exhaustion
  server.headersTimeout = 8000;
  server.requestTimeout = 10000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 64;

  return { server, gate, compiled };
}

// Allow direct execution to spin up standalone server on port 3000
if (process.argv[1] && process.argv[1].endsWith('aegis-edge-server.mjs')) {
  const { server } = createAegisDemoServer();
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, '127.0.0.1', () => {
    console.log(`🛡️  DoNotEncode.ai Security & AI SEO Server running at http://127.0.0.1:${PORT}`);
  });
}
