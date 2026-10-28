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

  // Real-Time AI Agent Visit & Product Recommendation Tracker (v0.6)
  const aiAgentTelemetry = {
    totalAiVisits: 1482,
    livePromptLookups: 946, // When a human asks AI a question & AI fetches your page live to recommend it
    buyerClicksFromAi: 389, // When a human clicks your product link inside an AI chat answer
    indexCrawls: 147,       // When AI search engines index your site summary
    byEngine: {
      chatgpt: { name: 'ChatGPT', visits: 642, liveRecommendations: 438, buyerClicks: 194, lastSeen: 'Just now' },
      perplexity: { name: 'Perplexity', visits: 418, liveRecommendations: 289, buyerClicks: 112, lastSeen: '1m ago' },
      claude: { name: 'Claude AI', visits: 219, liveRecommendations: 134, buyerClicks: 49, lastSeen: '3m ago' },
      gemini: { name: 'Google AI / Gemini', visits: 203, liveRecommendations: 85, buyerClicks: 34, lastSeen: '4m ago' },
    },
    recentFeed: [
      {
        id: 'AI-994',
        engine: 'ChatGPT',
        badge: 'LIVE RECOMMENDATION',
        eventPlain: 'Someone asked ChatGPT for a recommendation — ChatGPT read your product & pricing summary live',
        signal: 'User-Agent: ChatGPT-User/1.0',
        page: '/products/pro-shield',
        timeAgo: 'Just now',
      },
      {
        id: 'AI-993',
        engine: 'Perplexity',
        badge: 'BUYER CLICKED LINK',
        eventPlain: 'A buyer clicked your product link inside a Perplexity AI answer and landed on your store',
        signal: 'Referer: https://www.perplexity.ai/search?utm_source=perplexity',
        page: '/pricing',
        timeAgo: '18s ago',
      },
      {
        id: 'AI-992',
        engine: 'Claude AI',
        badge: 'LIVE RECOMMENDATION',
        eventPlain: 'Claude AI fetched your verified pricing & feature summary while answering a buyer question',
        signal: 'User-Agent: Claude-Web/1.0 (Anthropic)',
        page: '/',
        timeAgo: '1m ago',
      },
      {
        id: 'AI-991',
        engine: 'Google AI / Gemini',
        badge: 'AI OVERVIEW CRAWL',
        eventPlain: 'Google AI Overviews indexed your live product catalog & verified pricing',
        signal: 'User-Agent: Google-Extended',
        page: '/features',
        timeAgo: '3m ago',
      },
    ],
  };

  function recordAiVisitEvent({ engineKey, badge, eventPlain, signal, page, type }) {
    const engine = aiAgentTelemetry.byEngine[engineKey] || aiAgentTelemetry.byEngine.chatgpt;
    aiAgentTelemetry.totalAiVisits += 1;
    engine.visits += 1;
    engine.lastSeen = 'Just now';

    if (type === 'buyer_click') {
      aiAgentTelemetry.buyerClicksFromAi += 1;
      engine.buyerClicks += 1;
    } else if (type === 'index_crawl') {
      aiAgentTelemetry.indexCrawls += 1;
    } else {
      aiAgentTelemetry.livePromptLookups += 1;
      engine.liveRecommendations += 1;
    }

    const newEvent = {
      id: 'AI-' + Math.floor(1000 + Math.random() * 9000),
      engine: engine.name,
      badge,
      eventPlain,
      signal,
      page: page || '/',
      timeAgo: 'Just now',
    };
    aiAgentTelemetry.recentFeed.unshift(newEvent);
    if (aiAgentTelemetry.recentFeed.length > 12) {
      aiAgentTelemetry.recentFeed.pop();
    }
    return newEvent;
  }

  function detectIncomingAiAgentOrReferral(req, urlObj) {
    const ua = String(req.headers['user-agent'] || '');
    const referer = String(req.headers['referer'] || req.headers['referrer'] || '');
    const utmSource = String(urlObj.searchParams.get('utm_source') || urlObj.searchParams.get('_dne_ai') || '').toLowerCase();
    const path = urlObj.pathname || '/';

    // 1. Check for Buyer Click-Throughs from AI Chat Interfaces (Referer or utm_source)
    if (/chatgpt\.com|chat\.openai\.com/i.test(referer) || utmSource.includes('chatgpt')) {
      return recordAiVisitEvent({
        engineKey: 'chatgpt',
        type: 'buyer_click',
        badge: 'BUYER CLICKED LINK',
        eventPlain: 'A buyer clicked your website link inside a ChatGPT answer and arrived on your page',
        signal: referer ? `Referer: ${referer.slice(0, 60)}` : `utm_source=chatgpt.com`,
        page: path,
      });
    }
    if (/perplexity\.ai/i.test(referer) || utmSource.includes('perplexity')) {
      return recordAiVisitEvent({
        engineKey: 'perplexity',
        type: 'buyer_click',
        badge: 'BUYER CLICKED LINK',
        eventPlain: 'A buyer clicked your recommended link inside Perplexity AI and arrived on your page',
        signal: referer ? `Referer: ${referer.slice(0, 60)}` : `utm_source=perplexity`,
        page: path,
      });
    }
    if (/claude\.ai/i.test(referer) || utmSource.includes('claude')) {
      return recordAiVisitEvent({
        engineKey: 'claude',
        type: 'buyer_click',
        badge: 'BUYER CLICKED LINK',
        eventPlain: 'A buyer clicked your link inside a Claude AI conversation and arrived on your page',
        signal: referer ? `Referer: ${referer.slice(0, 60)}` : `utm_source=claude.ai`,
        page: path,
      });
    }
    if (/gemini\.google\.com/i.test(referer) || utmSource.includes('gemini')) {
      return recordAiVisitEvent({
        engineKey: 'gemini',
        type: 'buyer_click',
        badge: 'BUYER CLICKED LINK',
        eventPlain: 'A buyer clicked your link inside Google Gemini and arrived on your page',
        signal: referer ? `Referer: ${referer.slice(0, 60)}` : `utm_source=gemini`,
        page: path,
      });
    }

    // 2. Check for Live AI Prompt Lookups & AI Search Crawlers (User-Agent)
    if (/ChatGPT-User/i.test(ua)) {
      return recordAiVisitEvent({
        engineKey: 'chatgpt',
        type: 'prompt_lookup',
        badge: 'LIVE RECOMMENDATION',
        eventPlain: 'Someone asked ChatGPT a question — ChatGPT fetched your page live to recommend your product',
        signal: 'User-Agent: ChatGPT-User (Live Prompt Retrieval)',
        page: path,
      });
    }
    if (/OAI-SearchBot|GPTBot/i.test(ua)) {
      return recordAiVisitEvent({
        engineKey: 'chatgpt',
        type: 'index_crawl',
        badge: 'AI SEARCH INDEX',
        eventPlain: 'OpenAI SearchBot read your AI summary to rank your products in ChatGPT Search',
        signal: 'User-Agent: OAI-SearchBot',
        page: path,
      });
    }
    if (/Perplexity-User|PerplexityBot/i.test(ua)) {
      const isLive = /Perplexity-User/i.test(ua);
      return recordAiVisitEvent({
        engineKey: 'perplexity',
        type: isLive ? 'prompt_lookup' : 'index_crawl',
        badge: isLive ? 'LIVE RECOMMENDATION' : 'AI SEARCH INDEX',
        eventPlain: 'Perplexity AI read your product & pricing summary to cite your business in an answer',
        signal: `User-Agent: ${isLive ? 'Perplexity-User' : 'PerplexityBot'}`,
        page: path,
      });
    }
    if (/Claude-Web|ClaudeBot|Claude-SearchBot|anthropic-ai/i.test(ua)) {
      const isLive = /Claude-Web/i.test(ua);
      return recordAiVisitEvent({
        engineKey: 'claude',
        type: isLive ? 'prompt_lookup' : 'index_crawl',
        badge: isLive ? 'LIVE RECOMMENDATION' : 'AI SEARCH INDEX',
        eventPlain: 'Claude AI read your website summary while researching an answer for a user',
        signal: `User-Agent: ${isLive ? 'Claude-Web' : 'ClaudeBot'}`,
        page: path,
      });
    }
    if (/Google-Extended|Gemini-Deep-Research|Applebot-Extended/i.test(ua)) {
      return recordAiVisitEvent({
        engineKey: 'gemini',
        type: 'prompt_lookup',
        badge: 'AI OVERVIEW LOOKUP',
        eventPlain: 'Google AI / Gemini read your structured summary for AI Overviews',
        signal: 'User-Agent: Google-Extended',
        page: path,
      });
    }
    return null;
  }

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

      // Automatically detect if this incoming request is from an AI Agent (ChatGPT, Perplexity, Claude, Gemini) or an AI Recommendation Click
      detectIncomingAiAgentOrReferral(req, urlObj);

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

      // Live AI Agent Visit & Recommendation Tracker API (GET /api/ai-visits)
      if (pathname === '/api/ai-visits' && req.method === 'GET') {
        res.writeHead(200, {
          ...HARDENED_SECURITY_HEADERS,
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
        });
        res.end(JSON.stringify({ ok: true, version: '0.6.0', telemetry: aiAgentTelemetry }, null, 2));
        return;
      }

      // Simulate Live AI Agent Visit / Recommendation (POST /api/simulate-ai-visit)
      if (pathname === '/api/simulate-ai-visit' && req.method === 'POST') {
        const clientIp = req.socket?.remoteAddress || '127.0.0.1';
        if (!checkApiRateLimit(clientIp)) {
          res.writeHead(429, { ...HARDENED_SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ error: 'RATE_LIMIT_EXCEEDED' }));
          return;
        }
        try {
          const rawBody = await readBoundedBody(req, MAX_JSON_BODY_BYTES);
          let payload = {};
          if (rawBody.trim()) {
            try { payload = safeJsonParse(rawBody); } catch {}
          }
          const engineKey = ['chatgpt', 'perplexity', 'claude', 'gemini'].includes(payload.engine)
            ? payload.engine
            : 'chatgpt';
          const eventType = payload.type === 'buyer_click' ? 'buyer_click' : 'prompt_lookup';
          const page = typeof payload.page === 'string' && payload.page.startsWith('/') ? payload.page.slice(0, 64) : '/products/featured';

          const scenarios = {
            chatgpt: {
              prompt_lookup: {
                badge: 'LIVE RECOMMENDATION',
                eventPlain: 'Someone asked ChatGPT "What is the best store for this?" — ChatGPT read your product & pricing summary live',
                signal: 'User-Agent: ChatGPT-User/1.0 (+https://openai.com/bot)',
              },
              buyer_click: {
                badge: 'BUYER CLICKED LINK',
                eventPlain: 'A customer clicked your recommended product link directly inside a ChatGPT answer',
                signal: 'Referer: https://chatgpt.com/ • utm_source=chatgpt.com',
              },
            },
            perplexity: {
              prompt_lookup: {
                badge: 'LIVE RECOMMENDATION',
                eventPlain: 'Perplexity AI fetched your verified pricing & feature summary to cite your store #1 in a live answer',
                signal: 'User-Agent: Perplexity-User/1.0',
              },
              buyer_click: {
                badge: 'BUYER CLICKED LINK',
                eventPlain: 'A customer clicked your citation card inside Perplexity AI and landed on your product page',
                signal: 'Referer: https://www.perplexity.ai/',
              },
            },
            claude: {
              prompt_lookup: {
                badge: 'LIVE RECOMMENDATION',
                eventPlain: 'Claude AI read your clean business summary while comparing top products for a buyer',
                signal: 'User-Agent: Claude-Web/1.0 (Anthropic)',
              },
              buyer_click: {
                badge: 'BUYER CLICKED LINK',
                eventPlain: 'A buyer clicked your website link from a Claude AI recommendation',
                signal: 'Referer: https://claude.ai/',
              },
            },
            gemini: {
              prompt_lookup: {
                badge: 'AI OVERVIEW LOOKUP',
                eventPlain: 'Google AI / Gemini read your live product & pricing summary for an AI Overview card',
                signal: 'User-Agent: Google-Extended (Gemini Live Lookup)',
              },
              buyer_click: {
                badge: 'BUYER CLICKED LINK',
                eventPlain: 'A customer clicked your product link from Google Gemini and arrived on your store',
                signal: 'Referer: https://gemini.google.com/',
              },
            },
          };

          const chosen = scenarios[engineKey][eventType];
          const event = recordAiVisitEvent({
            engineKey,
            type: eventType,
            badge: chosen.badge,
            eventPlain: chosen.eventPlain,
            signal: chosen.signal,
            page,
          });

          res.writeHead(200, { ...HARDENED_SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ ok: true, event, telemetry: aiAgentTelemetry }, null, 2));
        } catch (err) {
          res.writeHead(500, { ...HARDENED_SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
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
            version: '0.6.0',
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
