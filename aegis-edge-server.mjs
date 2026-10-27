#!/usr/bin/env node
/**
 * @aegis/shield v2.0 — Live Edge Protection Server & Real-Time Threat Radar
 */

import http from 'node:http';
import { compileProtectedBundle } from './aegis-compiler.mjs';
import { AegisEdgeGate } from './aegis-edge-gate.mjs';
import { AegisDiagnosticAuditEngine } from './aegis-audit-engine.mjs';

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function createAegisDemoServer({ rawBundleCode = '', rawHtml = '' } = {}) {
  const gate = new AegisEdgeGate('aegis-live-edge-secret-2026');
  const auditEngine = new AegisDiagnosticAuditEngine();
  const compiled = rawBundleCode ? compileProtectedBundle(rawBundleCode.replace(/\bexport\s+/g, '')) : { stats: {} };

  const server = http.createServer(async (req, res) => {
    const urlObj = new URL(req.url || '/', 'http://127.0.0.1');
    const pathname = urlObj.pathname;

    // Serve High-Converting English Audit Landing Page & Static Template Assets
    if (pathname === '/' || pathname === '/audit' || pathname === '/index.html') {
      const landingHtml = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-cache',
        'X-Aegis-Shield': 'v6.0-SOVEREIGN',
      });
      res.end(landingHtml);
      return;
    }

    if (pathname === '/template.css') {
      const css = fs.readFileSync(path.join(__dirname, 'public', 'template.css'));
      res.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8', 'Cache-Control': 'public, max-age=3600' });
      res.end(css);
      return;
    }

    if (pathname === '/geist-latin.woff2') {
      const font = fs.readFileSync(path.join(__dirname, 'public', 'geist-latin.woff2'));
      res.writeHead(200, { 'Content-Type': 'font/woff2', 'Cache-Control': 'public, max-age=86400' });
      res.end(font);
      return;
    }

    // Live Diagnostic URL Audit API (POST /api/audit or GET /api/audit?url=...)
    if (pathname === '/api/audit') {
      try {
        let bodyText = '';
        for await (const chunk of req) bodyText += chunk;
        let targetUrl = urlObj.searchParams.get('url') || 'https://acme-nexus.io';
        if (bodyText) {
          try {
            const parsed = JSON.parse(bodyText);
            if (parsed.url) targetUrl = parsed.url;
          } catch {}
        }
        const dossier = await auditEngine.runLiveUrlAudit(targetUrl);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify(dossier, null, 2));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: String(err?.message || err) }));
      }
      return;
    }

    // Live 1-Click Shield Simulation API (POST /api/simulate-shield)
    if (pathname === '/api/simulate-shield') {
      try {
        let bodyText = '';
        for await (const chunk of req) bodyText += chunk;
        let targetUrl = urlObj.searchParams.get('url') || 'https://acme-nexus.io';
        if (bodyText) {
          try {
            const parsed = JSON.parse(bodyText);
            if (parsed.url) targetUrl = parsed.url;
          } catch {}
        }
        const simulation = auditEngine.simulateAegisShieldOnTarget(targetUrl);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify(simulation, null, 2));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: String(err?.message || err) }));
      }
      return;
    }

    // Threat Radar status endpoint (for owner dashboard)
    if (pathname === '/_aegis/status') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        active: true,
        version: '5.0.0',
        blockedClients: Array.from(gate.blockedIps.entries()).map(([ip, info]) => ({ ip, ...info })),
        recentTelemetry: gate.telemetryEvents.slice(-25),
        compilerStats: compiled.stats,
      }, null, 2));
      return;
    }

    // Live AI & SEO Manifests
    if (pathname === '/llms.txt') {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(gate.livingGeo.publishedManifests.get('/llms.txt')?.content || gate.generateAiRecommendationLlmsTxt());
      return;
    }

    // Canary trap triggered by explore.py or client-side CDP/eval firewall
    if (pathname === '/_aegis/canary-trap' || pathname === '/_aegis/telemetry') {
      const ip = req.socket?.remoteAddress || '127.0.0.1';
      const trigger = urlObj.searchParams.get('trigger') || req.headers['x-aegis-trap'] || 'CLIENT_CANARY_TRIPPED';
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
      res.writeHead(200, gate.sanitizeResponseHeaders({
        'Content-Type': 'application/javascript; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      }));
      res.end(compiled.code);
      return;
    }

    // Serve protected HTML demo page
    if (pathname === '/demo-target' && rawHtml) {
      const { html } = gate.scrubAndProtectHtml(rawHtml, sessionId);
      res.writeHead(200, gate.sanitizeResponseHeaders({
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Aegis-Protection': 'ACTIVE',
      }));
      res.end(html);
      return;
    }

    res.writeHead(404);
    res.end('Not Found');
  });

  return { server, gate, compiled };
}

// Allow direct execution to spin up standalone server on port 3000
if (process.argv[1] && process.argv[1].endsWith('aegis-edge-server.mjs')) {
  const { server } = createAegisDemoServer();
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, '127.0.0.1', () => {
    console.log(`🛡️  Aegis Shield Sovereign Audit Portal running at http://127.0.0.1:${PORT}`);
  });
}
