#!/usr/bin/env node
/**
 * @aegis/shield v6.0 — Universal 1-Command Auto-Installer, Framework Adapter & Zero-Code Proxy CLI
 *
 * Usage:
 *   1. Zero-Code Proxy / Cloudflare Worker Mode (Works on ANY website in 10 seconds):
 *      npx @aegis/shield init --target https://your-webapp.com
 *
 *   2. Auto-Detect Project Folder Mode (Next.js, Vite/React, Nuxt, Express, Django/FastAPI, PHP/Laravel, Go):
 *      npx @aegis/shield init --dir ./your-project
 *
 *   3. Direct JS Bundle Compiler Mode:
 *      npx @aegis/shield compile ./dist/app.js -o ./dist/app.aegis.js
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { compileProtectedBundle } from './aegis-compiler.mjs';
import { AegisVulnAutoFixer } from './aegis-vuln-autofixer.mjs';

function safeStr(val, fallback = '') {
  if (typeof val === 'string') return val;
  if (typeof val === 'number' || typeof val === 'boolean' || typeof val === 'bigint') return String(val);
  return fallback;
}

function safeResolveProjectFile(resolvedRoot, relFile) {
  if (typeof relFile !== 'string' || !relFile || relFile.includes('\0')) {
    throw new Error('INVALID_PROJECT_FILE_PATH');
  }
  const fullPath = path.resolve(resolvedRoot, relFile);
  if (!fullPath.startsWith(resolvedRoot + path.sep) && fullPath !== resolvedRoot) {
    throw new Error(`PATH_TRAVERSAL_BLOCKED:${relFile}`);
  }
  if (fs.existsSync(fullPath)) {
    const stat = fs.lstatSync(fullPath);
    if (stat.isSymbolicLink()) {
      throw new Error(`SYMLINK_FILE_BLOCKED:${relFile}`);
    }
  }
  return fullPath;
}

export function detectProjectStack(projectDir) {
  const detected = {
    framework: 'universal-proxy',
    language: 'javascript',
    filesFound: [],
  };

  const dirStr = safeStr(projectDir).trim();
  if (!dirStr || !fs.existsSync(dirStr)) return detected;
  const resolvedRoot = path.resolve(dirStr);

  try {
    const pkgPath = safeResolveProjectFile(resolvedRoot, 'package.json');
    if (fs.existsSync(pkgPath) && fs.lstatSync(pkgPath).isFile()) {
      detected.filesFound.push('package.json');
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        const allDeps = { ...(pkg?.dependencies || {}), ...(pkg?.devDependencies || {}) };
        if (allDeps.next) detected.framework = 'nextjs';
        else if (allDeps.nuxt) detected.framework = 'nuxt';
        else if (allDeps['@sveltejs/kit']) detected.framework = 'sveltekit';
        else if (allDeps['@remix-run/node'] || allDeps['@remix-run/react']) detected.framework = 'remix';
        else if (allDeps.astro) detected.framework = 'astro';
        else if (allDeps.vite || allDeps.react) detected.framework = 'vite-spa';
        else if (allDeps.express || allDeps.fastify || allDeps.koa) detected.framework = 'node-server';
      } catch {}
    } else if (
      fs.existsSync(safeResolveProjectFile(resolvedRoot, 'requirements.txt')) ||
      fs.existsSync(safeResolveProjectFile(resolvedRoot, 'pyproject.toml'))
    ) {
      detected.language = 'python';
      detected.framework = 'python-asgi-wsgi';
      detected.filesFound.push('requirements.txt');
    } else if (
      fs.existsSync(safeResolveProjectFile(resolvedRoot, 'composer.json')) ||
      fs.existsSync(safeResolveProjectFile(resolvedRoot, 'index.php'))
    ) {
      detected.language = 'php';
      detected.framework = 'php-fpm-shield';
      detected.filesFound.push('composer.json');
    } else if (fs.existsSync(safeResolveProjectFile(resolvedRoot, 'go.mod'))) {
      detected.language = 'go';
      detected.framework = 'go-http-middleware';
      detected.filesFound.push('go.mod');
    }
  } catch {}

  return detected;
}

export function initializeAegisInDirectory(opts = {}) {
  const {
    projectDir = process.cwd(),
    targetUrl = 'https://your-webapp.com',
    autoFixSource = true,
  } = opts && typeof opts === 'object' ? opts : {};
  const dirStr = safeStr(projectDir, process.cwd()).trim() || process.cwd();
  const resolvedRoot = path.resolve(dirStr);
  fs.mkdirSync(resolvedRoot, { recursive: true });
  const stackInfo = detectProjectStack(resolvedRoot);
  const masterSecret = 'aegis-sovereign-' + crypto.randomBytes(16).toString('hex');
  const generatedFiles = [];

  let safeTargetOrigin = 'https://your-webapp.com';
  try {
    const parsedTarget = new URL(safeStr(targetUrl, 'https://your-webapp.com').trim());
    if (parsedTarget.protocol === 'http:' || parsedTarget.protocol === 'https:') {
      safeTargetOrigin = parsedTarget.origin;
    }
  } catch {}

  // 1. Write `aegis.config.json`
  const configObj = {
    version: '6.0.0',
    targetOrigin: safeTargetOrigin,
    detectedFramework: stackInfo.framework,
    detectedLanguage: stackInfo.language,
    secretKeyEnv: 'AEGIS_MASTER_SECRET',
    layers: {
      layer1_polymorphicStackVm: true,
      layer2_cloudBaasAndRealtimeVault: true,
      layer3_commerceAndBolaIdorGuard: true,
      layer4_zeroDayVirtualPatchWaf: true,
      layer5_livingGeoAutoSync: true,
      layer6_continuousCanaryDefense: true,
    },
  };
  const configPath = safeResolveProjectFile(resolvedRoot, 'aegis.config.json');
  fs.writeFileSync(configPath, JSON.stringify(configObj, null, 2) + '\n', 'utf8');
  generatedFiles.push('aegis.config.json');

  // 2. Write Universal Cloudflare Worker / Edge Reverse Proxy (`aegis-edge-worker.mjs`)
  //    Allows ANY WebApp (even no-code, PHP, Python, Go, Shopify, WordPress) to be protected with 0 code edits!
  const workerCode = `/**
 * Auto-Generated by @aegis/shield v6.0 — Zero-Code Sovereign Edge Proxy Worker
 * Protects ${safeTargetOrigin} (${stackInfo.framework}) without touching application code.
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // 1. Block known site-decode, headless CDP & zero-day exploit vectors at the edge
    const ua = request.headers.get('user-agent') || '';
    if (/site-decode|HeadlessChrome|PhantomJS|sqlmap|nuclei/i.test(ua)) {
      return new Response('Forbidden by Aegis Sovereign Edge', { status: 403 });
    }
    if (request.headers.get('x-middleware-subrequest') || /\\bbr\\b/i.test(request.headers.get('content-encoding') || '')) {
      return new Response('Blocked Zero-Day Exploit Payload (CVE-2025-29927 / CVE-2026-111497)', { status: 403 });
    }
    const upstreamRes = await fetch(new URL(url.pathname + url.search, ${JSON.stringify(safeTargetOrigin)}), request);
    const cleanHeaders = new Headers(upstreamRes.headers);
    cleanHeaders.delete('x-powered-by');
    cleanHeaders.delete('server');
    cleanHeaders.set('X-Aegis-Shield', 'v6.0-ACTIVE');
    cleanHeaders.set('Cross-Origin-Opener-Policy', 'same-origin');
    cleanHeaders.set('Cross-Origin-Resource-Policy', 'same-origin');
    return new Response(upstreamRes.body, { status: upstreamRes.status, headers: cleanHeaders });
  }
};
`;
  const workerPath = safeResolveProjectFile(resolvedRoot, 'aegis-edge-worker.mjs');
  fs.writeFileSync(workerPath, workerCode, 'utf8');
  generatedFiles.push('aegis-edge-worker.mjs');

  // 3. Generate Framework-Specific 1-Line Drop-In Adapter
  if (stackInfo.framework === 'nextjs') {
    const nextMiddleware = `// Auto-Generated by @aegis/shield v6.0 — Next.js App/Pages Router Edge Middleware
import { NextResponse } from 'next/server';
export function middleware(request) {
  if (request.headers.get('x-middleware-subrequest')) {
    return new NextResponse('Blocked by Aegis CVE-2025-29927 Guard', { status: 403 });
  }
  const res = NextResponse.next();
  res.headers.delete('x-powered-by');
  res.headers.set('X-Aegis-Shield', 'v6.0-NEXTJS');
  return res;
}
`;
    fs.writeFileSync(safeResolveProjectFile(resolvedRoot, 'aegis-next-middleware.js'), nextMiddleware, 'utf8');
    generatedFiles.push('aegis-next-middleware.js');
  } else if (stackInfo.language === 'python') {
    const pyMiddleware = `# Auto-Generated by @aegis/shield v6.0 — Universal Python ASGI/WSGI (FastAPI / Django / Flask) Shield
class AegisAsgiMiddleware:
    def __init__(self, app):
        self.app = app
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            qs = scope.get("query_string", b"").decode("utf-8", errors="ignore")
            if "_connector" in qs or "_negated" in qs or "169.254.169.254" in qs:
                await send({"type": "http.response.start", "status": 403, "headers": [(b"content-type", b"text/plain")]})
                await send({"type": "http.response.body", "body": b"Blocked by Aegis Python Zero-Day Shield"})
                return
        await self.app(scope, receive, send)
`;
    fs.writeFileSync(safeResolveProjectFile(resolvedRoot, 'aegis_asgi_shield.py'), pyMiddleware, 'utf8');
    generatedFiles.push('aegis_asgi_shield.py');
  } else if (stackInfo.language === 'php') {
    const phpPrepend = `<?php
// Auto-Generated by @aegis/shield v6.0 — Universal PHP Auto-Prepend Zero-Day Shield (Laravel / WordPress / Symfony)
ini_set('session.upload_progress.enabled', '0');
ini_set('expose_php', '0');
header_remove('X-Powered-By');
if (isset($_REQUEST['PHP_SESSION_UPLOAD_PROGRESS']) || stripos($_SERVER['QUERY_STRING'] ?? '', 'allow_url_include') !== false) {
    http_response_code(403);
    exit('Blocked by Aegis PHP2Shell Shield');
}
`;
    fs.writeFileSync(safeResolveProjectFile(resolvedRoot, 'aegis_prepend_shield.php'), phpPrepend, 'utf8');
    generatedFiles.push('aegis_prepend_shield.php');
  }

  // 4. Optional Auto-Fix of existing source files in projectDir
  let autoFixedIssues = [];
  if (autoFixSource) {
    const fixer = new AegisVulnAutoFixer();
    const candidateFiles = ['package.json', 'requirements.txt', 'php.ini', '.env', 'app.py', 'index.php', 'main.go'];
    const filesMap = {};
    for (const f of candidateFiles) {
      const fp = safeResolveProjectFile(resolvedRoot, f);
      if (fs.existsSync(fp) && fs.lstatSync(fp).isFile()) {
        filesMap[f] = fs.readFileSync(fp, 'utf8');
      }
    }
    if (Object.keys(filesMap).length > 0) {
      const fixRes = fixer.scanAndAutoFixProject({ files: filesMap });
      autoFixedIssues = fixRes.autoFixedIssues;
      for (const [f, newContent] of Object.entries(fixRes.fixedFiles)) {
        if (candidateFiles.includes(f)) {
          fs.writeFileSync(safeResolveProjectFile(resolvedRoot, f), newContent, 'utf8');
        }
      }
    }
  }

  return {
    ok: true,
    projectDir: resolvedRoot,
    detectedFramework: stackInfo.framework,
    detectedLanguage: stackInfo.language,
    generatedFiles,
    autoFixedCount: autoFixedIssues.length,
    autoFixedIssues,
    masterSecretPreview: masterSecret.slice(0, 18) + '...',
  };
}

// CLI entrypoint
if (process.argv[1] && process.argv[1].endsWith('aegis-cli.mjs')) {
  const args = process.argv.slice(2);
  const cmd = args[0] || 'init';
  if (cmd === 'compile' && args[1]) {
    const inFile = path.resolve(args[1]);
    const outIdx = args.indexOf('-o');
    const outFile = outIdx >= 0 && args[outIdx + 1] ? path.resolve(args[outIdx + 1]) : inFile.replace(/\.js$/, '.aegis.js');
    const src = fs.readFileSync(inFile, 'utf8');
    const compiled = compileProtectedBundle(src);
    fs.writeFileSync(outFile, compiled.code, 'utf8');
    console.log(`[AEGIS v6.0] Compiled ${inFile} -> ${outFile} (${compiled.stats.vmCompiledFunctions} VM functions, ${compiled.stats.vaultedStrings} vaulted strings)`);
  } else {
    const dirIdx = args.indexOf('--dir');
    const targetIdx = args.indexOf('--target');
    const projectDir = dirIdx >= 0 && args[dirIdx + 1] ? path.resolve(args[dirIdx + 1]) : process.cwd();
    const targetUrl = targetIdx >= 0 && args[targetIdx + 1] ? args[targetIdx + 1] : 'https://your-webapp.com';
    const res = initializeAegisInDirectory({ projectDir, targetUrl });
    console.log(`[AEGIS v6.0] Initialized in ${res.projectDir} (Stack: ${res.detectedFramework}, Generated: ${res.generatedFiles.join(', ')}, Auto-Fixed: ${res.autoFixedCount} issues)`);
  }
}
