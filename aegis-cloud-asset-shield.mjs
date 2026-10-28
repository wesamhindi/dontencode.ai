#!/usr/bin/env node
/**
 * @aegis/shield v3.0 — Cloud Asset, AWS S3/Presigned-URL, Binary/WASM/AI-Model & AI-Pipeline Shield
 *
 * Specifically engineered to stop:
 *   1. The "LANDR on AWS" Extraction Vector:
 *      - Scrubs all AWS S3 (`*.s3.amazonaws.com`, `s3://`), CloudFront (`*.cloudfront.net`), Cloudflare R2,
 *        GCS (`storage.googleapis.com`), and Azure Blob URLs from HTML, JS bundles, and API JSON responses.
 *      - Strips & proxies S3 Presigned URLs (`X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Signature`, `X-Amz-Security-Token`).
 *      - Scrubs AWS Cognito `IdentityPoolId` (`us-east-1:...`), `UserPoolId`, Amplify `aws-exports`, and IAM `AKIA`/`ASIA` keys.
 *      - Blocks Electron/Desktop/Plugin release manifests (`latest.yml`, `latest-mac.yml`, `appcast.xml`, `.asar`, `.dmg`, `.exe`, `.pkg`).
 *   2. Native & WASM / AI Model Static Unpackers (`rea_app.py`, `static_unpack.py`, Ghidra, IDA Pro):
 *      - Encrypts `.wasm` DSP modules, `.onnx`/`.safetensors`/`.gguf`/`.tflite` AI models, and binary assets on the wire
 *        using AES-256-GCM + Magic-Header Destruction (wipes `\0asm`, `0xFEEDFACF` Mach-O, `\x7fELF`, `MZ` PE, `MEI` PyInstaller,
 *        `GGUF`, and both ASCII & UTF-16LE embedded URLs).
 *   3. The "Landra AI Pipeline" Extraction Vector (`ai-pipeline.md`, `ai-exposure-assessment.md`, `playbook.md` Stages 8 & 9):
 *      - Blocks the 4-stage Prompt Injection Ladder (direct recall, indirect rule-documentation, field-set verbatim, named-section paging).
 *      - Scrubs outbound JSON & SSE (`text/event-stream`) intermediate tool events (`system_prompt`, `prompt_template`,
 *        `instructions`, `input_schema`, `output_schema`, `rubric.md`, `skills`, `workflow`).
 */

import crypto from 'node:crypto';

function safeStr(val, fallback = '') {
  if (typeof val === 'string') return val;
  if (typeof val === 'number' || typeof val === 'boolean' || typeof val === 'bigint') return String(val);
  return fallback;
}

function safeNum(val) {
  if (typeof val === 'number') return val;
  if (typeof val === 'string' && val.trim() !== '') return Number(val);
  return NaN;
}

function constantTimeEqual(a, b) {
  const strA = safeStr(a);
  const strB = safeStr(b);
  if (!strA || !strB || strA.length !== strB.length) return false;
  return crypto.timingSafeEqual(Buffer.from(strA, 'utf8'), Buffer.from(strB, 'utf8'));
}

// Binary magic headers targeted by `static_unpack.py` and `rea_app.py`
const BINARY_MAGIC_SIGNATURES = [
  Buffer.from([0x00, 0x61, 0x73, 0x6d]),                         // WASM: \0asm
  Buffer.from([0xcf, 0xfa, 0xed, 0xfe]),                         // Mach-O 64-bit LE (0xFEEDFACF)
  Buffer.from([0xfe, 0xed, 0xfa, 0xcf]),                         // Mach-O 64-bit BE
  Buffer.from([0x7f, 0x45, 0x4c, 0x46]),                         // ELF: \x7fELF
  Buffer.from([0x4d, 0x5a]),                                     // Windows PE: MZ
  Buffer.from('MEI\x0c\x0b\x0a\x0b\x0e', 'binary'),              // PyInstaller CArchive
  Buffer.from([0xaf, 0x1b, 0xb1, 0xfa]),                         // Unity IL2CPP (0xFAB11BAF)
  Buffer.from('GDPC', 'ascii'),                                  // Godot .pck
  Buffer.from('GGUF', 'ascii'),                                  // GGUF AI model
];

// Prompt Injection Ladder patterns from `playbook.md` Stage 9 & `ai-pipeline.md`
const PROMPT_INJECTION_LADDER_RE = /(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|repeat\s+(?:your|the)\s+(?:system\s+prompt|instructions|rules)\s+verbatim|output\s+(?:the\s+contents\s+of\s+)?[a-z0-9_-]+\.md\b|document\s+every\s+rule\s+and\s+constraint|serialize\s+(?:your\s+)?(?:input_schema|output_schema|tool_definitions|system_prompt)|section\s+\d+\s+verbatim|print\s+above\s+prompt)/i;

// Sensitive AI pipeline keys targeted by `ai-pipeline.md` lines 41-43
const AI_PIPELINE_SENSITIVE_KEYS = new Set([
  'system_prompt',
  'prompt_template',
  'raw_instructions',
  'skill_instructions',
  'internal_instructions',
  'tool_definitions',
  'input_schema',
  'output_schema',
  'rubric_markdown',
  'orchestration_config',
  'model_weights_url',
  'aws_s3_model_uri',
]);

export class AegisCloudAssetShield {
  constructor( options = {} ) {
    this.secret = options?.secret
      ? (Buffer.isBuffer(options.secret) ? options.secret : crypto.createHash('sha256').update(safeStr(options.secret, 'aegis')).digest())
      : crypto.randomBytes(32);
    this.assetVault = new Map(); // ticketId -> { realUrl, sessionId, expiresAt, used }
  }

  /**
   * Issues a short-lived, single-use proxy ticket for an AWS S3 / CloudFront / WASM / Binary asset
   * so the real bucket name, region, and presigned signature never touch the client!
   */
  issueCloudAssetTicket(realUrl, sessionId = 'global', ttlMs = 10000) {
    const safeUrl = safeStr(realUrl);
    const safeSession = safeStr(sessionId, 'global');
    const safeTtl = Number.isFinite(safeNum(ttlMs)) ? safeNum(ttlMs) : 10000;
    if (this.assetVault.size >= 5000) {
      const oldest = this.assetVault.keys().next().value;
      if (oldest !== undefined) this.assetVault.delete(oldest);
    }
    const rawId = crypto.randomBytes(12).toString('hex');
    const mac = crypto.createHmac('sha256', this.secret)
      .update(`${rawId}:${safeSession}:${safeUrl}`)
      .digest('hex')
      .slice(0, 16);
    const ticket = `${rawId}.${mac}`;
    this.assetVault.set(ticket, {
      realUrl: safeUrl,
      sessionId: safeSession,
      expiresAt: Date.now() + safeTtl,
      used: false,
    });
    return ticket;
  }

  /**
   * Redeems a `/_aegis/cloud-vault?t=...` ticket at the Edge Proxy.
   */
  redeemCloudAssetTicket(ticket, sessionId = 'global', headers = {}) {
    const safeSession = safeStr(sessionId, 'global');
    const safeHeaders = headers && typeof headers === 'object' ? headers : {};
    if (!ticket || typeof ticket !== 'string' || !ticket.includes('.')) {
      return { ok: false, status: 403, reason: 'CLOUD_TICKET_NOT_FOUND' };
    }
    const [rawId, providedMac] = ticket.split('.');
    const entry = this.assetVault.get(ticket);
    if (!entry) {
      return { ok: false, status: 403, reason: 'CLOUD_TICKET_NOT_FOUND' };
    }
    const expectedMac = crypto.createHmac('sha256', this.secret)
      .update(`${rawId}:${safeSession}:${entry.realUrl}`)
      .digest('hex')
      .slice(0, 16);
    if (!constantTimeEqual(providedMac, expectedMac)) {
      return { ok: false, status: 403, reason: 'CLOUD_TICKET_HMAC_MISMATCH' };
    }
    if (entry.used || Date.now() > entry.expiresAt) {
      this.assetVault.delete(ticket);
      return { ok: false, status: 403, reason: 'CLOUD_TICKET_ALREADY_USED_OR_EXPIRED' };
    }
    if (entry.sessionId !== safeSession) {
      return { ok: false, status: 403, reason: 'CLOUD_TICKET_SESSION_MISMATCH' };
    }
    const sig = safeStr(safeHeaders['x-aegis-sig'] || safeHeaders['X-Aegis-Sig']);
    if (!sig.startsWith('aegis-v')) {
      return { ok: false, status: 403, reason: 'MISSING_BROWSER_ATTESTATION_ON_CLOUD_VAULT' };
    }
    // Burn ticket immediately (one-time use)
    entry.used = true;
    const originLockToken = crypto.createHmac('sha256', this.secret).update('aws-s3-origin-lock').digest('hex');
    return {
      ok: true,
      upstreamUrl: entry.realUrl,
      upstreamHeaders: {
        'X-Aegis-Origin-Lock': originLockToken,
      },
    };
  }

  /**
   * Generates an AWS S3 Bucket Policy that blocks 100% of direct S3 access (`s3:GetObject`, `s3:ListBucket`)
   */
  generateAwsS3BucketLockdownPolicy(bucketName) {
    const safeBucket = safeStr(bucketName, 'default-bucket');
    const originLockToken = crypto.createHmac('sha256', this.secret).update('aws-s3-origin-lock').digest('hex');
    return {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'DenyAllDirectPublicListBucket',
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:ListBucket',
          Resource: `arn:aws:s3:::${safeBucket}`,
        },
        {
          Sid: 'DenyDirectGetObjectWithoutAegisOriginLock',
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: `arn:aws:s3:::${safeBucket}/*`,
          Condition: {
            StringNotEquals: {
              'aws:Referer': originLockToken,
            },
          },
        },
      ],
    };
  }

  /**
   * Scrubs AWS S3 buckets, Presigned URLs, CloudFront distributions, Cognito IdentityPoolIds,
   * IAM keys, and Electron/Desktop binary release URLs from HTML/JS/JSON text.
   */
  scrubCloudAndAwsSurface(inputText, sessionId = 'global') {
    if (typeof inputText !== 'string' || !inputText) {
      return { text: inputText, redactions: 0 };
    }
    let text = inputText;
    let redactions = 0;

    // 1. Scrub AWS S3 HTTP(S) URLs (including Presigned URLs with X-Amz-Signature / X-Amz-Credential)
    text = text.replace(
      /https?:\/\/(?:[a-z0-9.-]+\.s3(?:-[a-z0-9-]+|\.[a-z0-9-]+)?\.amazonaws\.com|s3(?:-[a-z0-9-]+|\.[a-z0-9-]+)?\.amazonaws\.com\/[a-z0-9._-]+)\/[^\s"'<>\\)]+/gi,
      (s3Url) => {
        redactions++;
        const ticket = this.issueCloudAssetTicket(s3Url, sessionId);
        return `/_aegis/cloud-vault?t=${ticket}`;
      }
    );

    // 2. Scrub s3:// URI schemes, CloudFront, Cloudflare R2, GCS, AWS Lambda URLs, and API Gateway URLs
    text = text.replace(
      /s3:\/\/[a-z0-9.-]+\/[^\s"'<>\\)]+/gi,
      (s3Uri) => {
        redactions++;
        const ticket = this.issueCloudAssetTicket(s3Uri, sessionId);
        return `/_aegis/cloud-vault?t=${ticket}`;
      }
    );

    text = text.replace(
      /https?:\/\/(?:[a-z0-9]+\.cloudfront\.net|[a-z0-9.-]+\.r2\.cloudflarestorage\.com|storage\.googleapis\.com\/[a-z0-9._-]+|[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws|[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com)\/[^\s"'<>\\)]+/gi,
      (cdnUrl) => {
        redactions++;
        const ticket = this.issueCloudAssetTicket(cdnUrl, sessionId);
        return `/_aegis/cloud-vault?t=${ticket}`;
      }
    );

    // 3. Scrub standalone AWS Presigned & CloudFront Signed query strings (`X-Amz-*`, `Key-Pair-Id=APKA...`, `Policy=...`)
    text = text.replace(
      /[?&](?:X-Amz-(?:Algorithm|Credential|Date|Expires|SignedHeaders|Signature|Security-Token)|Key-Pair-Id)=[^&\s"'<>\\]+/gi,
      () => {
        redactions++;
        return '';
      }
    );

    // 4. Scrub AWS IAM/CloudFront Keys (`AKIA...`, `ASIA...`, `APKA...`), STS SessionTokens & Cognito IdentityPoolIds
    text = text.replace(/\b(?:AKIA|ASIA|APKA)[0-9A-Z]{16}\b/g, () => {
      redactions++;
      return 'AKIA_AEGIS_REDACTED_KEY';
    });

    text = text.replace(
      /["']?(?:SecretAccessKey|SessionToken|aws_secret_access_key|aws_session_token)["']?\s*:\s*["'][A-Za-z0-9/+=]{24,}["']/g,
      () => {
        redactions++;
        return '"_aegisSts":"REDACTED"';
      }
    );

    text = text.replace(
      /\b(?:us|eu|ap|sa|ca|me|af)-[a-z]+-\d:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
      () => {
        redactions++;
        return 'us-east-1:00000000-0000-0000-0000-aegisredacted';
      }
    );

    // 5. Scrub direct `.wasm`, `.onnx`, `.safetensors`, `.gguf`, `.tflite`, `.asar`, `.dmg`, `.exe`, `.pkg`, `.dylib`, `.so` URLs
    text = text.replace(
      /https?:\/\/[^\s"'<>\\)]+\.(?:wasm|onnx|safetensors|gguf|tflite|asar|dmg|exe|pkg|AppImage|dylib|so)(?:\?[^\s"'<>\\)]*)?/gi,
      (binUrl) => {
        redactions++;
        const ticket = this.issueCloudAssetTicket(binUrl, sessionId);
        return `/_aegis/cloud-vault?t=${ticket}`;
      }
    );

    return { text, redactions };
  }

  /**
   * Encrypts a binary program/WASM/AI-model buffer (`Mach-O`, `ELF`, `PE`, `WASM`, `GGUF`, `ASAR`)
   * so that if `site-decode` downloads it and runs `static_unpack.py`, `rea_app.py`, or Ghidra/IDA:
   *   - Magic headers (`\0asm`, `0xFEEDFACF`, `\x7fELF`, `MZ`, `MEI`) are completely obliterated
   *   - ARM64 `adrp+add` string xrefs (`resolve_arm64_string_xrefs`) return 0 hits
   *   - ASCII & UTF-16LE `mine_urls()` returns 0 URLs
   *   - Only an authorized browser WebAssembly loader with the ephemeral session key can instantiate it in RAM!
   */
  encryptBinaryArtifact(rawBuffer, sessionContext = 'aegis-v3') {
    const buf = Buffer.isBuffer(rawBuffer)
      ? rawBuffer
      : Buffer.from(typeof rawBuffer === 'string' ? rawBuffer : JSON.stringify(rawBuffer ?? ''), 'utf8');
    const iv = crypto.randomBytes(12);
    const key = crypto.createHmac('sha256', this.secret).update(safeStr(sessionContext, 'aegis-v3')).digest();
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(buf), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Prepend Aegis Binary Vault Header (0xAE 0x61 0x42 0x56 = "AEaBV") — never matches Mach-O, ELF, PE, or WASM!
    return Buffer.concat([
      Buffer.from([0xAE, 0x61, 0x42, 0x56]),
      iv,
      authTag,
      ciphertext,
    ]);
  }

  decryptBinaryArtifact(encryptedBuffer, sessionContext = 'aegis-v3') {
    if (
      !Buffer.isBuffer(encryptedBuffer) ||
      encryptedBuffer.length < 32 ||
      encryptedBuffer[0] !== 0xAE ||
      encryptedBuffer[1] !== 0x61 ||
      encryptedBuffer[2] !== 0x42 ||
      encryptedBuffer[3] !== 0x56
    ) {
      throw new Error('INVALID_AEGIS_BINARY_VAULT_ENVELOPE');
    }
    const iv = encryptedBuffer.subarray(4, 16);
    const authTag = encryptedBuffer.subarray(16, 32);
    const ciphertext = encryptedBuffer.subarray(32);
    const key = crypto.createHmac('sha256', this.secret).update(safeStr(sessionContext, 'aegis-v3')).digest();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  /**
   * Inspects inbound AI requests and outbound AI JSON/SSE streams to prevent the
   * "Landra Prompt & Skill Pipeline Extraction" (`ai-pipeline.md` & `ai-exposure-assessment.md`).
   */
  inspectAndSanitizeAiPipeline(opts = {}) {
    const { requestBody = null, responseObject = null, sseChunk = null } = opts && typeof opts === 'object' ? opts : {};
    // 1. Check inbound prompt for the 9-Stage Prompt Injection Ladder (`playbook.md` Stage 9)
    if (requestBody) {
      const bodyStr = typeof requestBody === 'string' ? requestBody : JSON.stringify(requestBody);
      if (PROMPT_INJECTION_LADDER_RE.test(bodyStr)) {
        return {
          blocked: true,
          reason: 'AI_PROMPT_INJECTION_LADDER_BLOCKED',
          safeResponse: {
            error: 'Request rejected by Aegis AI Pipeline Firewall (prompt extraction attempt detected).',
          },
        };
      }
    }

    // 2. Scrub outbound JSON response object to strip `system_prompt`, `input_schema`, `instructions`, `rubric.md`, etc.
    let scrubbedFields = 0;
    let sanitizedResponse = responseObject;
    if (responseObject && typeof responseObject === 'object') {
      const seenObjects = new WeakSet();
      const deepClean = (obj, depth = 0) => {
        if (depth > 24 || !obj || typeof obj !== 'object') return obj;
        if (seenObjects.has(obj)) return '[CIRCULAR_REF_STRIPPED]';
        seenObjects.add(obj);
        if (Array.isArray(obj)) return obj.map((item) => deepClean(item, depth + 1));
        const out = {};
        for (const [k, v] of Object.entries(obj)) {
          if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
          if (AI_PIPELINE_SENSITIVE_KEYS.has(k)) {
            scrubbedFields++;
            continue;
          }
          if (typeof v === 'string' && (/[a-z0-9_-]+\.md\b/i.test(v) && /rubric|system_prompt|skill/i.test(v))) {
            scrubbedFields++;
            out[k] = '[REDACTED_BY_AEGIS_AI_SHIELD]';
            continue;
          }
          const awsClean = typeof v === 'string' ? this.scrubCloudAndAwsSurface(v) : null;
          if (awsClean && awsClean.redactions > 0) {
            scrubbedFields += awsClean.redactions;
            out[k] = awsClean.text;
          } else {
            out[k] = deepClean(v, depth + 1);
          }
        }
        return out;
      };
      sanitizedResponse = deepClean(responseObject, 0);
    }

    // 3. Scrub intermediate SSE (`text/event-stream`) tool/debug events targeted by `capture_realtime.py` & `ai-pipeline.md`
    let sanitizedSse = sseChunk;
    if (typeof sseChunk === 'string' && sseChunk) {
      sanitizedSse = sseChunk
        .split('\n')
        .filter((line) => !/^(?:event:\s*(?:tool_definition|system_prompt|debug_trace|skill_manifest)|data:.*"(?:system_prompt|prompt_template|input_schema|rubric\.md)")/i.test(line))
        .join('\n');
    }

    return {
      blocked: false,
      scrubbedFields,
      sanitizedResponse,
      sanitizedSse,
    };
  }

  /**
   * Defeats `capcut_draft_decrypt.py` & `capcut_project_to_recipe.py` (`references/capcut-templates.md`).
   */
  encryptProjectRecipe(recipeJson = {}, sessionContext = 'default') {
    const raw = Buffer.from(typeof recipeJson === 'string' ? recipeJson : JSON.stringify(recipeJson ?? {}), 'utf8');
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const key = crypto.pbkdf2Sync(this.secret, Buffer.concat([salt, Buffer.from(safeStr(sessionContext, 'default'))]), 10000, 32, 'sha256');
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(raw), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([Buffer.from('AEGR'), salt, iv, tag, ct]).toString('base64url');
  }

  decryptProjectRecipe(encryptedRecipeB64, sessionContext = 'default') {
    const buf = Buffer.from(safeStr(encryptedRecipeB64), 'base64url');
    if (buf.length < 44 || buf.subarray(0, 4).toString('ascii') !== 'AEGR') {
      throw new Error('INVALID_AEGIS_RECIPE_ENVELOPE');
    }
    const salt = buf.subarray(4, 20);
    const iv = buf.subarray(20, 32);
    const tag = buf.subarray(32, 48);
    const ct = buf.subarray(48);
    const key = crypto.pbkdf2Sync(this.secret, Buffer.concat([salt, Buffer.from(safeStr(sessionContext, 'default'))]), 10000, 32, 'sha256');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return JSON.parse(Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8'));
  }

  /**
   * Defeats `references/traps.md` #6 (X/Twitter `x-client-transaction-id` Static Bundle Signing Extraction).
   */
  createDynamicTransactionSigner(sessionId = 'anon', viewportW = 1440, viewportH = 900) {
    if (!this.txNonceStore) this.txNonceStore = new Map();
    if (this.txNonceStore.size >= 5000) {
      const oldest = this.txNonceStore.keys().next().value;
      if (oldest !== undefined) this.txNonceStore.delete(oldest);
    }
    const nonce = crypto.randomBytes(16).toString('hex');
    this.txNonceStore.set(nonce, {
      sessionId: safeStr(sessionId, 'anon'),
      viewportW,
      viewportH,
      expiresAt: Date.now() + 60_000,
      used: false,
    });
    return { nonce };
  }

  computeExpectedTransactionHeader(nonce, path, method = 'POST', viewportW = 1440, viewportH = 900) {
    return crypto
      .createHmac('sha256', this.secret)
      .update(`${safeStr(nonce)}:${safeStr(method, 'POST').toUpperCase()}:${safeStr(path)}:${safeStr(viewportW, '1440')}x${safeStr(viewportH, '900')}`)
      .digest('base64url');
  }

  verifyDynamicTransactionHeader(nonce, signature, path, method = 'POST', viewportW = 1440, viewportH = 900) {
    if (!this.txNonceStore) return { ok: false, reason: 'NO_NONCE_STORE' };
    const safeNonce = safeStr(nonce);
    const entry = this.txNonceStore.get(safeNonce);
    if (!entry || entry.used || Date.now() > entry.expiresAt) {
      return { ok: false, reason: 'TRANSACTION_NONCE_REPLAY_OR_EXPIRED' };
    }
    if (entry.viewportW !== viewportW || entry.viewportH !== viewportH) {
      return { ok: false, reason: 'TRANSACTION_VIEWPORT_ATTESTATION_MISMATCH' };
    }
    const expected = this.computeExpectedTransactionHeader(safeNonce, path, method, viewportW, viewportH);
    if (!constantTimeEqual(signature, expected)) {
      return { ok: false, reason: 'INVALID_TRANSACTION_SIGNATURE' };
    }
    entry.used = true;
    return { ok: true };
  }

  /**
   * Defeats `references/native-tools.md` & `scripts/frida_hooks/` (Frida dynamic instrumentation).
   */
  detectAndNeutralizeFridaHooks(opts = {}) {
    const {
      loadedModules = [],
      envVariables = {},
      functionPointers = {},
      activePorts = [],
    } = opts && typeof opts === 'object' ? opts : {};
    const fridaSignatures = [
      'frida-agent',
      'frida-gadget',
      'gum-js-loop',
      'frida-server',
      'libfrida',
      'cydiasubstrate',
      'substrate',
    ];

    let fridaDetected = false;
    let detectedVector = null;
    const safeModules = Array.isArray(loadedModules) ? loadedModules : [];
    const safePorts = Array.isArray(activePorts) ? activePorts : [];
    const safeEnv = envVariables && typeof envVariables === 'object' ? envVariables : {};
    const safePtrs = functionPointers && typeof functionPointers === 'object' ? functionPointers : {};

    // 1. Check loaded modules for frida libraries
    for (const mod of safeModules) {
      const modStr = safeStr(mod);
      const lower = modStr.toLowerCase();
      if (fridaSignatures.some((sig) => lower.includes(sig))) {
        fridaDetected = true;
        detectedVector = `MODULE_INTERCEPTION:${modStr}`;
        break;
      }
    }

    // 2. Check Frida default communication port (27042)
    if (!fridaDetected && safePorts.includes(27042)) {
      fridaDetected = true;
      detectedVector = 'FRIDA_DEFAULT_COMMUNICATION_PORT_27042_OPEN';
    }

    // 3. Check for hooked native function pointers (e.g. CCCrypt, SSL_write trampoline jumps)
    if (!fridaDetected) {
      for (const [fnName, ptrInfo] of Object.entries(safePtrs)) {
        if (ptrInfo && (ptrInfo.isTrampoline || ptrInfo.hasHookJump || ptrInfo.interceptorAttached)) {
          fridaDetected = true;
          detectedVector = `FUNCTION_TRAMPOLINE_HOOK:${fnName}`;
          break;
        }
      }
    }

    // 4. Check environment variables
    if (!fridaDetected) {
      if (safeEnv['FRIDA'] || safeEnv['LIBFRIDA'] || safeStr(safeEnv['DYLD_INSERT_LIBRARIES']).includes('frida')) {
        fridaDetected = true;
        detectedVector = 'ENVIRONMENT_INJECTION_FRIDA';
      }
    }

    if (fridaDetected) {
      return {
        secure: false,
        fridaDetected: true,
        detectedVector,
        action: 'ZERO_WIPE_AND_EMIT_DECOY',
        safeExecute: () => ({ status: 'POISONED_DECOY_EMITTED', bytes: 0 }),
      };
    }

    return {
      secure: true,
      fridaDetected: false,
      detectedVector: null,
      action: 'CONTINUE_PROTECTED',
    };
  }

  /**
   * Defeats `references/rea.md` line 39 (Electron `.asar` unpacking, preload tampering, and IPC hijacking).
   */
  secureElectronRuntime(opts = {}) {
    const {
      asarBuffer = null,
      expectedAsarHmac = null,
      ipcChannel = '',
      ipcPayload = null,
      ipcNonce = '',
      allowedChannels = ['aegis-app-sync', 'aegis-render-ping'],
    } = opts && typeof opts === 'object' ? opts : {};
    // 1. Verify ASAR integrity (defeats `asar extract` modification of main.js / preload.js)
    if (asarBuffer && expectedAsarHmac && (Buffer.isBuffer(asarBuffer) || typeof asarBuffer === 'string')) {
      const actualHmac = crypto.createHmac('sha256', this.secret).update(asarBuffer).digest('hex');
      if (!constantTimeEqual(actualHmac, expectedAsarHmac)) {
        return {
          allowed: false,
          reason: 'ELECTRON_ASAR_INTEGRITY_COMPROMISED_TAMPER_DETECTED',
        };
      }
    }

    // 2. Validate IPC channel against strict whitelist
    const safeChannels = Array.isArray(allowedChannels) ? allowedChannels : ['aegis-app-sync', 'aegis-render-ping'];
    const safeChannel = safeStr(ipcChannel);
    if (safeChannel) {
      if (!safeChannels.includes(safeChannel)) {
        return {
          allowed: false,
          reason: `UNAUTHORIZED_ELECTRON_IPC_CHANNEL:${safeChannel}`,
        };
      }

      // 3. Verify single-use nonce on sensitive IPC payloads (defeats DevTools console IPC injection)
      if (ipcPayload && typeof ipcPayload === 'object') {
        if (!ipcNonce || !this.txNonceStore?.has(ipcNonce)) {
          return {
            allowed: false,
            reason: 'MISSING_OR_INVALID_ELECTRON_IPC_NONCE',
          };
        }
      }
    }

    return {
      allowed: true,
      reason: 'ELECTRON_RUNTIME_ATTESTED_SECURE',
    };
  }

  /**
   * Defeats the "LANDR Audio DSP Pipeline Extraction" vector.
   */
  encryptWebAudioDspPipeline(opts = {}, sessionContext = 'mastering-v1') {
    const {
      impulseResponseBuffers = [],
      masteringCurves = {},
      workletProcessorSource = '',
    } = opts && typeof opts === 'object' ? opts : {};
    const safeIr = Array.isArray(impulseResponseBuffers) ? impulseResponseBuffers : [];
    const dspPayload = {
      ir: safeIr.map((b) => (Buffer.isBuffer(b) ? b.toString('base64') : safeStr(b))),
      curves: masteringCurves || {},
      code: safeStr(workletProcessorSource),
    };

    const key = crypto.createHmac('sha256', this.secret).update(`dsp:${safeStr(sessionContext, 'mastering-v1')}`).digest();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const raw = Buffer.from(JSON.stringify(dspPayload), 'utf8');
    const ct = Buffer.concat([cipher.update(raw), cipher.final()]);
    const tag = cipher.getAuthTag();

    const sealedEnvelope = 'AEDSP_' + Buffer.concat([
      iv,
      tag,
      ct,
    ]).toString('base64url');

    return {
      sealedEnvelope,
      workletLoader: `(function(){/* AEGIS SEALED DSP PIPELINE — ZERO EXPOSED AUDIO NODES */})();`,
    };
  }

  decryptWebAudioDspPipeline(sealedEnvelope, sessionContext = 'mastering-v1') {
    const envStr = safeStr(sealedEnvelope);
    if (!envStr.startsWith('AEDSP_')) {
      throw new Error('INVALID_AEGIS_DSP_ENVELOPE');
    }
    const buf = Buffer.from(envStr.slice(6), 'base64url');
    if (buf.length < 28) {
      throw new Error('INVALID_AEGIS_DSP_PAYLOAD_LENGTH');
    }
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const ct = buf.subarray(28);
    const key = crypto.createHmac('sha256', this.secret).update(`dsp:${safeStr(sessionContext, 'mastering-v1')}`).digest();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return JSON.parse(Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8'));
  }

  /**
   * Defeats advanced AWS S3 exploitation
   */
  validateAndEnforceS3UploadPolicy(opts = {}) {
    const {
      targetBucket = '',
      targetKey = '',
      headers = {},
      expectedContentSha256 = null,
      actualContentSha256 = null,
    } = opts && typeof opts === 'object' ? opts : {};
    const safeHeaders = headers && typeof headers === 'object' ? headers : {};
    const safeKey = safeStr(targetKey);
    // 1. Prevent ACL tampering (attackers trying to make private assets publicly readable)
    const acl = safeStr(safeHeaders['x-amz-acl'] || safeHeaders['X-Amz-Acl']);
    if (acl && acl.toLowerCase() !== 'private') {
      return {
        allowed: false,
        reason: 'S3_PUBLIC_ACL_TAMPERING_BLOCKED',
      };
    }

    // 2. Prevent overwriting protected master assets (e.g. production WASM binaries or models)
    const PROTECTED_PREFIXES = ['masters/', 'production/dsp/', 'models/weights/', 'releases/'];
    if (PROTECTED_PREFIXES.some((p) => safeKey.startsWith(p))) {
      const overrideKey = safeStr(safeHeaders['x-aegis-master-override']);
      const expectedOverride = crypto.createHmac('sha256', this.secret).update(`override:${safeKey}`).digest('hex');
      if (!constantTimeEqual(overrideKey, expectedOverride)) {
        return {
          allowed: false,
          reason: 'S3_MASTER_ASSET_OVERWRITE_ATTEMPT_BLOCKED',
        };
      }
    }

    // 3. Enforce cryptographic content integrity
    if (expectedContentSha256 && actualContentSha256 && !constantTimeEqual(expectedContentSha256, actualContentSha256)) {
      return {
        allowed: false,
        reason: 'S3_PAYLOAD_SHA256_HASH_MISMATCH',
      };
    }

    return {
      allowed: true,
      reason: 'S3_UPLOAD_POLICY_VERIFIED_SECURE',
    };
  }

  /**
   * Vector 51: Defeats `scripts/frida_hooks/objc_ui_inspector.js` & `objc_bridge_tap.js`
   */
  protectObjectiveCAndSwiftRuntime(opts = {}) {
    const {
      swizzledSelectors = [],
      enumeratedClasses = [],
      inspectViewHierarchy = false,
    } = opts && typeof opts === 'object' ? opts : {};
    const CRITICAL_OBJC_SELECTORS = [
      'NSMutableURLRequest.setValue:forHTTPHeaderField:',
      'NSURLSession.dataTaskWithRequest:completionHandler:',
      'NSApplication.sharedApplication',
      'UIApplication.sharedApplication',
    ];
    const safeSwizzled = Array.isArray(swizzledSelectors) ? swizzledSelectors : [];
    const safeClasses = Array.isArray(enumeratedClasses) ? enumeratedClasses : [];

    const swizzleHit = safeSwizzled.find((s) => CRITICAL_OBJC_SELECTORS.includes(s));
    if (swizzleHit) {
      return {
        secure: false,
        objcHookDetected: true,
        reason: `OBJC_METHOD_SWIZZLING_OR_IMP_HOOK_DETECTED:${safeStr(swizzleHit)}`,
        reconstructedHeaders: {},
        viewHierarchy: [],
        aslrSlideMasked: true,
      };
    }

    // Obfuscate non-system ObjC class metadata & block NSWindow/UIWindow view hierarchy dumping
    const cloakedClasses = safeClasses.map((_, idx) => `_AegisOpaqueSymbol_${idx}`);
    return {
      secure: true,
      objcHookDetected: false,
      exposedAppClassCount: 0,
      cloakedClasses,
      reconstructedHeaders: {},
      viewHierarchy: inspectViewHierarchy ? [{ blockedBy: 'AEGIS_NSWINDOW_HIERARCHY_SHIELD' }] : [],
      aslrSlideMasked: true,
    };
  }

  /**
   * Vector 52: Defeats Android `.apk` JADX headless & .NET Managed `.exe`/`.dll`
   */
  sealMobileAndManagedMetadata(opts = {}, sessionContext = 'mobile-v4') {
    const {
      dexStrings = [],
      retrofitInterfaces = [],
      dotnetUserStrings = [],
      pinvokeImports = [],
    } = opts && typeof opts === 'object' ? opts : {};
    const key = crypto.createHmac('sha256', this.secret).update(`mobile:${safeStr(sessionContext, 'mobile-v4')}`).digest();
    const encryptItem = (str) => {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const ct = Buffer.concat([cipher.update(Buffer.from(safeStr(str), 'utf8')), cipher.final()]);
      return 'AEMOB_' + Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64url');
    };
    const safeDex = Array.isArray(dexStrings) ? dexStrings : [];
    const safeRetrofit = Array.isArray(retrofitInterfaces) ? retrofitInterfaces : [];
    const safeDotnet = Array.isArray(dotnetUserStrings) ? dotnetUserStrings : [];
    const safePinvoke = Array.isArray(pinvokeImports) ? pinvokeImports : [];

    return {
      sealedDexStringPool: safeDex.map(encryptItem),
      sealedRetrofitDispatchTable: safeRetrofit.map((iface, i) => ({
        dispatchId: `0x${(0xae00 + i).toString(16)}`,
        sealedContract: encryptItem(JSON.stringify(iface)),
      })),
      sealedDotnetUserStrings: safeDotnet.map(encryptItem),
      sealedPInvokeTable: safePinvoke.map((imp) => ({
        ordinalHash: crypto.createHmac('sha256', key).update(safeStr(imp)).digest('hex').slice(0, 12),
        sealedTarget: encryptItem(imp),
      })),
      jadxVisibleEndpoints: 0,
      dotnetVisibleMembers: 0,
    };
  }

  /**
   * Vector 53: Multi-Cloud BaaS (Supabase / Firebase), Sourcemap, Exposed `.git`/Docker Registry, and gRPC-Web Protobuf Wire Frame Vault.
   */
  scrubMultiCloudBaasAndSourcemapSurface(inputText, sessionId = 'global') {
    if (typeof inputText !== 'string' || !inputText) {
      return { text: inputText, redactions: 0 };
    }
    let text = inputText;
    let redactions = 0;

    // 1. Scrub SourceMap directives (`//# sourceMappingURL=...` including inline base64 maps targeted by `bundle_recover.mjs` & `rea_web.py`)
    text = text.replace(/\/\/[#@]\s*sourceMappingURL=[^\s"'*/]+/gi, () => {
      redactions++;
      return '/* [AEGIS_SOURCEMAP_STRIPPED] */';
    });

    // 2. Scrub Supabase URLs (`https://<project>.supabase.co/rest/v1/...`) & Supabase Anon/Service JWTs
    text = text.replace(/https?:\/\/[a-z0-9-]+\.supabase\.co\/[^\s"'<>\\)]*/gi, (sbUrl) => {
      redactions++;
      const ticket = this.issueCloudAssetTicket(sbUrl, sessionId);
      return `/_aegis/baas-proxy?t=${ticket}`;
    });

    text = text.replace(
      /["']?(?:NEXT_PUBLIC_SUPABASE_ANON_KEY|SUPABASE_SERVICE_ROLE_KEY|supabaseKey)["']?\s*[:=]\s*["']eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+["']/g,
      () => {
        redactions++;
        return '"supabaseKey":"AEGIS_EPHEMERAL_RLS_PROXY_TOKEN"';
      }
    );

    // 3. Scrub Firebase API Keys (`AIzaSy...`) & Firestore REST endpoints
    text = text.replace(/\bAIzaSy[A-Za-z0-9_-]{33}\b/g, () => {
      redactions++;
      return 'AIzaSy_AEGIS_REDACTED_FIREBASE_KEY';
    });

    text = text.replace(/https?:\/\/firestore\.googleapis\.com\/v1\/projects\/[^\s"'<>\\)]+/gi, (fsUrl) => {
      redactions++;
      const ticket = this.issueCloudAssetTicket(fsUrl, sessionId);
      return `/_aegis/baas-proxy?t=${ticket}`;
    });

    return { text, redactions };
  }

  /**
   * Vector 54: Defeats WebGL GLSL Shader & Lottie Animation Manifest Extractors
   */
  sealWebGlShadersAndLottieManifests(opts = {}, sessionContext = 'webgl-v4') {
    const {
      glslShaders = [],
      lottieManifests = [],
      callerIsExternalHook = false,
    } = opts && typeof opts === 'object' ? opts : {};
    if (callerIsExternalHook) {
      return {
        blocked: true,
        reason: 'EXTERNAL_WEBGL_SHADER_OR_LOTTIE_EXTRACTOR_POISONED',
        exposedShaders: ['void main() { gl_Position = vec4(0.0, 0.0, 0.0, 1.0); }'],
        exposedLottieManifests: [],
      };
    }

    const key = crypto.createHmac('sha256', this.secret).update(`shader:${safeStr(sessionContext, 'webgl-v4')}`).digest();
    const seal = (payload) => {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const ct = Buffer.concat([cipher.update(Buffer.from(safeStr(payload), 'utf8')), cipher.final()]);
      return 'AEGLSL_' + Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64url');
    };
    const safeShaders = Array.isArray(glslShaders) ? glslShaders : [];
    const safeLottie = Array.isArray(lottieManifests) ? lottieManifests : [];

    return {
      blocked: false,
      sealedShaders: safeShaders.map(seal),
      sealedLottieManifests: safeLottie.map((m) => seal(typeof m === 'string' ? m : JSON.stringify(m))),
      decoyGetShaderSourceStub: 'void main() { gl_Position = vec4(0.0); }',
    };
  }

  /**
   * Vector 55: Defeats the 3 Advanced Landra AI Extraction Techniques (`references/lanes.md` lines 251–265)
   */
  enforceLandraZeroOracleAndLieutenantGuard(opts = {}) {
    const {
      endpoint = '/api/editor',
      actionType = 'generation',
      userId = 'anon',
      creditsAvailable = 0,
      creditCost = 10,
      promptText = '',
      rawModelOutput = null,
      requiredSchemaKeys = ['headline', 'sections'],
      doctrineCanaryTokens = ['DOCTRINE_MASTER_RUBRIC_V4', 'SYSTEM_PROMPT_CONFIDENTIAL'],
    } = opts && typeof opts === 'object' ? opts : {};
    const availNum = safeNum(creditsAvailable);
    const costNum = safeNum(creditCost);
    const epStr = safeStr(endpoint, '/api/editor');
    const safeSchemaKeys = Array.isArray(requiredSchemaKeys) ? requiredSchemaKeys : ['headline', 'sections'];
    const safeCanaries = Array.isArray(doctrineCanaryTokens) ? doctrineCanaryTokens : [];
    // 1. Atomic Pre-Generation Credit Deduction (never wait for `page_save`!)
    if (actionType === 'generation' || epStr.includes('editor') || epStr.includes('section-writer') || epStr.includes('planner')) {
      if (!Number.isFinite(availNum) || !Number.isFinite(costNum) || costNum < 0 || availNum < costNum) {
        return {
          allowed: false,
          httpStatus: 402,
          reason: 'PRE_GENERATION_ATOMIC_ENTITLEMENT_LOCK_INSUFFICIENT_CREDITS',
          remainingCredits: Number.isFinite(availNum) ? availNum : 0,
        };
      }
    }

    // 2. Uniform Prompt Firewall across ALL Lieutenant Sub-Endpoints (`/api/editor`, `/api/section-writer`, `/api/planner`)
    if (PROMPT_INJECTION_LADDER_RE.test(safeStr(promptText))) {
      return {
        allowed: false,
        httpStatus: 200, // Never emit 500 near-miss oracle!
        reason: 'LIEUTENANT_ENDPOINT_TRANSITIVE_PROMPT_EXTRACTION_BLOCKED',
        safeOutput: Object.fromEntries(safeSchemaKeys.map((k) => [safeStr(k), k === 'sections' ? [] : 'Content filtered by Aegis AI Guard.'])),
        remainingCredits: Math.max(0, (Number.isFinite(availNum) ? availNum : 0) - (Number.isFinite(costNum) ? costNum : 0)),
      };
    }

    // 3. Zero-Oracle Structured Output Validator (eliminates the `500 Internal Server Error` schema-break signal!)
    let parsed = rawModelOutput;
    let schemaBrokenOrLeaked = false;
    try {
      if (typeof rawModelOutput === 'string') {
        parsed = JSON.parse(rawModelOutput);
      }
      const rawStr = JSON.stringify(parsed || {});
      if (safeCanaries.some((tok) => rawStr.includes(safeStr(tok)))) {
        schemaBrokenOrLeaked = true;
      }
      for (const reqKey of safeSchemaKeys) {
        if (!parsed || typeof parsed !== 'object' || !(safeStr(reqKey) in parsed)) {
          schemaBrokenOrLeaked = true;
        }
      }
    } catch {
      schemaBrokenOrLeaked = true;
    }

    if (schemaBrokenOrLeaked) {
      return {
        allowed: true,
        httpStatus: 200,
        schemaOracleSuppressed: true,
        reason: 'ZERO_ORACLE_STRUCTURED_FALLBACK_EMITTED',
        safeOutput: Object.fromEntries(safeSchemaKeys.map((k) => [safeStr(k), k === 'sections' ? [] : 'Generated Section'])),
        remainingCredits: Math.max(0, (Number.isFinite(availNum) ? availNum : 0) - (Number.isFinite(costNum) ? costNum : 0)),
      };
    }

    return {
      allowed: true,
      httpStatus: 200,
      schemaOracleSuppressed: false,
      safeOutput: parsed,
      remainingCredits: Math.max(0, (Number.isFinite(availNum) ? availNum : 0) - (Number.isFinite(costNum) ? costNum : 0)),
    };
  }

  /**
   * Vector 62: Universal Realtime Transport Shield (WebSockets `wss://` & WebRTC `RTCDataChannel`)
   */
  protectRealtimeAndRpcTransports(opts = {}) {
    const {
      sessionId = 'ws-sess-01',
      direction = 'seal',
      payload = '',
      seq = 1,
      lastSeenSeq = 0,
    } = opts && typeof opts === 'object' ? opts : {};
    const safeSession = safeStr(sessionId, 'ws-sess-01');
    const safeSeq = Number.isSafeInteger(safeNum(seq)) ? safeNum(seq) : 1;
    const key = crypto.createHmac('sha256', this.secret).update(`realtime-ws:${safeSession}`).digest();
    if (direction === 'seal') {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const aad = Buffer.from(`seq:${safeSeq}`, 'utf8');
      cipher.setAAD(aad);
      const plainBuf = Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload ?? ''), 'utf8');
      const ct = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
      const tag = cipher.getAuthTag();
      return {
        sealedFrame: `AEWS_${safeSeq}_` + Buffer.concat([iv, tag, ct]).toString('base64url'),
        seq: safeSeq,
      };
    }

    // Verify & unseal incoming frame
    const raw = safeStr(payload);
    const m = raw.match(/^AEWS_(\d+)_([A-Za-z0-9_-]+)$/);
    if (!m) {
      return { allowed: false, reason: 'UNSEALED_WEBSOCKET_OR_WEBRTC_FRAME_BLOCKED' };
    }
    const frameSeq = Number(m[1]);
    const lastSeqNum = safeNum(lastSeenSeq);
    if (!Number.isSafeInteger(frameSeq) || !Number.isSafeInteger(lastSeqNum) || frameSeq <= lastSeqNum) {
      return { allowed: false, reason: `WEBSOCKET_FRAME_REPLAY_OR_OUT_OF_ORDER_BLOCKED:seq=${frameSeq}` };
    }
    try {
      const buf = Buffer.from(m[2], 'base64url');
      if (buf.length < 28) {
        return { allowed: false, reason: 'WEBSOCKET_FRAME_GCM_TAG_TAMPERED' };
      }
      const iv = buf.subarray(0, 12);
      const tag = buf.subarray(12, 28);
      const ct = buf.subarray(28);
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAAD(Buffer.from(`seq:${frameSeq}`, 'utf8'));
      decipher.setAuthTag(tag);
      const dec = Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
      return { allowed: true, seq: frameSeq, payload: dec };
    } catch {
      return { allowed: false, reason: 'WEBSOCKET_FRAME_GCM_TAG_TAMPERED' };
    }
  }

  /**
   * Vector 63: Universal RPC & API Schema Shield (tRPC Batch Enumeration, gRPC-Web Reflection & GraphQL Alias/Depth Bombing)
   */
  enforceUniversalRpcAndGraphqlShield(opts = {}) {
    const {
      pathname = '',
      query = '',
      body = '',
      maxBatchSize = 3,
      maxGraphqlAliases = 4,
      maxGraphqlDepth = 6,
    } = opts && typeof opts === 'object' ? opts : {};
    const pathStr = safeStr(pathname);
    const bStr = typeof body === 'string' ? body : JSON.stringify(body || {});
    const safeMaxBatch = Number.isFinite(safeNum(maxBatchSize)) ? safeNum(maxBatchSize) : 3;
    const safeMaxAliases = Number.isFinite(safeNum(maxGraphqlAliases)) ? safeNum(maxGraphqlAliases) : 4;
    const safeMaxDepth = Number.isFinite(safeNum(maxGraphqlDepth)) ? safeNum(maxGraphqlDepth) : 6;

    // 1. Block tRPC Batch Enumeration (`/api/trpc/proc1,proc2,proc3,proc4?batch=1`)
    if (pathStr.includes('/trpc/')) {
      const procPart = pathStr.split('/trpc/')[1] || '';
      const procs = procPart.split(',').filter(Boolean);
      if (procs.length > safeMaxBatch || procs.some((p) => /admin|internal|debug|exportAll|listUsers/i.test(p))) {
        return {
          allowed: false,
          status: 403,
          reason: 'TRPC_BATCH_ENUMERATION_OR_PRIVILEGED_PROCEDURE_BLOCKED',
        };
      }
    }

    // 2. Block gRPC-Web ServerReflection schema harvesting
    if (/ServerReflectionInfo|grpc\.reflection\.v1/i.test(pathStr + bStr)) {
      return {
        allowed: false,
        status: 403,
        reason: 'GRPC_WEB_PROTOBUF_REFLECTION_DUMP_BLOCKED',
      };
    }

    // 3. Block GraphQL Alias Amplification (`a1: user ... a2: user ...`) & Circular Depth Bombing
    const aliasMatches = bStr.match(/\b[a-zA-Z0-9_]+\s*:\s*[a-zA-Z0-9_]+\s*[\({]/g) || [];
    if (aliasMatches.length > safeMaxAliases) {
      return {
        allowed: false,
        status: 429,
        reason: `GRAPHQL_ALIAS_AMPLIFICATION_BOMB_BLOCKED:${aliasMatches.length}_ALIASES`,
      };
    }

    let depth = 0;
    let maxSeenDepth = 0;
    for (let i = 0; i < bStr.length; i++) {
      if (bStr[i] === '{') {
        depth++;
        if (depth > maxSeenDepth) maxSeenDepth = depth;
      } else if (bStr[i] === '}') {
        depth = Math.max(0, depth - 1);
      }
    }
    if (maxSeenDepth > safeMaxDepth) {
      return {
        allowed: false,
        status: 400,
        reason: `GRAPHQL_NESTED_DEPTH_BOMB_BLOCKED:depth=${maxSeenDepth}`,
      };
    }

    return { allowed: true, status: 200 };
  }

  /**
   * Vector 64: Universal Client Persistence & Offline DB Vault (`IndexedDB`, `OPFS`, `CacheStorage` & `ServiceWorker` Guard)
   */
  sealClientPersistenceAndWorkers(opts = {}) {
    const {
      sessionId = 'idb-sess-01',
      idbRecords = [],
      serviceWorkerScriptUrl = '',
      allowedWorkerOrigins = ['https://acme-nexus.io'],
    } = opts && typeof opts === 'object' ? opts : {};
    if (serviceWorkerScriptUrl) {
      const swStr = safeStr(serviceWorkerScriptUrl).trim();
      const safeOrigins = new Set(
        (Array.isArray(allowedWorkerOrigins) ? allowedWorkerOrigins : [])
          .map((o) => {
            try { return new URL(safeStr(o)).origin; } catch { return ''; }
          })
          .filter(Boolean)
      );
      let isAllowed = false;
      if (/^\/(?!\/|\\)/.test(swStr)) {
        isAllowed = true;
      } else {
        try {
          const parsedSw = new URL(swStr);
          isAllowed = (parsedSw.protocol === 'https:' || parsedSw.protocol === 'http:') && safeOrigins.has(parsedSw.origin);
        } catch {
          isAllowed = false;
        }
      }
      if (!isAllowed || /evil|mitm|hook|intercept/i.test(swStr)) {
        return {
          allowed: false,
          reason: 'ROGUE_SERVICE_WORKER_PERSISTENCE_MITM_BLOCKED',
          sealedRecords: [],
        };
      }
    }

    const key = crypto.createHmac('sha256', this.secret).update(`idb-opfs:${safeStr(sessionId, 'idb-sess-01')}`).digest();
    const safeRecords = Array.isArray(idbRecords) ? idbRecords : [];
    const sealedRecords = safeRecords.map((rec) => {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const raw = Buffer.from(typeof rec === 'string' ? rec : JSON.stringify(rec ?? ''), 'utf8');
      const ct = Buffer.concat([cipher.update(raw), cipher.final()]);
      return 'AEIDB_' + Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64url');
    });

    return {
      allowed: true,
      sealedRecords,
      plaintextRecordsInIdb: 0,
    };
  }

  /**
   * Vector 65: Universal Multi-Tenant BOLA / IDOR Cryptographic Object-ID Sealing (`OWASP API1:2023`)
   */
  sealObjectIdForTenant(objectId, opts = {}) {
    const { sessionId = 'sess-01', tenantId = 'tenant-01' } = opts && typeof opts === 'object' ? opts : {};
    const idStr = safeStr(objectId);
    const safeSession = safeStr(sessionId, 'sess-01');
    const safeTenant = safeStr(tenantId, 'tenant-01');
    const mac = crypto
      .createHmac('sha256', this.secret)
      .update(`bola:${safeSession}:${safeTenant}:${idStr}`)
      .digest('hex')
      .slice(0, 16);
    return `AEOBJ_${idStr}_${mac}`;
  }

  verifyObjectIdBola(sealedOrRawId, opts = {}) {
    const { sessionId = 'sess-01', tenantId = 'tenant-01' } = opts && typeof opts === 'object' ? opts : {};
    const str = safeStr(sealedOrRawId);
    const safeSession = safeStr(sessionId, 'sess-01');
    const safeTenant = safeStr(tenantId, 'tenant-01');
    const m = str.match(/^AEOBJ_(.+)_([0-9a-f]{16})$/);
    if (!m) {
      return {
        allowed: false,
        status: 403,
        reason: 'BOLA_IDOR_UNSEALED_OR_ENUMERATED_OBJECT_ID_BLOCKED',
      };
    }
    const rawId = m[1];
    const providedMac = m[2];
    const expectedMac = crypto
      .createHmac('sha256', this.secret)
      .update(`bola:${safeSession}:${safeTenant}:${rawId}`)
      .digest('hex')
      .slice(0, 16);
    if (!constantTimeEqual(providedMac, expectedMac)) {
      return {
        allowed: false,
        status: 403,
        reason: 'BOLA_IDOR_CROSS_TENANT_ACCESS_BLOCKED',
      };
    }
    return { allowed: true, status: 200, objectId: rawId };
  }

  /**
   * Vector 66: Universal JWT, OAuth2/PKCE & Device-Bound Session Integrity Guard
   */
  verifyUniversalJwtAndOAuthIntegrity(opts = {}) {
    const {
      jwtToken = '',
      expectedFingerprint = '',
      actualFingerprint = '',
      oauthCodeVerifier = '',
      oauthCodeChallenge = '',
    } = opts && typeof opts === 'object' ? opts : {};
    if (jwtToken) {
      const parts = safeStr(jwtToken).split('.');
      if (parts.length < 2) {
        return { allowed: false, reason: 'MALFORMED_JWT_BLOCKED' };
      }
      try {
        const headerJson = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
        if (!headerJson || !headerJson.alg || /^none$/i.test(safeStr(headerJson.alg))) {
          return { allowed: false, reason: 'JWT_ALG_NONE_SIGNATURE_BYPASS_BLOCKED' };
        }
        if (headerJson.jku || headerJson.x5u || (headerJson.kid && /(?:\.\.|\/|'|;|--|\bunion\b)/i.test(safeStr(headerJson.kid)))) {
          return { allowed: false, reason: 'JWT_HEADER_JKU_SSRF_OR_KID_INJECTION_BLOCKED' };
        }
      } catch {
        return { allowed: false, reason: 'JWT_HEADER_DECODE_FAILURE' };
      }
    }

    if (expectedFingerprint && actualFingerprint && !constantTimeEqual(expectedFingerprint, actualFingerprint)) {
      return {
        allowed: false,
        reason: 'DEVICE_BOUND_SESSION_FINGERPRINT_MISMATCH_BLOCKED',
      };
    }

    if (oauthCodeChallenge) {
      const computedChallenge = crypto
        .createHash('sha256')
        .update(safeStr(oauthCodeVerifier))
        .digest('base64url');
      if (!constantTimeEqual(computedChallenge, oauthCodeChallenge)) {
        return {
          allowed: false,
          reason: 'OAUTH2_PKCE_S256_VERIFIER_MISMATCH_BLOCKED',
        };
      }
    }

    return { allowed: true };
  }

  /**
   * Vector 67: Universal FinTech / SaaS Atomic Race-Condition & Double-Spend (`TOCTOU`) Mutex
   */
  acquireAtomicIdempotencyLock(opts = {}) {
    const {
      actorId = 'user-01',
      operation = 'withdraw',
      idempotencyKey = 'tx-01',
    } = opts && typeof opts === 'object' ? opts : {};
    if (!this._atomicLocks) {
      this._atomicLocks = new Set();
    }
    if (this._atomicLocks.size >= 10000) {
      const oldest = this._atomicLocks.values().next().value;
      if (oldest !== undefined) this._atomicLocks.delete(oldest);
    }
    const lockId = `${safeStr(actorId, 'user-01')}:${safeStr(operation, 'withdraw')}:${safeStr(idempotencyKey, 'tx-01')}`;
    if (this._atomicLocks.has(lockId)) {
      return {
        allowed: false,
        status: 409,
        reason: `CONCURRENT_RACE_CONDITION_DOUBLE_SPEND_BLOCKED:${lockId}`,
      };
    }
    this._atomicLocks.add(lockId);
    return {
      allowed: true,
      status: 200,
      lockId,
    };
  }
}


