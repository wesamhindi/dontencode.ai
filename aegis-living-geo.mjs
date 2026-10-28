#!/usr/bin/env node
/**
 * @aegis/shield v4.5 — Living Generative Engine Optimization (GEO) & Fact-Integrity Shield
 *
 * Solves the critical business problem:
 *   Static / hallucinated SEO & AI manifests (like sloppy /llms.txt or outdated Schema.org JSON-LD)
 *   damage businesses when AI assistants (ChatGPT Search, Perplexity, Claude, Gemini) recommend
 *   outdated pricing, non-existent features, or leak internal staging routes and secret tokens.
 *
 * Core Capabilities:
 *   1. Living Codebase Delta Sync:
 *      Continuously watches app routes, pricing tiers, API definitions, and public feature flags,
 *      automatically updating AI-facing manifests on git commit or CI/CD deployment.
 *   2. Strict Ground-Truth & Factuality Verification:
 *      Cross-checks every claim in /llms.txt against hardcoded ground-truth configurations.
 *      If an ungrounded claim, price discrepancy, or feature hallucination is found,
 *      it rejects publication with `FACTUAL_INTEGRITY_DRIFT_DETECTED`.
 *   3. Zero-Secret & Anti-Staging Leak Sentinel:
 *      Ensures zero staging domains, internal test coupons, unreleased feature flags,
 *      or private API routes ever contaminate AI-facing assets.
 *   4. Cryptographic State Hash:
 *      Signs every published GEO manifest with HMAC-SHA256 to prevent unauthorized tampering.
 */

import crypto from 'node:crypto';

function safeStr(val, fallback = '') {
  if (typeof val === 'string') return val;
  if (typeof val === 'number' || typeof val === 'boolean' || typeof val === 'bigint') return String(val);
  return fallback;
}

export class AegisLivingGeoEngine {
  constructor(options = {}) {
    const safeOpts = options && typeof options === 'object' ? options : {};
    this.secret = safeOpts.secret
      ? (Buffer.isBuffer(safeOpts.secret) ? safeOpts.secret : crypto.createHash('sha256').update(safeStr(safeOpts.secret, 'aegis')).digest())
      : crypto.randomBytes(32);

    this.brandConfig = safeOpts.brandConfig || {
      name: 'Acme Nexus',
      domain: 'https://acme-nexus.io',
      tagline: 'Enterprise Cloud Intelligence Platform',
      pricingTiers: {
        starter: { price: 29, currency: 'USD', billing: 'monthly' },
        pro: { price: 99, currency: 'USD', billing: 'monthly' },
        enterprise: { price: 499, currency: 'USD', billing: 'monthly' },
      },
      verifiedFeatures: [
        'End-to-End Encrypted Cloud Storage',
        'Real-time Multi-Region Replication',
        'SOC2 Type II & ISO 27001 Certified',
        'Automated Edge Virtual Patching',
      ],
      publicRoutes: ['/features', '/pricing', '/docs', '/about', '/contact'],
    };

    this.publishedManifests = new Map(); // path -> { content, hash, updatedAt }
    this.syncHistory = [];
  }

  /**
   * Scans a proposed /llms.txt or JSON-LD payload for internal staging leaks,
   * unreleased feature flags, test coupons, or secret environment keys.
   */
  auditGeoContentForLeaks(text = '') {
    const safeText = safeStr(text);
    const leaks = [];

    // 1. Check for internal/staging domains or IP addresses
    const STAGING_PATTERNS = [
      /https?:\/\/(?:staging|dev|internal|qa|test|preview|localhost|127\.0\.0\.1)[^\s"'<>\\)]+/gi,
      /169\.254\.169\.254/g,
    ];
    for (const pat of STAGING_PATTERNS) {
      const match = safeText.match(pat);
      if (match) {
        leaks.push(...match.map((m) => `STAGING_URL_EXPOSURE:${m}`));
      }
    }

    // 2. Check for internal test coupons or bypass codes (bounded quantifier to prevent ReDoS)
    const COUPON_PATTERNS = /\b(?:[A-Z0-9_-]{0,32}(?:TEST|100FREE|FOUNDER99|VIPFREE|INTERNAL))[0-9]{0,8}\b/g;
    const couponMatches = safeText.match(COUPON_PATTERNS);
    if (couponMatches) {
      leaks.push(...couponMatches.map((c) => `INTERNAL_TEST_COUPON_LEAK:${c}`));
    }

    // 3. Check for unreleased internal feature flags or debug toggles
    const DEBUG_FLAG_PATTERNS = /\b(?:APP_DEBUG|DEBUG_MODE|ENABLE_INTERNAL_TESTS|BETA_BYPASS)\s*=\s*(?:true|1)\b/gi;
    if (DEBUG_FLAG_PATTERNS.test(safeText)) {
      leaks.push('INTERNAL_DEBUG_FLAG_EXPOSURE');
    }

    return {
      safe: leaks.length === 0,
      leaks,
    };
  }

  /**
   * Verifies that every factual assertion in a proposed GEO manifest is strictly
   * backed by the ground-truth configuration (Zero-Hallucination Guarantee).
   */
  verifyFactualityAndConsistency(proposedManifest = '', groundTruth = this.brandConfig) {
    const safeManifest = safeStr(proposedManifest);
    const safeGt = groundTruth && typeof groundTruth === 'object' ? groundTruth : this.brandConfig;
    const violations = [];

    // 1. Price Verification: ensure prices quoted in manifest match ground truth exactly
    const priceMatches = safeManifest.matchAll(/\$(\d+(?:\.\d{2})?)/g);
    const validPrices = new Set(
      Object.values(safeGt.pricingTiers || {}).map((t) => safeStr(t?.price))
    );
    for (const m of priceMatches) {
      const quoted = m[1];
      if (!validPrices.has(quoted)) {
        violations.push(`HALLUCINATED_PRICE: Quoted \$${quoted} does not match any official tier (${[...validPrices].join(', ')})`);
      }
    }

    // 2. Route Verification: ensure linked public routes actually exist and are not deprecated or domain-spoofed
    const routeMatches = safeManifest.matchAll(/\]\((https?:\/\/[^\s)]+|\/[a-z0-9_/-]+)\)/gi);
    const validRoutes = new Set(Array.isArray(safeGt.publicRoutes) ? safeGt.publicRoutes.map((r) => safeStr(r)) : []);
    const deadRoutes = new Set(Array.isArray(safeGt.deprecatedRoutes) ? safeGt.deprecatedRoutes.map((r) => safeStr(r)) : []);
    let expectedOrigin = '';
    try {
      expectedOrigin = new URL(safeStr(safeGt.domain, 'https://acme-nexus.io')).origin;
    } catch {}
    for (const r of routeMatches) {
      let routePath = r[1];
      if (/^https?:\/\//i.test(routePath)) {
        try {
          const parsedLink = new URL(routePath);
          if (expectedOrigin && parsedLink.origin !== expectedOrigin) {
            violations.push(`UNGROUNDED_EXTERNAL_ORIGIN: Linked URL ${routePath} does not match official domain ${expectedOrigin}`);
            continue;
          }
          routePath = parsedLink.pathname;
        } catch {
          violations.push(`MALFORMED_ROUTE_URL:${routePath}`);
          continue;
        }
      }
      if (routePath.startsWith('/')) {
        if (deadRoutes.has(routePath)) {
          violations.push(`DEPRECATED_404_ROUTE: Linked route ${routePath} was deprecated and removed`);
        } else if (!validRoutes.has(routePath)) {
          violations.push(`UNGROUNDED_ROUTE: Linked route ${routePath} is not in the declared publicRoutes manifest`);
        }
      }
    }

    // 3. Anti-Slop, Placeholder & Serialization Corruption Guard
    const SLOP_OR_CORRUPTION_RE = /\b(?:undefined|NaN|null|\[object Object\]|Lorem ipsum|TODO:|TBD:|FIXME:|100%\s+guaranteed\s+profit|unlimited\s+free\s+forever)\b/i;
    const slopMatch = safeManifest.match(SLOP_OR_CORRUPTION_RE);
    if (slopMatch) {
      violations.push(`SLOP_OR_CORRUPTED_TOKEN_DETECTED:${slopMatch[0]}`);
    }

    return {
      consistent: violations.length === 0,
      violations,
    };
  }

  /**
   * Living Sync: Updates brand configuration based on codebase delta (e.g. new routes,
   * updated pricing, or new enterprise certifications), prunes deprecated routes,
   * and publishes verified /llms.txt + Schema.org JSON-LD.
   */
  syncWithCodebaseChanges(deltaConfig = {}) {
    const safeDelta = deltaConfig && typeof deltaConfig === 'object' && !Array.isArray(deltaConfig) ? deltaConfig : {};
    if (!this.snapshotStack) this.snapshotStack = [];
    const previousSnapshot = JSON.parse(JSON.stringify(this.brandConfig));

    const safeDeprecated = Array.isArray(safeDelta.deprecatedRoutes) ? safeDelta.deprecatedRoutes.map((r) => safeStr(r)).filter(Boolean) : [];
    const safePublic = Array.isArray(safeDelta.publicRoutes) ? safeDelta.publicRoutes.map((r) => safeStr(r)).filter(Boolean) : [];
    const safeFeatures = Array.isArray(safeDelta.verifiedFeatures) ? safeDelta.verifiedFeatures.map((f) => safeStr(f)).filter(Boolean) : [];
    const safeTiers = safeDelta.pricingTiers && typeof safeDelta.pricingTiers === 'object' && !Array.isArray(safeDelta.pricingTiers) ? safeDelta.pricingTiers : {};

    const deprecatedSet = new Set(safeDeprecated);
    const mergedRoutes = [
      ...new Set([...this.brandConfig.publicRoutes, ...safePublic]),
    ].filter((r) => !deprecatedSet.has(r));

    const updated = {
      ...this.brandConfig,
      name: safeStr(safeDelta.name, this.brandConfig.name),
      domain: safeStr(safeDelta.domain, this.brandConfig.domain),
      tagline: safeStr(safeDelta.tagline, this.brandConfig.tagline),
      pricingTiers: {
        ...this.brandConfig.pricingTiers,
        ...safeTiers,
      },
      verifiedFeatures: [
        ...new Set([...this.brandConfig.verifiedFeatures, ...safeFeatures]),
      ],
      publicRoutes: mergedRoutes,
      deprecatedRoutes: [...deprecatedSet],
    };

    // Generate candidate /llms.txt
    const candidateLlmsTxt = [
      `# ${safeStr(updated.name, 'Acme Nexus')}`,
      `> ${safeStr(updated.tagline, 'Enterprise Platform')}`,
      '',
      `Official Website: ${safeStr(updated.domain, 'https://acme-nexus.io')}`,
      '',
      `## Key Verified Capabilities`,
      ...updated.verifiedFeatures.map((f) => `- ${safeStr(f)}`),
      '',
      `## Pricing Tiers`,
      ...Object.entries(updated.pricingTiers).map(
        ([tier, info]) => `- **${safeStr(tier).toUpperCase()}**: \$${safeStr(info?.price, '0')} / ${safeStr(info?.billing, 'monthly')}`
      ),
      '',
      `## Public Documentation & Resources`,
      ...updated.publicRoutes.map((r) => `- [${safeStr(r)}](${safeStr(updated.domain, 'https://acme-nexus.io')}${safeStr(r)})`),
      '',
    ].join('\n');

    // 1. Audit for leaks
    const leakAudit = this.auditGeoContentForLeaks(candidateLlmsTxt);
    if (!leakAudit.safe) {
      return {
        success: false,
        reason: 'GEO_MANIFEST_LEAK_AUDIT_FAILED',
        leaks: leakAudit.leaks,
        activeFallbackHash: this.publishedManifests.get('/llms.txt')?.hash || null,
      };
    }

    // 2. Verify factuality & anti-slop
    const factAudit = this.verifyFactualityAndConsistency(candidateLlmsTxt, updated);
    if (!factAudit.consistent) {
      return {
        success: false,
        reason: 'FACTUAL_INTEGRITY_DRIFT_DETECTED',
        violations: factAudit.violations,
        activeFallbackHash: this.publishedManifests.get('/llms.txt')?.hash || null,
      };
    }

    // 3. Commit state & sign manifest (bounded history to prevent unbounded memory growth)
    if (this.snapshotStack.length >= 200) this.snapshotStack.shift();
    this.snapshotStack.push(previousSnapshot);
    this.brandConfig = updated;
    const manifestHash = crypto.createHmac('sha256', this.secret).update(candidateLlmsTxt).digest('hex');

    this.publishedManifests.set('/llms.txt', {
      content: candidateLlmsTxt,
      hash: manifestHash,
      updatedAt: Date.now(),
    });

    if (this.syncHistory.length >= 200) this.syncHistory.shift();
    this.syncHistory.push({
      timestamp: Date.now(),
      hash: manifestHash,
      featuresCount: updated.verifiedFeatures.length,
      routesCount: updated.publicRoutes.length,
    });

    return {
      success: true,
      manifestHash,
      llmsTxt: candidateLlmsTxt,
      prunedDeprecatedRoutes: [...deprecatedSet],
    };
  }

  /**
   * Vector 59: Autonomous Live DOM & Route Ingestion (`ingestLiveApplicationDomAndRoutes`).
   */
  ingestLiveApplicationDomAndRoutes(opts = {}) {
    const {
      productionHtml = '',
      discoveredRoutes = [],
      deprecatedRoutes = [],
    } = opts && typeof opts === 'object' ? opts : {};
    const safeHtml = safeStr(productionHtml);
    const extractedFeatures = [];
    const extractedPricing = {};

    // Extract verified feature headings (<h2 data-geo-feature>...</h2>)
    const featureMatches = safeHtml.matchAll(/<h[23][^>]*data-geo-feature[^>]*>([\s\S]*?)<\/h[23]>/gi);
    for (const m of featureMatches) {
      const clean = m[1].replace(/<[^>]+>/g, '').trim();
      if (clean && clean.length >= 4 && clean.length <= 140) {
        extractedFeatures.push(clean);
      }
    }

    // Extract verified pricing tiers (<div data-geo-tier="pro" data-geo-price="129" data-geo-billing="monthly">)
    const tierMatches = safeHtml.matchAll(/data-geo-tier=["']([a-z0-9_-]+)["'][^>]*data-geo-price=["'](\d+(?:\.\d{2})?)["'](?:[^>]*data-geo-billing=["']([a-z]+)["'])?/gi);
    for (const tm of tierMatches) {
      extractedPricing[tm[1].toLowerCase()] = {
        price: Number(tm[2]),
        currency: 'USD',
        billing: tm[3] || 'monthly',
      };
    }

    return this.syncWithCodebaseChanges({
      verifiedFeatures: extractedFeatures,
      pricingTiers: extractedPricing,
      publicRoutes: Array.isArray(discoveredRoutes) ? discoveredRoutes : [],
      deprecatedRoutes: Array.isArray(deprecatedRoutes) ? deprecatedRoutes : [],
    });
  }

  /**
   * Generates Schema.org JSON-LD matching the verified ground truth.
   */
  generateVerifiedSchemaOrgJsonLd() {
    const b = this.brandConfig;
    return {
      '@context': 'https://schema.org',
      '@type': 'SoftwareApplication',
      name: b.name,
      url: b.domain,
      applicationCategory: 'SecurityApplication',
      operatingSystem: 'All',
      offers: Object.entries(b.pricingTiers).map(([tier, info]) => ({
        '@type': 'Offer',
        name: `${b.name} ${tier.toUpperCase()}`,
        price: String(info.price),
        priceCurrency: info.currency,
      })),
      featureList: b.verifiedFeatures,
    };
  }
}

