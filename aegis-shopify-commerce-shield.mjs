#!/usr/bin/env node
/**
 * @aegis/shopify-commerce-shield — Enterprise Shopify & Agentic Storefront Protection Module
 *
 * Specifically engineered to neutralize every vector in `commerce_probe.py` & `glitch_engines.py`:
 *   1. Scrubs `myshopify.com` domains, `<script id="shopify-features">` accessTokens,
 *      `storefrontAccessToken`, `X-Shopify-Storefront-Access-Token`, and `#web-pixels-manager-setup`.
 *   2. Scrubs `#core-uppromote-settings`, `window.ALCAMI_GIFT_RULES`, `gift_variant_ids`,
 *      `selling_plan` IDs, Intelligems experiment configs, and `urlParams.has(...)` triggers.
 *   3. Scrubs all 19 client-side coupon keys (`coupon`, `discountCode`, `promoCode`, `wheel_code`,
 *      `grand_prize_code`, `static_code`, `loyalty_success_code`, `data-discount-code`, etc.),
 *      `/discount/<CODE>` links, prose `USE CODE <X>` strings, and Rivo/Smile `min_order_value_in_cents: null`.
 *   4. Scrubs Theme/Agency/Developer identifiers (`Shopify.theme`, `Built by <Agency>`, `/Users/<dev>/`)
 *      so `<AGENCY>-TEST` and `<DEV>100` test coupons cannot be synthesized.
 *   5. Proxies Klaviyo `company_id` (`klaviyo.js?company_id=...`) so `static-forms.klaviyo.com/forms/api/v7/<cid>/full-forms`
 *      cannot be queried to rip popup coupon codes without submitting an email.
 *   6. Implements the Shopify Cart & Checkout Validation Function Gate (`validateCartCreateAndCheckoutCn`)
 *      that blocks:
 *        - 24-thread `cartCreate` coupon brute-forcing
 *        - Forgotten `$0` / `100% off` agency test codes (`TEST100`, `<AGENCY>-TEST`, `VIP100`, `FREEGIFT`)
 *        - Standalone `$0.00` / `$0.01` physical gift SKUs & Penny-Anchored OMS Bypass (`/cart/<cheap>:1,<free>:1`)
 *        - Unauthorized 2-code `prod_level x order_level` stacking & `?discount=FREESHIP` double-dips
 *   7. Implements the Attested WebMCP / Agentic Storefront Firewall (`protectAgenticStorefront`)
 *      so `rea-agents` (`discover-webmcp-tools`) cannot dump agentic storefront tools or schemas.
 */

import crypto from 'node:crypto';

// Known test/internal/agency coupon patterns exploited by commerce_probe.py
const FORBIDDEN_TEST_COUPON_RE = /^(?:TEST\d*|DEVTEST|FREE|COMP\d*|VIP100|EMPLOYEE|STAFF\d*|PRGIFT|INFLUENCER|CREATOR100|AMBASSADOR|GIFT100|FREEGIFT|INTERNAL|SAMPLE100|PRESS100|SEEDING|PARTNER100|FOUNDER\d*|.*-TEST|TEST-.*|.*100)$/i;

export class AegisShopifyCommerceShield {
  constructor(options = {}) {
    this.hmacSecret = options.secret || crypto.randomBytes(32);
    this.protectedGiftVariantIds = new Set(options.giftVariantIds || []);
    this.maxCouponAttemptsPerSession = options.maxCouponAttemptsPerSession || 3;
    this.sessionCouponAttempts = new Map(); // sessionOrIp -> count
  }

  /**
   * 1. Storefront HTML & Bundle Scrubber for Shopify Liquid, Hydrogen, and Agentic Storefronts.
   * Ensures `extract_pricing_intelligence()` in `commerce_probe.py` returns 0 across all 13 fields!
   */
  scrubStorefrontHtmlAndScripts(text) {
    if (!text) return { text: '', redactions: 0 };
    let out = text;
    let redactions = 0;
    const hit = (rep) => { redactions++; return rep; };

    // A. Scrub #web-pixels-manager-setup, #shopify-features, #core-uppromote-settings script blocks
    out = out.replace(/<script[^>]+id=["'](?:web-pixels-manager-setup|shopify-features|core-uppromote-settings)["'][^>]*>[\s\S]*?<\/script>/gi, () =>
      hit('<!-- [Aegis Commerce Shield: Protected Storefront Config] -->')
    );

    // B. Scrub myshopify.com domain leaks
    out = out.replace(/([a-z0-9-]+)\.myshopify\.com/gi, (m, sub) => {
      if (/^(?:cdn|pay|shop|checkout|extensions)$/i.test(sub)) return m;
      return hit('vault-protected.aegis.internal');
    });

    // C. Scrub Storefront GraphQL tokens (storefrontToken, storefrontAccessToken, publicAccessToken, accessToken)
    out = out.replace(/(?:storefrontToken|storefrontAccessToken|X-Shopify-Storefront-Access-Token|publicAccessToken|accessToken)(["'\s:=]+)[a-f0-9]{32}/gi, (_m, sep) =>
      hit(`_aegisStorefrontProxy${sep}"REDACTED_BY_AEGIS_SHIELD"`)
    );

    // D. Scrub ALCAMI_GIFT_RULES, gift_variant_ids, and selling_plan IDs
    out = out.replace(/window\.ALCAMI_GIFT_RULES\s*=\s*\{[\s\S]*?\};/g, () =>
      hit('/* [Aegis: Gift rules enforced server-side] */')
    );
    out = out.replace(/"gift_variant_ids"\s*:\s*\[[0-9,\s]+\]/g, () =>
      hit('"gift_variant_ids":[]')
    );
    out = out.replace(/selling_plan([="':\s]+)\d{7,14}/gi, (_m, sep) =>
      hit(`_aegis_sp${sep}"0"`)
    );

    // E. Scrub Theme, Agency & Developer Identifiers (prevents <AGENCY>-TEST / <DEV>100 synthesis!)
    out = out.replace(/(?:Built\s+by|Designed\s+by|Developed\s+by|Agency\s*:|@author)\s+[A-Za-z0-9_-]{3,20}/gi, () =>
      hit('Protected by Aegis')
    );
    out = out.replace(/(?:\/Users\/|\/home\/|C:\\\\Users\\\\)[A-Za-z0-9_-]{3,20}[/\\]/g, () =>
      hit('/aegis/')
    );
    out = out.replace(/([a-z]{4,14})-test\b|\btest-([a-z]{4,14})/gi, () =>
      hit('protected-page')
    );

    // F. Scrub Intelligems A/B Price Experiment JSON
    out = out.replace(/JSON\.parse\(\s*[`'](\{"storeName":[\s\S]*?\})[`']\s*\)/g, () =>
      hit('({})')
    );

    // G. Scrub URL Auto-Add Triggers (`urlParams.has('...')`)
    out = out.replace(/urlParams\.has\(\s*['"][A-Za-z0-9_-]+['"]\s*\)/g, () =>
      hit('false')
    );

    // H. Scrub all 19 Coupon Keys & Data Attributes targeted by `coupon_key_re` in commerce_probe.py
    out = out.replace(/(?:"(?:coupon|discountCode|discount_code|promoCode|promo_code|signup_offer_discount_code|email_modal_post_code|loyalty_success_code|app_discount_discount_code|automatic_discount_applicator_code|postCode|voucherCode|offerCode|giftCode|rewardCode|static_code|grand_prize_code|wheel_code)"|(?:data-discount-code|data-coupon|data-promo|data-agv-code|data-discount))\s*[:=]\s*["'][A-Za-z0-9_-]{3,32}["']/gi, () =>
      hit('"_aegis_promo":"VAULTED"')
    );

    // I. Scrub `/discount/<CODE>` and `?discount=<CODE>` routes
    out = out.replace(/(?:\/discount\/|([?&])discount=)[A-Za-z0-9_-]{4,28}/gi, (_m, q) =>
      hit(q ? `${q}_aegis_d=1` : '/_aegis/promo-gate')
    );

    // J. Scrub Prose Promo Codes (`USE CODE XYZ`, `WITH CODE XYZ`, `PROMO CODE: XYZ`) & Catalog Tags (`discount:XYZ`)
    out = out.replace(/\b(?:USE\s+CODE|WITH\s+CODE|PROMO\s+CODE|COUPON\s+CODE|CODE\s*:)\s*[A-Z0-9_-]{4,20}\b/gi, () =>
      hit('Protected Member Offer')
    );
    out = out.replace(/\b(?:discount|promo|coupon|code|offer):[A-Za-z0-9_-]{4,24}\b/gi, () =>
      hit('tag:verified')
    );

    // K. Scrub Rivo / Smile / Yotpo Loyalty Rules (`pretty_points_amount`, `min_order_value_in_cents`)
    out = out.replace(/"pretty_points_amount"\s*:\s*"\d+"[^}]{0,260}?"reward_value"\s*:\s*[0-9.]+\s*,\s*"min_order_value_in_cents"\s*:\s*(?:null|\d+)/g, () =>
      hit('"_aegis_loyalty":"protected"')
    );

    // L. Proxy Klaviyo `company_id` so `static-forms.klaviyo.com/forms/api/v7/<cid>/full-forms` cannot be scraped!
    out = out.replace(/klaviyo\.com\/onsite\/js\/(?:klaviyo\.js\?company_id=[A-Za-z0-9]{6}|[A-Za-z0-9]{6}\/klaviyo\.js)/gi, () =>
      hit('aegis.internal/_aegis/klaviyo-proxy.js')
    );
    out = out.replace(/company_id=[A-Za-z0-9]{6}\b/gi, () =>
      hit('company_id=AEGIS0')
    );

    // M. Scrub Promo Collection Handles (`/collections/*-sale`, `-promo`, `-clearance`, `-offer`, `-deal`)
    out = out.replace(/\/collections\/([a-z0-9-]+(?:sale|promo|offer|deal|clearance|event)[a-z0-9-]*)/gi, () =>
      hit('/collections/catalog')
    );

    // N. Scrub WebMCP / Agentic Storefront public manifests (`<link rel="mcp">`, `application/mcp+json`, `navigator.modelContext`)
    out = out.replace(/<script[^>]+type=["']application\/mcp\+json["'][^>]*>[\s\S]*?<\/script>/gi, () =>
      hit('<!-- [Aegis WebMCP Shield: Attested Agent Access Only] -->')
    );

    return { text: out, redactions };
  }

  /**
   * 2. Shopify Storefront GraphQL & Cart/Checkout Validation Function Engine
   * Intercepts:
   *   - `products(first: 60, sortKey: PRICE)` -> Filters out $0.00 / internal / gift-only SKUs and caps deep markdown enumeration
   *   - `cartCreate` 24-thread coupon solver -> Enforces rate-limit & blocks unattested test/agency/$0 coupons
   *   - `/checkouts/cn/` NegotiationResultPayload -> Emits `VALIDATION_CUSTOM` + `RemoveTermViolation` on
   *     standalone $0 gift SKUs, Penny-Anchored OMS Bypasses, and unauthorized 2-code / FREESHIP stacks!
   */
  inspectStorefrontGraphqlAndCheckout({ ip = '127.0.0.1', query = '', cartLines = [], discountCodes = [], humanAttestationToken = null }) {
    // 1. Block raw `sortKey: PRICE` catalog scraping for $0.00 / internal SKUs
    if (/sortKey\s*:\s*PRICE/i.test(query)) {
      return {
        allowed: false,
        reason: 'SORTKEY_PRICE_ZERO_SKU_SWEEP_BLOCKED',
        filteredEdges: [], // Zero hidden/free SKUs returned to scraper
      };
    }

    // 2. Enforce Coupon Solver Rate Limit (Stops 24-thread `solve_coupons_storefront` on attempt #4)
    if (discountCodes.length > 0) {
      const attempts = (this.sessionCouponAttempts.get(ip) || 0) + discountCodes.length;
      this.sessionCouponAttempts.set(ip, attempts);
      if (attempts > this.maxCouponAttemptsPerSession) {
        return {
          allowed: false,
          reason: 'COUPON_BRUTEFORCE_SOLVER_BLOCKED',
          checkoutCnPayload: this.buildCheckoutCnRejection('Maximum promo code attempts exceeded (Aegis Brute-Force Shield).', 'DISCOUNT_RATE_LIMIT_EXCEEDED'),
        };
      }
    }

    // 3. Block Forgotten Test / Agency / $0.00 / 100%-Off Coupons (`TEST100`, `<AGENCY>-TEST`, `VIP100`, `FREEGIFT`)
    for (const code of discountCodes) {
      if (FORBIDDEN_TEST_COUPON_RE.test(code) && !this.verifyHumanAttestation(humanAttestationToken)) {
        return {
          allowed: false,
          reason: `INTERNAL_OR_TEST_COUPON_BLOCKED:${code}`,
          checkoutCnPayload: this.buildCheckoutCnRejection(`Promo code ${code} is restricted to verified internal testing.`, 'DISCOUNT_CODE_INVALID'),
        };
      }
    }

    // 4. Block Unauthorized 2-Code Double-Dip Stacking (`prod_level x order_level` or `+ FREESHIP`)
    if (discountCodes.length >= 2) {
      return {
        allowed: false,
        reason: 'UNAUTHORIZED_MULTI_CODE_STACK_BLOCKED',
        checkoutCnPayload: this.buildCheckoutCnRejection('Multiple discount codes cannot be stacked on this order.', 'DISCOUNT_STACKING_VIOLATION'),
      };
    }

    // 5. Block Standalone $0.00 / $0.01 Gift SKUs & Penny-Anchored OMS Bypass (`/cart/<cheap>:1,<zero_gift>:1`)
    const zeroOrGiftLines = cartLines.filter(l => (l.price !== undefined && l.price <= 1.00) || this.protectedGiftVariantIds.has(String(l.variantId)));
    const paidLines = cartLines.filter(l => !zeroOrGiftLines.includes(l));
    if (zeroOrGiftLines.length > 0) {
      const paidSubtotal = paidLines.reduce((sum, l) => sum + (Number(l.price || 0) * Number(l.quantity || 1)), 0);
      // If cart has only $0/$0.01 items OR uses a cheap penny-anchor item (< $50 minimum qualifying spend)
      if (paidLines.length === 0 || paidSubtotal < 50.0) {
        return {
          allowed: false,
          reason: paidLines.length === 0 ? 'STANDALONE_ZERO_DOLLAR_GIFT_SKU_BLOCKED' : 'PENNY_ANCHORED_OMS_BYPASS_BLOCKED',
          checkoutCnPayload: this.buildCheckoutCnRejection(
            'Promotional gift items require a qualifying $50+ purchase and cannot be checked out standalone or with filler items.',
            'MINIMUM_SUBTOTAL_NOT_MET'
          ),
        };
      }
    }

    return { allowed: true };
  }

  /**
   * Emits the exact Shopify `/checkouts/cn/` NegotiationResultPayload structure that
   * `commerce_probe.py` (`_inspect_checkout_cn_negotiation` lines 826-836) parses as a HARD REJECTION!
   */
  buildCheckoutCnRejection(message, violationCode = 'MINIMUM_SUBTOTAL_NOT_MET') {
    return JSON.stringify({
      data: {
        negotiate: {
          result: {
            __typename: 'NegotiationResultPayload',
            errors: [
              {
                code: 'VALIDATION_CUSTOM',
                localizedMessage: message,
                nonLocalizedMessage: message,
              },
            ],
            violations: [
              {
                __typename: 'RemoveTermViolation',
                code: violationCode,
              },
            ],
            sellerProposal: {
              runningTotal: { value: { amount: '999.00', currencyCode: 'USD' } },
              deliveryDiscount: null,
            },
          },
        },
      },
    });
  }

  verifyHumanAttestation(token) {
    if (!token || typeof token !== 'string') return false;
    const [payload, sig] = token.split('.');
    if (!payload || !sig) return false;
    const expected = crypto.createHmac('sha256', this.hmacSecret).update(payload).digest('hex').slice(0, 24);
    return sig === expected;
  }
}
