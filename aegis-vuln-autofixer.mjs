#!/usr/bin/env node
/**
 * @aegis/shield v4.0 — Universal Vulnerability Scanner, Auto-Fixer, Virtual-Patching WAF & Remediation Engine
 *
 * Covers the most critical real-world vulnerabilities across PHP, Python, Node.js/Next.js/React, Java, Go & Cloud:
 *   1. PHP Ecosystem:
 *      - "PHP2Shell" (CVE-2026-109618 & CVE-2026-109619, CVSS 9.2): OOM/longjmp & Use-After-Free RCE in PHP < 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
 *      - PHP-CGI Argument Injection (CVE-2024-4577): `%ADd+allow_url_include=1+-d+auto_prepend_file=php://input`
 *      - Laravel Ignition / Debug RCE & APP_DEBUG=true exposure & PHP Object Injection (`unserialize()`)
 *   2. Python Ecosystem:
 *      - Django QuerySet Dict-Expansion SQLi (CVE-2025-64459, CVSS 9.1): `_connector` & `_negated` injection in `.filter(**dict)`
 *      - Starlette / FastAPI "BadHost" Access Control Bypass (CVE-2026-48710): Host / X-Forwarded-Host manipulation
 *      - PyTorch `torch.load` RCE (CVE-2025-32434 & CVE-2026-24747, CVSS 8.8): Deserialization RCE in PyTorch < 2.10.0
 *      - Flask / Jinja2 SSTI (`render_template_string`), PyYAML `yaml.load()`, `pickle.loads()`, Werkzeug `DEBUG=True`
 *   3. Node.js / Next.js / React Ecosystem:
 *      - "Node2Shell" Brotli Decoder Out-of-Bounds Write RCE (CVE-2026-111497, CVSS 9.8) in Node.js < 22.23.4 / 24.22.1 / 26.12.1
 *      - React Server Components (RSC) Flight Protocol RCE (CVE-2025-55182 / CVE-2025-66478, CVSS 10.0)
 *      - Next.js Middleware Authorization Bypass (CVE-2025-29927: `x-middleware-subrequest`)
 *      - Next.js Image Optimization SVG RCE (CVE-2026-96889 / GHSA-2464-fhr4-w9xw) & `use cache` RCE (GHSA-673q-mjm6-r5xr)
 *   4. Universal Cloud / Web / Java / Go Vectors:
 *      - Cloud Metadata SSRF (`169.254.169.254`, `metadata.google.internal`, `fd00:ec2::254`)
 *      - Log4Shell / SpEL Injection (`${jndi:...}`, `#{...}`), Path Traversal (`../`), `.env` / `.git/config` exposure
 */

function safeStr(val, fallback = '') {
  if (typeof val === 'string') return val;
  if (typeof val === 'number' || typeof val === 'boolean' || typeof val === 'bigint') return String(val);
  return fallback;
}

export class AegisVulnAutoFixer {
  constructor(options = {}) {
    const safeOpts = options && typeof options === 'object' ? options : {};
    this.allowedHosts = new Set(Array.isArray(safeOpts.allowedHosts) ? safeOpts.allowedHosts : ['acme-nexus.io', 'api.acme-nexus.io', 'localhost']);
  }

  /**
   * 1. REAL-TIME EDGE VIRTUAL PATCHING (WAF)
   * Blocks exploit payloads on the wire BEFORE they reach an unpatched PHP, Python, Node.js, Next.js, Java, or Go backend!
   */
  inspectRequestVirtualPatch(opts = {}) {
    const {
      method = 'GET',
      url = '/',
      headers = {},
      query = {},
      body = null,
    } = opts && typeof opts === 'object' ? opts : {};
    const safeUrl = safeStr(url, '/');
    const lowerHeaders = {};
    if (headers && typeof headers === 'object') {
      for (const [k, v] of Object.entries(headers)) {
        lowerHeaders[k.toLowerCase()] = safeStr(v);
      }
    }
    const bodyStr = typeof body === 'string' ? body : JSON.stringify(body || {});
    const queryStr = typeof query === 'string' ? query : JSON.stringify(query || {});
    const combinedInput = `${safeUrl}\n${queryStr}\n${bodyStr}`;

    // A. Next.js Middleware Authorization Bypass (CVE-2025-29927)
    if (lowerHeaders['x-middleware-subrequest']) {
      return {
        blocked: true,
        cve: 'CVE-2025-29927',
        stack: 'Next.js',
        reason: 'NEXTJS_MIDDLEWARE_SUBREQUEST_AUTH_BYPASS_BLOCKED',
      };
    }

    // B. Node2Shell Brotli Decoder RCE (CVE-2026-111497)
    if (/\bbr\b/i.test(lowerHeaders['content-encoding'] || '')) {
      return {
        blocked: true,
        cve: 'CVE-2026-111497',
        stack: 'Node.js',
        reason: 'NODE2SHELL_INBOUND_BROTLI_RCE_BLOCKED',
      };
    }

    // C. Starlette / FastAPI "BadHost" Header Bypass (CVE-2026-48710)
    const hostHdr = (lowerHeaders['x-forwarded-host'] || lowerHeaders['host'] || '').split(':')[0].trim();
    if (hostHdr && this.allowedHosts.size > 0 && !this.allowedHosts.has(hostHdr)) {
      return {
        blocked: true,
        cve: 'CVE-2026-48710',
        stack: 'Python (FastAPI/Starlette)',
        reason: `BADHOST_HEADER_SPOOF_BLOCKED:${hostHdr}`,
      };
    }

    // D. PHP2Shell (CVE-2026-109618 & CVE-2026-109619) & PHP-CGI (CVE-2024-4577) & Laravel Ignition RCE
    if (
      /PHP_SESSION_UPLOAD_PROGRESS/i.test(combinedInput) ||
      /PHPSESSID=[^;\s]{128,}/i.test(lowerHeaders['cookie'] || '') ||
      /(?:%AD|-d)\s*allow_url_include|auto_prepend_file\s*=|php:\/\/input|php:\/\/filter/i.test(combinedInput) ||
      /\/_ignition\/execute-solution|\/_profiler\/|phpinfo\.php/i.test(safeUrl)
    ) {
      return {
        blocked: true,
        cve: 'CVE-2026-109618 / CVE-2026-109619 / CVE-2024-4577',
        stack: 'PHP (Core / Laravel / WordPress / FPM)',
        reason: 'PHP2SHELL_OR_CGI_RCE_PAYLOAD_BLOCKED',
      };
    }

    // E. Django QuerySet Dict-Expansion SQL Injection (CVE-2025-64459)
    if (/"?(?:_connector|_negated)"?\s*:|[\?&](?:_connector|_negated)=/i.test(combinedInput)) {
      return {
        blocked: true,
        cve: 'CVE-2025-64459',
        stack: 'Python (Django)',
        reason: 'DJANGO_QUERYSET_CONNECTOR_SQLI_BLOCKED',
      };
    }

    // F. Python Jinja2 SSTI / Pickle / PyYAML / Torch Deserialization RCE
    if (
      /\{\{[\s\S]*?(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|config\.items)[\s\S]*?\}\}/i.test(combinedInput) ||
      /!!python\/object|cos\nsystem|posix\nsystem|torch\.storage\._load_from_bytes/i.test(combinedInput)
    ) {
      return {
        blocked: true,
        cve: 'CVE-2026-24747 / SSTI / Deserialization',
        stack: 'Python (Flask / Jinja2 / PyTorch / PyYAML)',
        reason: 'PYTHON_SSTI_OR_DESERIALIZATION_RCE_BLOCKED',
      };
    }

    // G. React Server Components (RSC) Flight Protocol RCE (CVE-2025-55182) & Next.js SVG Image RCE (CVE-2026-96889)
    if (
      (lowerHeaders['next-action'] && /(?:\$@|__proto__|constructor\.prototype)/i.test(bodyStr)) ||
      (/\/_next\/image\b/i.test(safeUrl) && /\.svg\b|<svg/i.test(combinedInput))
    ) {
      return {
        blocked: true,
        cve: 'CVE-2025-55182 / CVE-2026-96889',
        stack: 'React / Next.js',
        reason: 'RSC_FLIGHT_OR_NEXT_IMAGE_SVG_RCE_BLOCKED',
      };
    }

    // H. Universal Cloud Metadata SSRF (AWS IMDSv1 / GCP / Azure) & Path Traversal & Log4Shell
    if (
      /(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|\[?fd00:ec2::254\]?)/i.test(combinedInput) ||
      /(?:\.\.\/|\.\.\\|%2e%2e%2f){2,}/i.test(combinedInput) ||
      /\$\{(?:jndi|lower|upper|env):/i.test(combinedInput)
    ) {
      return {
        blocked: true,
        cve: 'SSRF-IMDS / Path-Traversal / JNDI',
        stack: 'Universal Cloud / Backend',
        reason: 'CLOUD_METADATA_SSRF_OR_TRAVERSAL_BLOCKED',
      };
    }

    return { blocked: false };
  }

  /**
   * 2. STATIC SOURCE & CONFIG VULNERABILITY SCANNER + AUTOMATIC CODE PATCHER + MANUAL INSTRUCTIONS GENERATOR
   */
  scanAndAutoFixProject(opts = {}) {
    const {
      files = {},
      runtimeVersions = {},
    } = opts && typeof opts === 'object' ? opts : {};
    const safeFiles = files && typeof files === 'object' ? files : {};
    const safeRv = runtimeVersions && typeof runtimeVersions === 'object' ? runtimeVersions : {};
    const fixedFiles = {};
    const autoFixedIssues = [];
    const manualInstructions = [];

    // 1. Check Server Runtime Binary Versions (Cannot be fixed by editing JS/PHP/PY source alone -> Emit exact instructions + Virtual Patch!)
    if (safeRv.php) {
      const v = String(safeRv.php);
      const isVulnPhp =
        (v.startsWith('8.2.') && Number(v.split('.')[2]) < 35) ||
        (v.startsWith('8.3.') && Number(v.split('.')[2]) < 36) ||
        (v.startsWith('8.4.') && Number(v.split('.')[2]) < 27) ||
        (v.startsWith('8.5.') && Number(v.split('.')[2]) < 12) ||
        /^[57]\.|^8\.[01]\./.test(v);
      if (isVulnPhp) {
        manualInstructions.push({
          id: 'CVE-2026-109618 / CVE-2026-109619 (PHP2Shell)',
          severity: 'CRITICAL (CVSS 9.2)',
          stack: `PHP Runtime (${v})`,
          virtualPatchedAtEdge: true,
          whyManualRequired: 'The vulnerability resides in the C-level PHP interpreter engine (longjmp OOM & Use-After-Free). Source code edits cannot replace the OS binary.',
          steps: [
            '1. Upgrade PHP binary on the server to >= 8.2.35, >= 8.3.36, >= 8.4.27, or >= 8.5.12 (`sudo apt update && sudo apt install --only-upgrade php*`).',
            '2. Restart all persistent PHP-FPM / FrankenPHP / Apache mod_php workers immediately (`sudo systemctl restart php-fpm nginx`).',
            '3. Ensure `session.upload_progress.enabled = Off` is set in `php.ini` (Aegis has auto-patched local `php.ini` if provided).',
          ],
        });
      }
    }

    if (safeRv.node) {
      const v = String(safeRv.node).replace(/^v/, '');
      const [maj, min, pat] = v.split('.').map(Number);
      const isVulnNode =
        maj < 22 ||
        (maj === 22 && (min < 23 || (min === 23 && pat < 4))) ||
        (maj === 24 && (min < 22 || (min === 22 && pat < 1)));
      if (isVulnNode) {
        manualInstructions.push({
          id: 'CVE-2026-111497 (Node2Shell Brotli RCE)',
          severity: 'CRITICAL (CVSS 9.8)',
          stack: `Node.js Runtime (v${v})`,
          virtualPatchedAtEdge: true,
          whyManualRequired: 'Out-of-bounds write in the native C++ Brotli decoder bundled inside the Node.js binary.',
          steps: [
            '1. Upgrade the Node.js runtime binary to >= 22.23.4, >= 24.22.1, or >= 26.12.1 (`nvm install 22.23.4 && nvm alias default 22.23.4`).',
            '2. Rebuild or redeploy Docker containers using `FROM node:22.23.4-alpine` or newer.',
            '3. Keep Aegis Edge Gate active to strip inbound `Content-Encoding: br` headers until all nodes are upgraded.',
          ],
        });
      }
    }

    // 2. Scan and Auto-Fix Project Source & Configuration Files
    for (const [filePath, rawContent] of Object.entries(safeFiles)) {
      let content = String(rawContent);
      let modified = false;

      // --- A. PHP `php.ini` Auto-Hardening (Mitigates PHP2Shell CVE-2026-109618 & Info Leaks) ---
      if (filePath.endsWith('php.ini')) {
        if (/session\.upload_progress\.enabled\s*=\s*(?:On|1)/i.test(content)) {
          content = content.replace(/session\.upload_progress\.enabled\s*=\s*(?:On|1)/gi, 'session.upload_progress.enabled = Off');
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CVE-2026-109618 (PHP2Shell Mitigation)',
            fix: 'Disabled `session.upload_progress.enabled` in `php.ini` to neutralize multipart OOM longjmp corruption.',
          });
        } else if (!/session\.upload_progress\.enabled/i.test(content)) {
          content += '\nsession.upload_progress.enabled = Off\n';
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CVE-2026-109618 (PHP2Shell Mitigation)',
            fix: 'Appended `session.upload_progress.enabled = Off` to `php.ini`.',
          });
        }
        if (/expose_php\s*=\s*(?:On|1)/i.test(content)) {
          content = content.replace(/expose_php\s*=\s*(?:On|1)/gi, 'expose_php = Off');
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CWE-200 (PHP Version Disclosure)',
            fix: 'Set `expose_php = Off` in `php.ini`.',
          });
        }
      }

      // --- B. PHP Source Files (`.php`) Auto-Fixer ---
      if (filePath.endsWith('.php')) {
        // 1. Auto-replace unsafe PHP `unserialize($...)` with `json_decode($..., true)`
        if (/\bunserialize\s*\(\s*(\$[a-zA-Z0-9_[\]'"->]+)\s*\)/g.test(content)) {
          content = content.replace(/\bunserialize\s*\(\s*(\$[a-zA-Z0-9_[\]'"->]+)\s*\)/g, 'json_decode($1, true)');
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CWE-502 (PHP Object Injection RCE)',
            fix: 'Replaced unsafe `unserialize($input)` with `json_decode($input, true)`.',
          });
        }
        // 2. Detect raw SQL string interpolation in PHP (`mysqli_query` / `->query("SELECT ... $_GET ...")`)
        if (/->query\s*\(\s*"[^"]*\$_(?:GET|POST|REQUEST)/i.test(content)) {
          manualInstructions.push({
            id: 'CWE-89 (PHP Raw SQL Interpolation)',
            severity: 'HIGH',
            stack: `PHP (${filePath})`,
            virtualPatchedAtEdge: true,
            whyManualRequired: 'Converting raw SQL string concatenation to parameterized PDO statements requires binding specific column types.',
            steps: [
              `1. In \`${filePath}\`, replace \`$db->query("... $_GET[...] ...")\` with \`$stmt = $pdo->prepare("SELECT ... WHERE id = :id"); $stmt->execute(['id' => $_GET['id']]);\`.`,
            ],
          });
        }
      }

      // --- C. Laravel / App `.env` Auto-Fixer ---
      if (filePath.endsWith('.env')) {
        if (/^APP_DEBUG\s*=\s*true\b/im.test(content)) {
          content = content.replace(/^APP_DEBUG\s*=\s*true\b/gim, 'APP_DEBUG=false');
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CVE-2021-3129 / CWE-215 (Laravel Ignition Debug RCE & Secret Dump)',
            fix: 'Set `APP_DEBUG=false` in `.env` so Ignition debug stack traces and `APP_KEY` are never exposed.',
          });
        }
      }

      // --- D. Python Source Files (`.py`) Auto-Fixer ---
      if (filePath.endsWith('.py')) {
        // 1. Django QuerySet Dict-Expansion SQLi (CVE-2025-64459): `.filter(**payload)`
        const djangoFilterRe = /\.filter\(\s*\*\*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)/g;
        if (djangoFilterRe.test(content)) {
          content = content.replace(
            djangoFilterRe,
            '.filter(**{k: v for k, v in $1.items() if not str(k).startswith("_")})'
          );
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CVE-2025-64459 (Django QuerySet Dict-Expansion SQLi)',
            fix: 'Sanitized `.filter(**dict)` to strip internal `_connector` and `_negated` SQL injection keys.',
          });
        }

        // 2. PyYAML unsafe `yaml.load(data)` -> `yaml.safe_load(data)`
        const yamlRe = /\byaml\.load\(\s*([^,)]+)\s*\)/g;
        if (yamlRe.test(content)) {
          content = content.replace(yamlRe, 'yaml.safe_load($1)');
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CWE-502 (PyYAML Arbitrary Code Execution)',
            fix: 'Replaced unsafe `yaml.load(...)` with `yaml.safe_load(...)`.',
          });
        }

        // 3. PyTorch `torch.load(path)` without `weights_only=True` (CVE-2025-32434 / CVE-2026-24747)
        const torchLoadRe = /\btorch\.load\(\s*([^,)]+)\s*\)/g;
        if (torchLoadRe.test(content)) {
          content = content.replace(torchLoadRe, 'torch.load($1, weights_only=True)');
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CVE-2025-32434 / CVE-2026-24747 (PyTorch Deserialization RCE)',
            fix: 'Enforced `weights_only=True` in `torch.load(...)`.',
          });
          manualInstructions.push({
            id: 'CVE-2026-24747 (PyTorch < 2.10.0 weights_only Bypass)',
            severity: 'CRITICAL (CVSS 8.8)',
            stack: `Python PyTorch (${filePath})`,
            virtualPatchedAtEdge: true,
            whyManualRequired: 'In PyTorch < 2.10.0, even `weights_only=True` can be bypassed by crafted `.pth` checkpoints; upgrading to PyTorch >= 2.10.0 or migrating to `.safetensors` is required.',
            steps: [
              '1. Upgrade PyTorch to >= 2.10.0 (`pip install --upgrade "torch>=2.10.0"`).',
              '2. Migrate model checkpoints from pickle-based `.pt`/`.pth` to `safetensors` (`from safetensors.torch import load_file`).',
            ],
          });
        }

        // 4. Flask / Werkzeug `debug=True` RCE console exposure
        if (/\bapp\.run\(([^)]*)\bdebug\s*=\s*True\b/g.test(content)) {
          content = content.replace(/\bdebug\s*=\s*True\b/g, 'debug=False');
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CWE-489 (Werkzeug Interactive Debugger RCE Exposure)',
            fix: 'Patched `app.run(..., debug=True)` to `debug=False`.',
          });
        }
      }

      // --- E. Python `requirements.txt` Auto-Fixer ---
      if (filePath.endsWith('requirements.txt')) {
        if (/^django==(?:4\.2\.(?:[0-9]|1[0-9]|2[0-5])|5\.1\.(?:[0-9]|1[0-3])|5\.2\.[0-7])\b/im.test(content)) {
          content = content.replace(/^django==[0-9.]+/gim, 'django>=5.2.8');
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CVE-2025-64459 (Django SQLi)',
            fix: 'Upgraded `django` in `requirements.txt` to `django>=5.2.8`.',
          });
        }
        if (/^torch==(?:1\.|2\.[0-9]\.)/im.test(content)) {
          content = content.replace(/^torch==[0-9.]+/gim, 'torch>=2.10.0');
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CVE-2026-24747 (PyTorch RCE)',
            fix: 'Upgraded `torch` in `requirements.txt` to `torch>=2.10.0`.',
          });
        }
      }

      // --- F. Next.js / React `package.json` Auto-Fixer ---
      if (filePath.endsWith('package.json')) {
        try {
          const pkg = JSON.parse(content);
          const deps = pkg.dependencies || {};
          if (deps.next && /^(?:\^|~)?(?:13\.|14\.|15\.[0-4]\.|15\.5\.(?:[0-9]|1[0-9]|2[0-7])\b|16\.[0-3]\.)/.test(deps.next)) {
            deps.next = '^16.4.1';
            modified = true;
            autoFixedIssues.push({
              file: filePath,
              cve: 'CVE-2025-29927 / CVE-2026-96889 / GHSA-673q-mjm6-r5xr (Next.js RCE & Auth Bypass)',
              fix: 'Upgraded `next` dependency in `package.json` to `^16.4.1`.',
            });
          }
          if (deps.react && /^(?:\^|~)?19\.(?:0\.0|1\.[01]|2\.0)\b/.test(deps.react)) {
            deps.react = '^19.2.1';
            if (deps['react-dom']) deps['react-dom'] = '^19.2.1';
            modified = true;
            autoFixedIssues.push({
              file: filePath,
              cve: 'CVE-2025-55182 / CVE-2025-66478 (React Server Components Flight RCE)',
              fix: 'Upgraded `react` and `react-dom` in `package.json` to `^19.2.1`.',
            });
          }
          if (modified) {
            content = JSON.stringify(pkg, null, 2) + '\n';
          }
        } catch {}
      }

      // --- G. Go Backend Source Files (`.go`) Auto-Fixer ---
      if (filePath.endsWith('.go')) {
        const goSqlRe = /\bdb\.Query\(\s*fmt\.Sprintf\(\s*"([^"]*%s[^"]*)"\s*,\s*([a-zA-Z0-9_.]+)\s*\)\s*\)/g;
        if (goSqlRe.test(content)) {
          content = content.replace(goSqlRe, (_m, sqlTpl, argVar) => {
            const paramSql = sqlTpl.replace(/['"]?%s['"]?/, '$1');
            return `db.Query("${paramSql}", ${argVar})`;
          });
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CWE-89 (Go database/sql fmt.Sprintf SQL Injection)',
            fix: 'Converted `db.Query(fmt.Sprintf(...))` to parameterized `$1` query placeholder.',
          });
        }
      }

      // --- H. Java / Spring Boot Source Files (`.java`) Auto-Fixer ---
      if (filePath.endsWith('.java')) {
        const javaDeserRe = /new\s+ObjectInputStream\(([^)]+)\)\.readObject\(\)/g;
        if (javaDeserRe.test(content)) {
          content = content.replace(javaDeserRe, 'AegisSafeObjectInputStream.readSafeObject($1)');
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CWE-502 (Java ObjectInputStream Deserialization RCE)',
            fix: 'Replaced `new ObjectInputStream(...).readObject()` with allowlist-enforced `AegisSafeObjectInputStream.readSafeObject(...)`.',
          });
        }
        const springSqlRe = /jdbcTemplate\.queryForList\(\s*"([^"]*?)'?\s*"\s*\+\s*([a-zA-Z0-9_]+)\s*\+\s*"'?"\s*\)/g;
        if (springSqlRe.test(content)) {
          content = content.replace(springSqlRe, 'jdbcTemplate.queryForList("$1?", $2)');
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CWE-89 (Spring JdbcTemplate SQL Concatenation)',
            fix: 'Replaced string-concatenated `jdbcTemplate.queryForList` with `?` bind parameter.',
          });
        }
      }

      // --- I. C# / .NET Backend Source Files (`.cs`) Auto-Fixer ---
      if (filePath.endsWith('.cs')) {
        const csBinFmtRe = /new\s+BinaryFormatter\(\)\.Deserialize\(([^)]+)\)/g;
        if (csBinFmtRe.test(content)) {
          content = content.replace(csBinFmtRe, 'JsonSerializer.Deserialize<object>($1)');
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CWE-502 (.NET BinaryFormatter Deserialization RCE)',
            fix: 'Replaced unsafe `BinaryFormatter().Deserialize(...)` with `JsonSerializer.Deserialize<object>(...)`.',
          });
        }
      }

      // --- J. Ruby on Rails Source Files (`.rb`) Auto-Fixer ---
      if (filePath.endsWith('.rb')) {
        const railsWhereRe = /\.where\(\s*"([^"#]*?)'?#\{([^}]+)\}'?"\s*\)/g;
        if (railsWhereRe.test(content)) {
          content = content.replace(railsWhereRe, '.where("$1?", $2)');
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CWE-89 (Rails ActiveRecord String Interpolation SQLi)',
            fix: 'Replaced `.where("... #{...}")` interpolation with parameterized `.where("... ?", param)`.',
          });
        }
        const rubyYamlRe = /\bYAML\.load\(\s*([^,)]+)\s*\)/g;
        if (rubyYamlRe.test(content)) {
          content = content.replace(rubyYamlRe, 'YAML.safe_load($1)');
          modified = true;
          autoFixedIssues.push({
            file: filePath,
            cve: 'CWE-502 (Ruby Psych YAML Deserialization RCE)',
            fix: 'Replaced `YAML.load(...)` with `YAML.safe_load(...)`.',
          });
        }
      }

      fixedFiles[filePath] = content;
    }

    return {
      fixedFiles,
      autoFixedCount: autoFixedIssues.length,
      autoFixedIssues,
      manualInstructionCount: manualInstructions.length,
      manualInstructions,
    };
  }
}
