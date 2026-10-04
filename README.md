# Fresh Press — Secure Login Form

A small login page inspired by [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/).
It demonstrates how a login flow can defend against **SQL Injection**, **Cross-Site Scripting (XSS)**, 
and **authentication bypass / brute force** using layered validation and secure password handling.

## What it does

- A clean email + password login form (`index.html`).
- **Client-side validation** (`script.js`): blocks empty submissions, requires an
  `@` in the email, and requires a password of at least 8 characters. All feedback
  is written with `textContent` (never `innerHTML`), so typed `<script>` tags are
  shown as literal text and never execute.
- **Server-side validation** (`server.js`): the Express backend re-checks every
  field, because any client-side check can be bypassed with devtools or `curl`.
- **Secure password handling:** passwords are verified against a **bcrypt** hash
  (cost factor 12, salted). Plaintext passwords are never stored.
- **Injection-safe lookups:** users are fetched by object key, not by a
  string-built SQL query, so classic payloads like `' OR '1'='1` match nothing.
- **Hardening:** `helmet` security headers (incl. a Content-Security-Policy),
  rate limiting (5 attempts / 15 min / IP), generic auth errors, and a constant
  bcrypt compare to resist user-enumeration timing attacks.

## Project structure

```
index.html     login page markup + styles
script.js      client-side validation (XSS-safe DOM updates)
server.js      Express + bcrypt backend with server-side validation
package.json    dependencies and start script
```

## Requirements

- [Node.js](https://nodejs.org/) 16 or newer (includes npm)

## How to run

```bash
# 1. Install dependencies
npm install

# 2. Start the server
npm start

# 3. Open the app
#    http://localhost:3000
```

### Demo account

| Email                     | Password         |
| ------------------------- | ---------------- |
| `admin@freshpress.test`   | `JuicyGr@pe2024` |

> The demo user's bcrypt hash is generated fresh at server startup, so the
> credentials above always work without committing any secret to the repo.

## Testing the defenses

With the server running, try these from a terminal:

```bash
# Valid login -> success
curl -X POST http://localhost:3000/api/login -H "Content-Type: application/json" \
  -d '{"email":"admin@freshpress.test","password":"JuicyGr@pe2024"}'

# SQL-injection style string -> treated as a literal, no bypass
curl -X POST http://localhost:3000/api/login -H "Content-Type: application/json" \
  -d "{\"email\":\"' OR 1=1 --\",\"password\":\"xxxxxxxx\"}"

# XSS payload as email -> rejected by validation, never executed
curl -X POST http://localhost:3000/api/login -H "Content-Type: application/json" \
  -d '{"email":"<script>alert(1)</script>","password":"xxxxxxxx"}'
```

## License

MIT — for educational use.
