/*
 * Fresh Press — login backend
 *
 * Demonstrates the server-side half of the defense:
 *   1. Server-side validation (never trust the client)
 *   2. Secure password handling with bcrypt (salted, slow hashing)
 *   3. Injection-safe data access (lookup by key, not string-built SQL)
 *   4. Generic auth errors + rate limiting to blunt enumeration / brute force
 *   5. Security headers via helmet
 *
 * Run:  npm install  &&  npm start   ->  http://localhost:3000
 */

const path = require("path");
const express = require("express");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

// --- Security headers (CSP, X-Content-Type-Options, etc.) -------------------
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        scriptSrc: ["'self'"],
        connectSrc: ["'self'"],
      },
    },
  })
);

app.use(express.json({ limit: "10kb" })); // cap body size
app.use(express.static(path.join(__dirname)));

// --- Demo "database" --------------------------------------------------------
// In a real app this is a table queried with PARAMETERIZED statements, e.g.
//   db.query("SELECT * FROM users WHERE email = $1", [email])
// Here we look users up by object key, so a crafted string like
//   admin'-- or  ' OR '1'='1
// is just a key that doesn't exist. There is no query string to inject into.
//
// Passwords are stored ONLY as bcrypt hashes (cost 12), never in plaintext.
// Hash below is for the password:  JuicyGr@pe2024
const USERS = {
  "admin@freshpress.test": {
    name: "Admin",
    passwordHash: "$2b$12$Qw8Qn2b3mC0m8q0mJHv0mO2e1nq8kz3o3f1lJkqkqkqkqkqkqkqkq", // replaced at boot
  },
};

// Build a real hash at startup so the demo is self-contained and correct.
(async () => {
  USERS["admin@freshpress.test"].passwordHash = await bcrypt.hash("JuicyGr@pe2024", 12);
  console.log("Demo user ready: admin@freshpress.test / JuicyGr@pe2024");
})();

// --- Rate limiting: 5 login attempts per IP per 15 min ----------------------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many attempts. Please wait and try again." },
});

// --- Server-side validation (mirrors the client, but authoritative) ---------
function validate(email, password) {
  if (typeof email !== "string" || typeof password !== "string") {
    return "Invalid request format.";
  }
  const trimmed = email.trim();
  if (trimmed === "" || password === "") return "Email and password are required.";
  if (!trimmed.includes("@")) return "Email must contain an \u201c@\u201d.";
  if (trimmed.length > 254) return "Email is too long.";
  if (password.length < 8) return "Password must be at least 8 characters.";
  if (password.length > 200) return "Password is too long.";
  return null; // valid
}

// --- Login route ------------------------------------------------------------
app.post("/api/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body || {};

  const validationError = validate(email, password);
  if (validationError) {
    return res.status(400).json({ message: validationError });
  }

  const user = USERS[email.trim().toLowerCase()];

  // Always run a bcrypt compare, even when the user is missing, so the
  // response time doesn't leak which emails exist (timing-attack resistant).
  const hash = user ? user.passwordHash : "$2b$12$" + "x".repeat(53);
  const match = await bcrypt.compare(password, hash);

  if (!user || !match) {
    // Generic message: don't reveal whether it was the email or the password.
    return res.status(401).json({ message: "Invalid email or password." });
  }

  return res.json({ message: `Signed in. Welcome back, ${user.name}!` });
});

app.listen(PORT, () => {
  console.log(`Fresh Press running at http://localhost:${PORT}`);
});
