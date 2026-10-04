/*
 * OWASP Juice Shop login mimic — client-side validation
 *
 * Security notes:
 *  - All feedback is written with textContent, NEVER innerHTML, so any script
 *    tags a user types are shown as literal text and cannot execute (DOM-XSS safe).
 *  - Client validation is a UX convenience only. The server re-validates every
 *    field, because anything in the browser can be bypassed with devtools or curl.
 */

const form       = document.getElementById("loginForm");
const emailEl     = document.getElementById("email");
const passEl      = document.getElementById("password");
const emailErr    = document.getElementById("emailErr");
const passErr     = document.getElementById("passErr");
const statusEl    = document.getElementById("status");
const submitBtn   = document.getElementById("submitBtn");
const loginLabel  = document.getElementById("loginLabel");

// Toggle the invalid state + inline message for one field.
function setError(inputEl, errEl, message) {
  if (message) {
    inputEl.setAttribute("aria-invalid", "true");
    errEl.textContent = message;          // textContent => no HTML execution
  } else {
    inputEl.removeAttribute("aria-invalid");
    errEl.textContent = "";
  }
}

// Silent validity check (no messages) — drives the Log in button state.
function isValid() {
  const email = emailEl.value.trim();
  const pass  = passEl.value;
  return email !== "" && email.includes("@") && pass.length >= 8;
}

// Enable/disable the pill button like the real Juice Shop does.
function updateButton() {
  if (isValid()) {
    submitBtn.classList.add("ready");
    submitBtn.setAttribute("aria-disabled", "false");
  } else {
    submitBtn.classList.remove("ready");
    submitBtn.setAttribute("aria-disabled", "true");
  }
}

// Full validation WITH messages — used on submit.
function validate() {
  const email = emailEl.value.trim();
  const pass  = passEl.value;              // do NOT trim passwords
  let ok = true;

  if (email === "") {
    setError(emailEl, emailErr, "Email is required."); ok = false;
  } else if (!email.includes("@")) {
    setError(emailEl, emailErr, "Email must contain an \u201c@\u201d."); ok = false;
  } else {
    setError(emailEl, emailErr, "");
  }

  if (pass === "") {
    setError(passEl, passErr, "Password is required."); ok = false;
  } else if (pass.length < 8) {
    setError(passEl, passErr, "Password must be at least 8 characters."); ok = false;
  } else {
    setError(passEl, passErr, "");
  }

  return ok;
}

function showStatus(kind, text) {
  statusEl.className = "status " + (kind === "ok" ? "ok" : "bad");
  statusEl.textContent = text;             // server message rendered as TEXT only
}

// Password visibility toggle (the eye icon in the password field).
const togglePw = document.getElementById("togglePw");
if (togglePw) {
  togglePw.addEventListener("click", () => {
    const show = passEl.type === "password";
    passEl.type = show ? "text" : "password";
    togglePw.setAttribute("aria-label", show ? "Hide password" : "Show password");
  });
}

// "Not yet a customer?" — placeholder (no registration page in this demo).
const signup = document.getElementById("signup");
if (signup) {
  signup.addEventListener("click", () =>
    showStatus("bad", "Registration isn't part of this demo."));
}

// Update button readiness as the user types.
emailEl.addEventListener("input", updateButton);
passEl.addEventListener("input",  updateButton);
updateButton(); // initial state: disabled

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  statusEl.className = "status";
  statusEl.textContent = "";

  if (!validate()) return;                 // blocks empty / malformed submissions

  submitBtn.classList.remove("ready");
  submitBtn.setAttribute("aria-disabled", "true");
  loginLabel.textContent = "Logging in\u2026";

  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: emailEl.value.trim(),
        password: passEl.value,
      }),
    });
    const data = await res.json();
    showStatus(res.ok ? "ok" : "bad", data.message || "Unexpected response.");
  } catch (err) {
    showStatus("bad", "Could not reach the server. Is it running?");
  } finally {
    loginLabel.textContent = "Log in";
    updateButton();
  }
});