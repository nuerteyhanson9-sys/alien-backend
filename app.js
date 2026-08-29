import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import xss from "xss";
import validator from "validator";
import { Resend } from "resend";

const app = express();

app.set("trust proxy", 1);

// ------------------------------------------------------------
// 5. CORS — restrict to your frontend origin(s) only.
// ------------------------------------------------------------
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

const corsOptions = {
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST"],
};

app.use(cors(corsOptions));

app.use(express.json({ limit: "10kb" }));
app.disable("x-powered-by");

// ------------------------------------------------------------
// Field length limits
// ------------------------------------------------------------
const LIMITS = {
  name: { min: 2, max: 100 },
  email: { max: 254 },
  service: { max: 100 },
  message: { min: 10, max: 2000 },
};

// ------------------------------------------------------------
// 3. XSS prevention — escape every user-supplied value before it
//    touches the HTML email template.
// ------------------------------------------------------------
const escapeHtml = (value) =>
  xss(value, {
    whiteList: {},
    stripIgnoreTag: true,
    stripIgnoreTagBody: ["script"],
  });

// ------------------------------------------------------------
// 2. RESEND CLIENT — created lazily on first use and reused.
//    (REST API, no SMTP connection to maintain. Free tier:
//    100 emails/day, 3000/month.) Constructing is deferred so the
//    app still boots if the API key env var is temporarily missing.
// ------------------------------------------------------------
let resendClient = null;
const getResend = () => {
  if (!resendClient) resendClient = new Resend(process.env.RESEND_API_KEY);
  return resendClient;
};
// Inbox that receives all form messages (use onboarding@resend.dev
// to contact yourself while setting up, or your own domain sender).
const TO_ADDR = process.env.EMAIL_USER; // recipient
const FROM_ADDR = process.env.FROM_EMAIL || "onboarding@resend.dev";

// ------------------------------------------------------------
// 7. Timeout guard — races Resend against a hard deadline so the
//    response always arrives.
// ------------------------------------------------------------
const SEND_TIMEOUT_MS = 9_000;

const withTimeout = (promise, ms) =>
  Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Email send timed out")), ms)
    ),
  ]);

// ------------------------------------------------------------
// 1. Server-side validation — email format + length checks.
// ------------------------------------------------------------
const validateContact = ({ name, email, service, message }) => {
  if (typeof name !== "string" || typeof email !== "string" || typeof message !== "string") {
    return "All fields required";
  }

  const trimmedName = name.trim();
  const trimmedEmail = email.trim();
  const trimmedMessage = message.trim();

  if (trimmedName.length < LIMITS.name.min || trimmedName.length > LIMITS.name.max) {
    return `Name must be between ${LIMITS.name.min} and ${LIMITS.name.max} characters`;
  }
  if (!validator.isEmail(trimmedEmail) || trimmedEmail.length > LIMITS.email.max) {
    return "A valid email is required";
  }
  if (trimmedMessage.length < LIMITS.message.min || trimmedMessage.length > LIMITS.message.max) {
    return `Message must be between ${LIMITS.message.min} and ${LIMITS.message.max} characters`;
  }
  if (service != null && (typeof service !== "string" || service.length > LIMITS.service.max)) {
    return "Invalid service value";
  }
  return null;
};

// ------------------------------------------------------------
// 4. Rate limiting — max 5 submissions per IP per 15 minutes.
// ------------------------------------------------------------
const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({ error: "Too many requests. Please try again later." });
  },
});

app.get("/", (req, res) => {
  const mask = (v) => (v ? v.slice(0, 3) + "…" + v.slice(-3) : null);
  res.json({
    status: "Alien Backend Running 👽",
    diagnostics: {
      allowedOrigins: ALLOWED_ORIGINS,
      resendKeySet: Boolean(process.env.RESEND_API_KEY),
      fromEmail: FROM_ADDR,
      toEmailMasked: mask(TO_ADDR)
    }
  });
});

app.post("/api/contact", contactLimiter, async (req, res) => {
  const { name, email, message, service } = req.body;

  const validationError = validateContact({ name, email, service, message });
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  const clean = {
    name: name.trim(),
    email: email.trim(),
    message: message.trim(),
    service: typeof service === "string" ? service.trim() : "",
  };

  const safe = {
    name: escapeHtml(clean.name),
    email: escapeHtml(clean.email),
    message: escapeHtml(clean.message).replace(/\n/g, "<br/>"),
    service: escapeHtml(clean.service || "General"),
  };

  const subject = `New Portfolio Inquiry: ${clean.service || "General"}`
    .replace(/[\r\n]+/g, " ")
    .slice(0, 200);

  try {
    const { data, error } = await withTimeout(
      getResend().emails.send({
        from: FROM_ADDR,
        to: TO_ADDR,
        replyTo: clean.email,
        subject,
        html: `
          <h2>New Message from Alien Portfolio</h2>
          <p><b>Name:</b> ${safe.name}</p>
          <p><b>Email:</b> <a href="mailto:${safe.email}">${safe.email}</a></p>
          <p><b>Service:</b> ${safe.service}</p>
          <p><b>Message:</b> ${safe.message}</p>
        `,
      }),
      SEND_TIMEOUT_MS
    );

    // Resend returns { error } instead of throwing on API failures.
    if (error) throw new Error(error.message || "Resend refused to send");

    return res.json({ success: true, message: "Message sent!" });
  } catch (err) {
    if (err?.message === "Email send timed out") {
      console.error("[contact] send timed out after 9s");
    } else {
      console.error("[contact] send failed:", err.message);
    }

    const timedOut = err?.message === "Email send timed out";
    return res.status(500).json({
      error: timedOut
        ? "The email service is slow right now. Please try again shortly."
        : "Something went wrong. Please try again later.",
    });
  }
});

// Shared app export: used by local `server.js` AND Vercel serverless.
export default app;