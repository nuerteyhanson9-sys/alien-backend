import express from "express";
import cors from "cors";
import nodemailer from "nodemailer";
import rateLimit from "express-rate-limit";
import xss from "xss";
import validator from "validator";
import dotenv from "dotenv";

dotenv.config();

const app = express();

// Render fronts all requests through a proxy, so trust it for real IPs.
app.set("trust proxy", 1);

// ------------------------------------------------------------
// 5. CORS — restrict to your frontend origin(s) only.
//    List them comma-separated in ALLOWED_ORIGINS.
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

// Cap request body size and hide the X-Powered-By header.
app.use(express.json({ limit: "10kb" }));
app.disable("x-powered-by");

// ------------------------------------------------------------
// 1a. Field length limits
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
// 2. TRANSPORTER — built ONCE at startup and reused.
//    SMTP timeouts (issue 7) set here so a dead/unreachable
//    server fails fast instead of hanging the request.
// ------------------------------------------------------------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  connectionTimeout: 5000,
  greetingTimeout: 5000,
  socketTimeout: 10000,
});

// ------------------------------------------------------------
// 7. Timeout guard — races sendMail against a hard deadline so
//    the HTTP request always responds.
// ------------------------------------------------------------
const SEND_TIMEOUT_MS = 10_000;

const withTimeout = (promise, ms) =>
  Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Email send timed out")), ms)
    ),
  ]);

// ------------------------------------------------------------
// 1b. Server-side validation — email format + length checks
//     before anything is sent.
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

// Health check
app.get("/", (req, res) => {
  res.send("Alien Backend Running 👽");
});

// Contact form endpoint
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
    await withTimeout(
      transporter.sendMail({
        from: `"${clean.name}" <${clean.email}>`,
        replyTo: clean.email,
        to: process.env.EMAIL_USER,
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

    return res.json({ success: true, message: "Message sent!" });
  } catch (err) {
    if (err?.message === "Email send timed out") {
      console.error("[contact] send timed out after 10s");
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Backend running on ${PORT}`));