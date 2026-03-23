![PicoClaw](https://raw.githubusercontent.com/sipeed/picoclaw/main/assets/logo.jpg)

# PicoClaw | Lightweight AI Agent Backend | Render Free-Tier Ready

**PicoClaw** is a lightweight, open-source AI agent control panel. Think of it as a simpler, more minimal alternative to OpenClaw. You host it yourself, connect a model provider, plug in a messaging channel, and your AI agent is live.

## 🚀 Advanced Deployment Version

This specialized version of PicoClaw has been heavily optimized and upgraded for **zero-cost hosting on Render's Free Tier** and features a premium modern dashboard.

### ✨ Key Features
* **Zero-Cost Optimized:** Built specifically to survive Render's 512MB RAM cap and ephemeral filesystem using memory optimizations and environment-variable config auto-loading.
* **Anti-Sleep Keep-Alive:** Includes a background ping mechanism to prevent Render from spinning down the instance after 15 minutes of inactivity.
* **Glassmorphism Dashboard:** A sleek, modern, dark-mode UI with live system metrics and provider bridging status.
* **Enterprise Security:** Replaces insecure Basic Auth with a custom JWT session authentication system (HttpOnly cookies).
* **Real-time SSE Logs:** Streams gateway terminal logs to your browser instantly over Server-Sent Events (SSE) with zero polling overhead.
* **Live API Health Checks:** Test your provider API keys (OpenAI, Anthropic, Gemini, Groq) directly from the UI to ensure they are valid before running the agent.

---

## 🛠️ Setup Guide (Render Free Tier)

**1️⃣ Fork and Deploy**
Fork this repository and connect it to a new Render Web Service.

**2️⃣ Configure Environment Variables**
Because Render's free tier uses an ephemeral filesystem, your API keys will be wiped on restart if you don't save them as environment variables.
In your Render dashboard, set the following:
* `ADMIN_PASSWORD` - Your secure login password
* `JWT_SECRET` - A long random string for securing your sessions
* `OPENAI_API_KEY` (or `ANTHROPIC_API_KEY`, `GROQ_API_KEY`, etc.)
* `TELEGRAM_BOT_TOKEN` (or other channel tokens)

**3️⃣ Login to the Dashboard**
Once deployed, visit your Render URL and log in using the `ADMIN_PASSWORD` you provided to view the live dashboard and manage your gateway.

---

## 💻 Tech Stack
* **Backend:** Python, Starlette, Uvicorn, PyJWT, HTTPX
* **Frontend:** HTML5, TailwindCSS, Alpine.js (Zero Build Step)
* **Agent Engine:** PicoClaw Go Binary
* **Infrastructure:** Docker (Alpine Linux, non-root user)

---

## 💰 Pricing & Infrastructure

### Render Hosting Cost
* **Free tier:** $0/month. This template is optimized to never sleep and stay within the 512MB RAM limit.
* Note: You are still responsible for paying your AI Model Provider (e.g., OpenAI) for the API calls the agent generates.

### Memory Optimizations
This build includes aggressive garbage collection, reduced log buffering, and stripped Docker base layers to ensure it runs comfortably under 100MB of RAM, leaving plenty of room for the agent process.

---

## ⚖️ PicoClaw vs OpenClaw

**PicoClaw**
* Extremely lightweight backend
* Minimal setup
* Self-hostable for free
* Focuses purely on routing models to channels

**OpenClaw**
* Broader feature set
* Heavy resource usage
* Expensive to host standalone

If you want a controllable, single-agent backend that's free to host, PicoClaw makes more sense.

---

## ❓ FAQs

**Does PicoClaw have a web chat UI?**
No. You interact with the agent through connected external channels like Discord or Telegram. The web UI is strictly a beautiful control panel for managing the server.

**How does the keep-alive work?**
It automatically detects its own public `RENDER_EXTERNAL_URL` and sends a lightweight HTTP ping to its own `/health` endpoint every 14 minutes, completely preventing the "cold start" spin-down.
