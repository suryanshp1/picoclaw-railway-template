import asyncio
import base64
import json
import os
import yaml
import re
import secrets
import signal
import time
from collections import deque
import gc
import httpx
import jwt
import datetime
from contextlib import asynccontextmanager
from pathlib import Path

from starlette.applications import Starlette
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    SimpleUser,
)
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, StreamingResponse, RedirectResponse
from starlette.routing import Route
from starlette.templating import Jinja2Templates

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
SECRET_FIELDS = {
    "api_key", "token", "app_secret", "encrypt_key",
    "verification_token", "bot_token", "app_token",
    "channel_secret", "channel_access_token", "client_secret",
}

def _get_writable_config_dir():
    paths = []
    _env_home = os.environ.get("PICOCLAW_HOME")
    if _env_home:
        paths.append(Path(_env_home).expanduser())
    try:
        paths.append(Path.home() / ".picoclaw")
    except Exception:
        pass
    paths.append(Path("/data/.picoclaw"))
    paths.append(Path("/tmp/.picoclaw"))
    
    for p in paths:
        if p.is_absolute():
            try:
                p.mkdir(parents=True, exist_ok=True)
                test_file = p / ".write_test"
                test_file.touch()
                test_file.unlink()
                return p
            except Exception:
                pass
    return Path("/tmp/.picoclaw")

CONFIG_DIR = _get_writable_config_dir()
os.environ["PICOCLAW_HOME"] = str(CONFIG_DIR)
CONFIG_PATH = CONFIG_DIR / "config.json"
_LOCAL_CONFIG = None  # In-memory config fallback

BOOT_TIME = time.time()

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = secrets.token_urlsafe(16)
    print(f"Generated admin password: {ADMIN_PASSWORD}")

JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))

def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30),
        "iat": datetime.datetime.now(datetime.timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def require_auth(request: Request):
    token = request.cookies.get("auth_token")
    if not token:
        # For API routes return 401, for HTML routes return redirect
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        return RedirectResponse(url="/login")
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return None
    except jwt.InvalidTokenError:
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": "Invalid token"}, status_code=401)
        return RedirectResponse(url="/login")

def load_config():
    global _LOCAL_CONFIG
    if not CONFIG_PATH.exists():
        return _LOCAL_CONFIG or default_config()
    try:
        return json.loads(CONFIG_PATH.read_text())
    except Exception:
        return _LOCAL_CONFIG or default_config()


# --- Known provider api_base values ------------------------------------------------
# These are REQUIRED for the Go engine to know the correct endpoint.
# Without these, the engine either fails to build the Bearer auth header or
# routes to the wrong URL (causing the 401 "No cookie auth credentials found" error).
PROVIDER_API_BASES = {
    "groq":       "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "deepseek":   "https://api.deepseek.com/v1",
    "moonshot":   "https://api.moonshot.cn/v1",
}

# Protocol prefixes the Go engine uses — the user MUST NOT include these in
# the model field because the engine adds them itself during the V0→V1 migration.
PROTOCOL_PREFIXES = {
    "groq", "openai", "anthropic", "openrouter", "gemini",
    "deepseek", "moonshot", "zhipu", "vllm", "nvidia",
}


def sanitize_model_string(model: str) -> str:
    """Remove double protocol prefixes like 'groq/openai/...' -> 'openai/...'
    or 'groq/groq/...' -> 'groq/...'. The Go engine adds the prefix itself."""
    parts = model.split("/", 1)
    if len(parts) == 2:
        prefix, rest = parts
        # If prefix is a known Go protocol AND rest also starts with a known protocol,
        # it is double-prefixed — strip the outer one.
        rest_prefix = rest.split("/")[0]
        if prefix.lower() in PROTOCOL_PREFIXES and rest_prefix.lower() in PROTOCOL_PREFIXES:
            return rest  # e.g. 'groq/openai/gpt-oss-20b' -> 'openai/gpt-oss-20b'
    return model


def enforce_provider_api_bases(data: dict) -> dict:
    """Ensure providers with known api_base always have it set in config.
    Without api_base, the Go engine cannot construct the correct HTTP endpoint
    and Groq/OpenRouter returns 401 'No cookie auth credentials found'."""
    providers = data.get("providers", {})
    for p_name, base_url in PROVIDER_API_BASES.items():
        if p_name in providers and isinstance(providers[p_name], dict):
            if not providers[p_name].get("api_base"):
                providers[p_name]["api_base"] = base_url
    return data


def write_security_yml(data: dict):
    """Write .security.yml for the Go Engine's V1 security schema.
    The Go engine reads credentials ONLY from this file; secrets in config.json
    are silently ignored after V0->V1 migration."""
    try:
        sec_path = CONFIG_DIR / ".security.yml"
        sec_data: dict = {"channels": {}, "model_list": {}}
        
        # 1. Map channel secrets
        c = data.get("channels", {})
        if c.get("telegram", {}).get("token"):
            sec_data["channels"]["telegram"] = {"token": c["telegram"]["token"]}
        if c.get("discord", {}).get("token"):
            sec_data["channels"]["discord"] = {"token": c["discord"]["token"]}
        if c.get("weixin", {}).get("token"):
            sec_data["channels"]["weixin"] = {"token": c["weixin"]["token"]}
        if c.get("qq", {}).get("app_secret"):
            sec_data["channels"]["qq"] = {"app_secret": c["qq"]["app_secret"]}
        if c.get("dingtalk", {}).get("client_secret"):
            sec_data["channels"]["dingtalk"] = {"client_secret": c["dingtalk"]["client_secret"]}
        if c.get("slack", {}):
            s = {k: c["slack"][k] for k in ("bot_token", "app_token") if c["slack"].get(k)}
            if s:
                sec_data["channels"]["slack"] = s
        if c.get("feishu", {}):
            f = {k: c["feishu"][k] for k in ("app_secret", "encrypt_key", "verification_token") if c["feishu"].get(k)}
            if f:
                sec_data["channels"]["feishu"] = f
 
        # 2. Map provider API keys → model_list
        # The Go V0 migration creates a model entry named after each provider;
        # the security file must use the SAME key to match.
        for p_name, p_cfg in data.get("providers", {}).items():
            key = p_cfg.get("api_key") if isinstance(p_cfg, dict) else None
            if key:
                sec_data["model_list"][p_name] = {"api_keys": [key]}
 
        if sec_data["channels"] or sec_data["model_list"]:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(sec_path, "w") as f:
                yaml.dump(sec_data, f, default_flow_style=False)
    except Exception as e:
        print(f"[warn] Could not write .security.yml: {e}")

def save_config(data):
    global _LOCAL_CONFIG
    # Fix 1: sanitize model string (prevent double-prefix like groq/openai/model)
    agents = data.get("agents", {}).get("defaults", {})
    if isinstance(agents.get("model"), str):
        data["agents"]["defaults"]["model"] = sanitize_model_string(agents["model"])
    # Fix 2: ensure api_base is always present for known providers
    data = enforce_provider_api_bases(data)
    _LOCAL_CONFIG = data
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(data, indent=2))
        # Fix 3: always regenerate .security.yml so Go engine can read the secrets
        write_security_yml(data)
    except PermissionError as e:
        print(f"[warn] Ignored config save permission error: {e}. Using in-memory config.")
    except Exception as e:
        print(f"[warn] Config save error: {e}. Using in-memory config.")


def default_config():
    return {
        "agents": {
            "defaults": {
                "workspace": "~/.picoclaw/workspace",
                "restrict_to_workspace": True,
                "provider": "",
                "model": "openai/gpt-4o",
                "max_tokens": 8192,
                "temperature": 0.7,
                "max_tool_iterations": 20,
            }
        },
        "channels": {
            "telegram": {"enabled": False, "token": "", "proxy": "", "allow_from": []},
            "discord": {"enabled": False, "token": "", "allow_from": []},
            "slack": {"enabled": False, "bot_token": "", "app_token": "", "allow_from": []},
            "whatsapp": {"enabled": False, "bridge_url": "ws://localhost:3001", "allow_from": []},
            "feishu": {"enabled": False, "app_id": "", "app_secret": "", "encrypt_key": "", "verification_token": "", "allow_from": []},
            "dingtalk": {"enabled": False, "client_id": "", "client_secret": "", "allow_from": []},
            "qq": {"enabled": False, "app_id": "", "app_secret": "", "allow_from": []},
            "line": {"enabled": False, "channel_secret": "", "channel_access_token": "", "webhook_host": "0.0.0.0", "webhook_port": 18791, "webhook_path": "/webhook/line", "allow_from": []},
            "maixcam": {"enabled": False, "host": "0.0.0.0", "port": 18790, "allow_from": []},
        },
        "providers": {
            "anthropic": {"api_key": ""},
            "openai": {"api_key": "", "api_base": ""},
            "openrouter": {"api_key": "", "api_base": "https://openrouter.ai/api/v1"},
            "deepseek": {"api_key": "", "api_base": "https://api.deepseek.com/v1"},
            "groq": {"api_key": "", "api_base": "https://api.groq.com/openai/v1"},
            "gemini": {"api_key": ""},
            "zhipu": {"api_key": "", "api_base": ""},
            "vllm": {"api_key": "", "api_base": ""},
            "nvidia": {"api_key": "", "api_base": ""},
            "moonshot": {"api_key": "", "api_base": ""},
        },
        "gateway": {"host": "0.0.0.0", "port": 18790},
        "tools": {
            "web": {
                "brave": {"enabled": False, "api_key": "", "max_results": 5},
                "duckduckgo": {"enabled": True, "max_results": 5},
            }
        },
        "heartbeat": {"enabled": True, "interval": 30},
        "devices": {"enabled": False, "monitor_usb": False},
    }


ENV_PROVIDER_MAP = {
    "OPENAI_API_KEY": ("providers", "openai", "api_key"),
    "ANTHROPIC_API_KEY": ("providers", "anthropic", "api_key"),
    "GROQ_API_KEY": ("providers", "groq", "api_key"),
    "GEMINI_API_KEY": ("providers", "gemini", "api_key"),
    "OPENROUTER_API_KEY": ("providers", "openrouter", "api_key"),
    "DEEPSEEK_API_KEY": ("providers", "deepseek", "api_key"),
    "TELEGRAM_BOT_TOKEN": ("channels", "telegram", "token"),
    "DISCORD_BOT_TOKEN": ("channels", "discord", "token"),
    "SLACK_BOT_TOKEN": ("channels", "slack", "bot_token"),
    "SLACK_APP_TOKEN": ("channels", "slack", "app_token"),
}


def init_from_env():
    config = load_config()
    changed = False
    
    for env_key, path in ENV_PROVIDER_MAP.items():
        value = os.environ.get(env_key, "")
        if value:
            section, name, field = path
            
            # For channels, also auto-enable if token provided
            if section == "channels":
                if not config.get(section, {}).get(name, {}).get("enabled"):
                    config.setdefault(section, {}).setdefault(name, {})["enabled"] = True
                    changed = True
                    
            if not config.get(section, {}).get(name, {}).get(field):
                config.setdefault(section, {}).setdefault(name, {})[field] = value
                changed = True

    # Always enforce correct api_bases and write security.yml on every boot
    # even if no env vars were updated (Railway restarts with a clean FS)
    config = enforce_provider_api_bases(config)
    write_security_yml(config)

    if changed:
        save_config(config)


def mask_secrets(data, _path=""):
    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            if k in SECRET_FIELDS and isinstance(v, str) and v:
                result[k] = v[:8] + "***" if len(v) > 8 else "***"
            else:
                result[k] = mask_secrets(v, f"{_path}.{k}")
        return result
    if isinstance(data, list):
        return [mask_secrets(item, _path) for item in data]
    return data


def merge_secrets(new_data, existing_data):
    if isinstance(new_data, dict) and isinstance(existing_data, dict):
        result = {}
        for k, v in new_data.items():
            if k in SECRET_FIELDS and isinstance(v, str) and (v.endswith("***") or v == ""):
                result[k] = existing_data.get(k, "")
            else:
                result[k] = merge_secrets(v, existing_data.get(k, {}))
        return result
    return new_data


class GatewayManager:
    def __init__(self):
        self.process: asyncio.subprocess.Process | None = None
        self.state = "stopped"
        self.logs: deque[str] = deque(maxlen=200) # Reduced for memory optimization
        self.start_time: float | None = None
        self.restart_count = 0
        self._read_tasks: list[asyncio.Task] = []

    async def start(self):
        if self.process and self.process.returncode is None:
            return
        self.state = "starting"
        
        # Ensure the Go binary respects our safe absolute path
        gateway_env = os.environ.copy()
        gateway_env["PICOCLAW_HOME"] = str(CONFIG_DIR)
        
        try:
            self.process = await asyncio.create_subprocess_exec(
                "picoclaw", "gateway", "-E",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=gateway_env
            )
            self.state = "running"
            self.start_time = time.time()
            task = asyncio.create_task(self._read_output())
            self._read_tasks.append(task)
        except Exception as e:
            self.state = "error"
            self.logs.append(f"Failed to start gateway: {e}")

    async def stop(self):
        if not self.process or self.process.returncode is not None:
            self.state = "stopped"
            return
        self.state = "stopping"
        self.process.terminate()
        try:
            await asyncio.wait_for(self.process.wait(), timeout=10)
        except asyncio.TimeoutError:
            self.process.kill()
            await self.process.wait()
        self.state = "stopped"
        self.start_time = None
        gc.collect() # Free up memory immediately

    async def restart(self):
        await self.stop()
        self.restart_count += 1
        await self.start()

    async def _read_output(self):
        try:
            while self.process and self.process.stdout:
                line = await self.process.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                cleaned = ANSI_ESCAPE.sub("", decoded)
                self.logs.append(cleaned)
                # Broadcast log to all SSE listeners
                for q in sse_queues:
                    # Non-blocking put, skip if full to avoid backpressure OOM
                    if not q.full():
                        q.put_nowait(cleaned)
        except asyncio.CancelledError:
            return
        if self.process and self.process.returncode is not None and self.state == "running":
            self.state = "error"
            self.logs.append(f"Gateway exited with code {self.process.returncode}")

    def get_status(self) -> dict:
        pid = None
        if self.process and self.process.returncode is None:
            pid = self.process.pid
        uptime = None
        if self.start_time and self.state == "running":
            uptime = int(time.time() - self.start_time)
        return {
            "state": self.state,
            "pid": pid,
            "uptime": uptime,
            "restart_count": self.restart_count,
        }


gateway = GatewayManager()
config_lock = asyncio.Lock()
sse_queues: list[asyncio.Queue] = []


async def login_page(request: Request):
    token = request.cookies.get("auth_token")
    if token:
        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            return RedirectResponse(url="/")
        except jwt.InvalidTokenError:
            pass
    return templates.TemplateResponse(request, "login.html")


async def api_login(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid request"}, status_code=400)
    
    pwd = body.get("password")
    if pwd == ADMIN_PASSWORD:
        token = create_token("admin")
        res = JSONResponse({"ok": True})
        res.set_cookie("auth_token", token, httponly=True, samesite="lax", max_age=2592000)
        return res
    return JSONResponse({"error": "Invalid password"}, status_code=401)


async def api_logout(request: Request):
    res = JSONResponse({"ok": True})
    res.delete_cookie("auth_token")
    return res


async def homepage(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    return templates.TemplateResponse(request, "index.html")


async def health(request: Request):
    cold = (time.time() - BOOT_TIME) < 30
    return JSONResponse({
        "status": "ok", 
        "gateway": gateway.state, 
        "cold_start": cold,
        "uptime_seconds": int(time.time() - BOOT_TIME)
    })


async def api_config_get(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    config = load_config()
    return JSONResponse(mask_secrets(config))


async def api_config_put(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    try:
        restart = body.pop("_restartGateway", False)

        async with config_lock:
            existing = load_config()
            merged = merge_secrets(body, existing)
            save_config(merged)

        if restart:
            asyncio.create_task(gateway.restart())

        return JSONResponse({"ok": True, "restarting": restart})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def api_status(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err

    config = load_config()

    providers = {}
    for name, prov in config.get("providers", {}).items():
        providers[name] = {"configured": bool(prov.get("api_key"))}

    channels = {}
    for name, chan in config.get("channels", {}).items():
        channels[name] = {"enabled": chan.get("enabled", False)}

    cron_dir = CONFIG_DIR / "cron"
    cron_jobs = []
    if cron_dir.exists():
        for f in cron_dir.glob("*.json"):
            try:
                cron_jobs.append(json.loads(f.read_text()))
            except Exception:
                pass

    return JSONResponse({
        "gateway": gateway.get_status(),
        "providers": providers,
        "channels": channels,
        "cron": {"count": len(cron_jobs), "jobs": cron_jobs},
    })


async def api_logs_stream(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
        
    async def event_generator():
        q = asyncio.Queue(maxsize=100)
        sse_queues.append(q)
        try:
            # Yield history
            for line in gateway.logs:
                yield f"data: {json.dumps({'line': line})}\n\n"
            # Yield new streams
            while True:
                line = await q.get()
                yield f"data: {json.dumps({'line': line})}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            if q in sse_queues:
                sse_queues.remove(q)

    return StreamingResponse(
        event_generator(), 
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


PROVIDER_TEST_URLS = {
    "openai": "https://api.openai.com/v1/models",
    "anthropic": "https://api.anthropic.com/v1/models",
    "groq": "https://api.groq.com/openai/v1/models",
    "gemini": "https://generativelanguage.googleapis.com/v1/models",
}

async def api_provider_health(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
        
    config = load_config()
    results = {}
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        # We only ping active providers or selectively test
        # To avoid rate limits, we'll only test ones that have an API key configured.
        providers_conf = config.get("providers", {})
        
        for name, url in PROVIDER_TEST_URLS.items():
            key = providers_conf.get(name, {}).get("api_key", "")
            if not key:
                results[name] = {"status": "not_configured"}
                continue
                
            try:
                headers = {"Authorization": f"Bearer {key}"}
                if name == "anthropic":
                    headers["x-api-key"] = key
                    # Anthropic doesn't use standard Bearer
                    headers["anthropic-version"] = "2023-06-01"
                    if "Authorization" in headers:
                        del headers["Authorization"]
                        
                resp = await client.get(url, headers=headers)
                results[name] = {
                    "status": "ok" if resp.status_code < 400 else "error", 
                    "code": resp.status_code
                }
            except Exception as e:
                results[name] = {"status": "unreachable", "error": str(e)}
                
    return JSONResponse(results)


async def api_gateway_start(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    asyncio.create_task(gateway.start())
    return JSONResponse({"ok": True})


async def api_gateway_stop(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    asyncio.create_task(gateway.stop())
    return JSONResponse({"ok": True})


async def api_gateway_restart(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    asyncio.create_task(gateway.restart())
    return JSONResponse({"ok": True})


async def auto_start_gateway():
    config = load_config()
    has_key = False
    for prov in config.get("providers", {}).values():
        if isinstance(prov, dict) and prov.get("api_key"):
            has_key = True
            break
    if has_key:
        asyncio.create_task(gateway.start())


SELF_PING_INTERVAL = int(os.environ.get("SELF_PING_INTERVAL", "840"))  # 14 min
RENDER_EXTERNAL_URL = os.environ.get("RENDER_EXTERNAL_URL", "")

async def self_ping_loop():
    if not RENDER_EXTERNAL_URL:
        return
    await asyncio.sleep(60)  # Let it boot first
    async with httpx.AsyncClient(timeout=10) as client:
        while True:
            try:
                await client.get(f"{RENDER_EXTERNAL_URL}/health")
            except Exception:
                pass
            await asyncio.sleep(SELF_PING_INTERVAL)


@asynccontextmanager
async def lifespan(app):
    # startup
    init_from_env()
    await auto_start_gateway()
    ping_task = asyncio.create_task(self_ping_loop())
    yield
    # shutdown
    ping_task.cancel()
    await gateway.stop()


routes = [
    Route("/", homepage),
    Route("/login", login_page),
    Route("/health", health),
    Route("/api/login", api_login, methods=["POST"]),
    Route("/api/logout", api_logout, methods=["POST"]),
    Route("/api/config", api_config_get, methods=["GET"]),
    Route("/api/config", api_config_put, methods=["PUT"]),
    Route("/api/status", api_status),
    Route("/api/provider/health", api_provider_health),
    Route("/api/logs/stream", api_logs_stream),
    Route("/api/gateway/start", api_gateway_start, methods=["POST"]),
    Route("/api/gateway/stop", api_gateway_stop, methods=["POST"]),
    Route("/api/gateway/restart", api_gateway_restart, methods=["POST"]),
]

app = Starlette(
    routes=routes,
    lifespan=lifespan,
)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8080"))

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info", loop="asyncio")
    server = uvicorn.Server(config)

    def handle_signal():
        loop.create_task(gateway.stop())
        server.should_exit = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, handle_signal)

    loop.run_until_complete(server.serve())
