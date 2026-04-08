from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request as StarletteRequest
import redis
import os

# IP resolution — reads X-Forwarded-For when using Railway
# direct client host for local development

def get_real_ip(request: StarletteRequest) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host


# App
app = FastAPI(
    title="Cogninn API",
    description="Demo of rate limiting and brute-force protection in FastAPI.",
    version="1.0.0",
)

# Rate limiter — key by IP
limiter = Limiter(key_func=get_real_ip)
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"error": "Too many requests."},
        headers={"Retry-After": "60"},
    )


# Redis — for brute force
r = redis.Redis.from_url(
    os.getenv("REDIS_URL", "redis://localhost:6379"),
    decode_responses=True
)


# Users (NOTE: This should be a database in production)
USERS = {
    "cogninn": "secure123",
}

MAX_ATTEMPTS = 5
LOCKOUT_DURATION = 30  # seconds

class LoginRequest(BaseModel):
    username: str
    password: str

# Routes

@app.get("/home")
@limiter.limit("10/minute")
async def home(request: Request):
    return {"message": "Hello."}


@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, body: LoginRequest):
    ip = get_real_ip(request)
    key = f"failed:{ip}"

    # Check brute force lockout
    attempts = int(r.get(key) or 0)
    if attempts >= MAX_ATTEMPTS:
        ttl = r.ttl(key)
        return JSONResponse(
            status_code=429,
            content={"error": f"Too many failed attempts. Try again in {ttl} seconds."}
        )

    # Validate credentials
    user_password = USERS.get(body.username)
    if user_password is None or user_password != body.password:
        r.incr(key)
        r.expire(key, LOCKOUT_DURATION)
        attempts_left = MAX_ATTEMPTS - (attempts + 1)
        return JSONResponse(
            status_code=401,
            content={"error": f"Invalid credentials. {attempts_left} attempts left."}
        )

    # Success — reset failed attempt counter
    r.delete(key)
    return {"message": f"Welcome, {body.username}!"}