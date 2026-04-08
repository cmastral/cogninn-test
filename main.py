from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import redis
import os


app = FastAPI(
    title="Cogninn API",
    description="Demo of rate limiting and brute-force protection in FastAPI.",
    version="1.0.0",
)

# Rate limiter, key by IP
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"error": "Too many requests."},
        headers={"Retry-After": "60"},
    )

USERS = {
    "cogninn": "secure123",
}

MAX_ATTEMPTS = 5
LOCKOUT_DURATION = 30 #seconds 

# Redis for brute force protection

# LOCAL HOSTING 
# r = redis.Redis(host="localhost", port=6379, decode_responses=True) 

# RAILWAY HOSTING
r = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)


class LoginRequest(BaseModel):
    username: str
    password: str

@app.get("/home")
@limiter.limit("10/minute")
async def ping(request: Request):
    return {"message": "Hello."}

@app.post("/login")
# limiter for request rate limit
@limiter.limit("5/minute") 
async def login(request: Request, body: LoginRequest):
    ip = request.client.host
    key = f"failed:{ip}"

    attempts = int(r.get(key) or 0)
    if attempts >= MAX_ATTEMPTS:
        ttl = r.ttl(key)
        return JSONResponse(
            status_code=429,
            content={"error": f"Too many failed attempts. Try again in {ttl} seconds."}
        )

    user_password = USERS.get(body.username)

    # Check credentials
    if user_password is None or user_password != body.password:
        r.incr(key)
        r.expire(key, LOCKOUT_DURATION)
        attempts_left = MAX_ATTEMPTS - (attempts + 1)
        return JSONResponse(
            status_code=401,
            content={"error": f"Invalid credentials. {attempts_left} attempts left."}
        )

    r.delete(key)
    return {"message": f"Welcome, {body.username}!"}