"""
Mock Upstream Web Application.
Simulates a real backend application that the WAF protects.
Runs on port 8080 by default.
"""

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

app = FastAPI(title="Target Web Application (Vulnerable / Protected)")

class LoginRequest(BaseModel):
    username: str
    password: str

@app.get("/health")
def health():
    return {"status": "ok", "app": "Mock Upstream Service"}

@app.get("/api/v1/products")
def get_products(category: str = "all", search: str = ""):
    return {
        "status": "success",
        "category": category,
        "search_query": search,
        "items": [
            {"id": 1, "name": "Wireless Headphones", "price": 129.99},
            {"id": 2, "name": "Mechanical Gaming Keyboard", "price": 89.50},
            {"id": 3, "name": "Ultra-Wide 4K Monitor", "price": 499.00}
        ]
    }

@app.post("/api/v1/login")
def login(creds: LoginRequest):
    return {
        "status": "success",
        "message": f"Welcome back, {creds.username}!",
        "token": "mock-jwt-token-xyz-123"
    }

@app.get("/api/v1/users/{user_id}")
def get_user_profile(user_id: int):
    return {
        "user_id": user_id,
        "username": f"user_{user_id}",
        "role": "standard_user",
        "email": f"user_{user_id}@targetapp.com"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
