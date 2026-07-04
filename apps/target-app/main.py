from fastapi import FastAPI, Header, HTTPException
from typing import Optional

app = FastAPI(title="Target Microservice")

@app.get("/")
def read_root():
    return {
        "message": "Welcome to the Secure E-Commerce Home Page",
        "status": "Healthy"
    }

@app.get("/products")
def read_products():
    return {
        "products": [
            {"id": 1, "name": "Developer Laptop", "price": 1200},
            {"id": 2, "name": "Mechanical Keyboard", "price": 150},
            {"id": 3, "name": "Sidecar Security Guide Book", "price": 35}
        ]
    }

@app.post("/cart")
def add_to_cart(item_id: int):
    return {
        "message": f"Item {item_id} added to cart successfully!"
    }

@app.post("/checkout")
def checkout(x_user_info: Optional[str] = Header(None)):
    # In a real microservice, we trust the sidecar proxy to authenticate.
    # OPA/Envoy will validate the JWT and inject the user info into the 'X-User-Info' header.
    if not x_user_info:
        raise HTTPException(
            status_code=401, 
            detail="Unauthorized: Access must go through the Sidecar security gateway."
        )
    
    return {
        "message": "Checkout successful! Payment processed.",
        "user_info": x_user_info
    }
