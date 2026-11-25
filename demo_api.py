"""Intentionally vulnerable local API for classroom demonstration only."""
from flask import Flask, jsonify, request

app = Flask(__name__)

@app.get("/")
def index():
    return jsonify({
        "name": "REST API Security Assessment Demo",
        "message": "Local training API. Do not expose this service publicly.",
        "endpoints": ["/api/public", "/api/profile", "/api/search?q=hello", "/health"]
    })

@app.get("/health")
def health():
    return jsonify({"status": "ok"})

@app.get("/api/public")
def public():
    return jsonify({"message": "This endpoint is intentionally public."})

@app.get("/api/profile")
def profile():
    # INTENTIONAL DEMO WEAKNESS: no authentication check.
    return jsonify({
        "user_id": 101,
        "name": "Demo Student",
        "email": "student@example.invalid",
        "note": "This private-looking endpoint is intentionally exposed for the project demo."
    })

@app.get("/api/search")
def search():
    # Demonstrates a simple input endpoint. No database or code execution is used.
    q = request.args.get("q", "")
    if len(q) > 100:
        return jsonify({"error": "Query too long"}), 400
    return jsonify({"query": q, "results": []})

if __name__ == "__main__":
    # Bind to loopback only, so the demo is not exposed to the network.
    app.run(host="127.0.0.1", port=5001, debug=False)
