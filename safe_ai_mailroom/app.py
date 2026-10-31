import os
from flask import Flask, request, jsonify
from mailroom import MailroomService, ContractError, ConflictError, ServiceUnavailable

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_BODY_BYTES", "2097152"))
service = MailroomService(
    db_path=os.getenv("DATABASE_PATH", "/var/data/mailroom.sqlite3" if os.getenv("RENDER") else "mailroom.sqlite3"),
    ai_base_url=os.getenv("AI_BASE_URL", "https://api.openai.com/v1"),
    ai_api_key=os.getenv("AI_API_KEY", ""),
    ai_model=os.getenv("AI_MODEL", "gpt-4.1-mini"),
    ai_timeout=float(os.getenv("AI_TIMEOUT_SECONDS", "35")),
)

@app.post("/v1/mailroom/actions")
def actions():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Malformed JSON object"}), 400
    try:
        if body.get("operation") == "propose":
            result = service.propose(body)
        elif body.get("operation") == "commit":
            result = service.commit(body)
        else:
            raise ContractError("operation must be propose or commit")
        return jsonify(result), 200
    except ConflictError as exc:
        return jsonify({"error": str(exc)}), 409
    except ServiceUnavailable as exc:
        return jsonify({"error": str(exc)}), 503
    except ContractError as exc:
        return jsonify({"error": str(exc)}), 422
    except Exception:
        app.logger.exception("Unhandled mailroom error")
        return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Request body too large"}), 413

@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
