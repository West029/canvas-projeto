import json
import os
import secrets
import sqlite3
from pathlib import Path

from flask import Flask, current_app, g, jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash


SECTIONS = (
    "justificativa",
    "objetivo_smart",
    "beneficios",
    "produto",
    "requisitos",
    "equipe",
    "premissas",
    "grupos_entregas",
    "restricoes",
    "riscos",
    "linha_tempo",
    "custos",
)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def initialize_db(app):
    with sqlite3.connect(app.config["DATABASE"]) as db:
        db.execute("PRAGMA foreign_keys = ON")
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS canvases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id),
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                sections TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        columns = {
            row[1] for row in db.execute("PRAGMA table_info(canvases)").fetchall()
        }
        if "user_id" not in columns:
            db.execute(
                "ALTER TABLE canvases ADD COLUMN user_id INTEGER REFERENCES users(id)"
            )


def empty_sections():
    return {section: "" for section in SECTIONS}


def canvas_to_dict(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "description": row["description"],
        "sections": json.loads(row["sections"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def parse_canvas_payload(data, existing=None):
    if not isinstance(data, dict):
        return None, "O corpo da requisição deve ser um objeto JSON."

    existing = existing or {
        "title": "",
        "description": "",
        "sections": empty_sections(),
    }
    title = data.get("title", existing["title"])
    description = data.get("description", existing["description"])
    sections = data.get("sections", existing["sections"])

    if not isinstance(title, str) or not title.strip():
        return None, "O título é obrigatório."
    if len(title.strip()) > 160:
        return None, "O título deve ter no máximo 160 caracteres."
    if not isinstance(description, str):
        return None, "A descrição deve ser um texto."
    if not isinstance(sections, dict):
        return None, "Os blocos do canvas devem ser enviados como objeto JSON."
    if any(key not in SECTIONS for key in sections):
        return None, "O canvas contém um bloco desconhecido."
    if any(not isinstance(value, str) for value in sections.values()):
        return None, "O conteúdo de cada bloco deve ser um texto."

    clean_sections = empty_sections()
    clean_sections.update(sections)
    return {
        "title": title.strip(),
        "description": description.strip(),
        "sections": clean_sections,
    }, None


def create_app(test_config=None):
    app = Flask(__name__, template_folder="template")
    app.config.from_mapping(
        DATABASE=str(Path(app.instance_path) / "canvases.sqlite3"),
        SECRET_KEY=os.environ.get("PM_CANVAS_SECRET_KEY"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    if not app.config["SECRET_KEY"]:
        secret_key_path = Path(app.instance_path) / "secret_key"
        try:
            with secret_key_path.open("x", encoding="utf-8") as secret_file:
                secret_file.write(secrets.token_hex(32))
        except FileExistsError:
            pass
        app.config["SECRET_KEY"] = secret_key_path.read_text(encoding="utf-8").strip()
    initialize_db(app)
    app.teardown_appcontext(close_db)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/canvases")
    def list_canvases():
        user_id = session.get("user_id")
        if user_id is None:
            return jsonify({"error": "Faça login para ver seus projetos."}), 401
        rows = get_db().execute(
            """
            SELECT id, title, description, sections, created_at, updated_at
            FROM canvases
            WHERE user_id = ?
            ORDER BY updated_at DESC, id DESC
            """,
            (user_id,),
        ).fetchall()
        return jsonify([canvas_to_dict(row) for row in rows])

    @app.get("/api/session")
    def get_session():
        user_id = session.get("user_id")
        if user_id is None:
            return jsonify({"user": None})
        user = get_db().execute(
            "SELECT id, email FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if user is None:
            session.clear()
            return jsonify({"user": None})
        return jsonify({"user": {"id": user["id"], "email": user["email"]}})

    @app.post("/api/register")
    def register():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Envie os dados da conta em JSON."}), 400
        email = data.get("email")
        password = data.get("password")
        if not isinstance(email, str) or not isinstance(password, str):
            return jsonify({"error": "E-mail e senha são obrigatórios."}), 400
        email = email.strip().lower()
        if len(email) > 254 or "@" not in email or any(char.isspace() for char in email):
            return jsonify({"error": "Informe um e-mail válido."}), 400
        if len(password) < 8:
            return jsonify({"error": "A senha deve ter pelo menos 8 caracteres."}), 400

        db = get_db()
        try:
            db.execute("BEGIN IMMEDIATE")
            first_user = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
            cursor = db.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, generate_password_hash(password)),
            )
            if first_user:
                db.execute(
                    "UPDATE canvases SET user_id = ? WHERE user_id IS NULL",
                    (cursor.lastrowid,),
                )
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            return jsonify({"error": "Já existe uma conta com este e-mail."}), 409

        session.clear()
        session["user_id"] = cursor.lastrowid
        return jsonify({"user": {"id": cursor.lastrowid, "email": email}}), 201

    @app.post("/api/login")
    def login():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Envie e-mail e senha em JSON."}), 400
        email = data.get("email")
        password = data.get("password")
        if not isinstance(email, str) or not isinstance(password, str):
            return jsonify({"error": "E-mail e senha são obrigatórios."}), 400

        user = get_db().execute(
            "SELECT id, email, password_hash FROM users WHERE email = ?",
            (email.strip().lower(),),
        ).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            return jsonify({"error": "E-mail ou senha incorretos."}), 401

        session.clear()
        session["user_id"] = user["id"]
        return jsonify({"user": {"id": user["id"], "email": user["email"]}})

    @app.post("/api/logout")
    def logout():
        session.clear()
        return "", 204

    @app.post("/api/canvases")
    def create_canvas():
        user_id = session.get("user_id")
        if user_id is None:
            return jsonify({"error": "Faça login para salvar projetos."}), 401
        payload, error = parse_canvas_payload(request.get_json(silent=True))
        if error:
            return jsonify({"error": error}), 400

        db = get_db()
        cursor = db.execute(
            """
            INSERT INTO canvases (user_id, title, description, sections)
            VALUES (?, ?, ?, ?)
            """,
            (
                user_id,
                payload["title"],
                payload["description"],
                json.dumps(payload["sections"], ensure_ascii=False),
            ),
        )
        db.commit()
        row = db.execute(
            "SELECT * FROM canvases WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
        return jsonify(canvas_to_dict(row)), 201

    @app.get("/api/canvases/<int:canvas_id>")
    def get_canvas(canvas_id):
        user_id = session.get("user_id")
        if user_id is None:
            return jsonify({"error": "Faça login para ver seus projetos."}), 401
        row = get_db().execute(
            "SELECT * FROM canvases WHERE id = ? AND user_id = ?",
            (canvas_id, user_id),
        ).fetchone()
        if row is None:
            return jsonify({"error": "Canvas não encontrado."}), 404
        return jsonify(canvas_to_dict(row))

    @app.put("/api/canvases/<int:canvas_id>")
    def update_canvas(canvas_id):
        user_id = session.get("user_id")
        if user_id is None:
            return jsonify({"error": "Faça login para editar projetos."}), 401
        db = get_db()
        row = db.execute(
            "SELECT * FROM canvases WHERE id = ? AND user_id = ?",
            (canvas_id, user_id),
        ).fetchone()
        if row is None:
            return jsonify({"error": "Canvas não encontrado."}), 404

        existing = canvas_to_dict(row)
        payload, error = parse_canvas_payload(
            request.get_json(silent=True), existing
        )
        if error:
            return jsonify({"error": error}), 400

        db.execute(
            """
            UPDATE canvases
            SET title = ?, description = ?, sections = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
            """,
            (
                payload["title"],
                payload["description"],
                json.dumps(payload["sections"], ensure_ascii=False),
                canvas_id,
                user_id,
            ),
        )
        db.commit()
        updated = db.execute(
            "SELECT * FROM canvases WHERE id = ?", (canvas_id,)
        ).fetchone()
        return jsonify(canvas_to_dict(updated))

    @app.delete("/api/canvases/<int:canvas_id>")
    def delete_canvas(canvas_id):
        user_id = session.get("user_id")
        if user_id is None:
            return jsonify({"error": "Faça login para excluir projetos."}), 401
        db = get_db()
        cursor = db.execute(
            "DELETE FROM canvases WHERE id = ? AND user_id = ?",
            (canvas_id, user_id),
        )
        db.commit()
        if cursor.rowcount == 0:
            return jsonify({"error": "Canvas não encontrado."}), 404
        return "", 204

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)