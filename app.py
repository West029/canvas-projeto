import json
import math
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

DEFAULT_DIAGRAM_JSON = '{"type":"mechanical","nodes":[],"connections":[]}'
DIAGRAM_TYPES = {"mechanical", "electrical"}
DIAGRAM_SYMBOLS = {
    "start",
    "process",
    "decision",
    "io",
    "motor",
    "pump",
    "valve",
    "tank",
    "sensor",
    "source_ac",
    "battery",
    "breaker",
    "switch",
    "lamp",
    "resistor",
    "ground",
}


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
    db = sqlite3.connect(app.config["DATABASE"])
    try:
        with db:
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
                    diagram TEXT NOT NULL DEFAULT '{"type":"mechanical","nodes":[],"connections":[]}',
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
            if "diagram" not in columns:
                db.execute(
                    "ALTER TABLE canvases ADD COLUMN diagram TEXT NOT NULL DEFAULT "
                    "'{\"type\":\"mechanical\",\"nodes\":[],\"connections\":[]}'"
                )
    finally:
        db.close()


def empty_sections():
    return {section: "" for section in SECTIONS}


def empty_diagram():
    return json.loads(DEFAULT_DIAGRAM_JSON)


def canvas_to_dict(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "description": row["description"],
        "sections": json.loads(row["sections"]),
        "diagram": json.loads(row["diagram"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def parse_diagram_payload(value):
    if not isinstance(value, dict):
        return None, "O diagrama deve ser enviado como objeto JSON."

    diagram_type = value.get("type")
    nodes = value.get("nodes")
    connections = value.get("connections")
    if not isinstance(diagram_type, str) or diagram_type not in DIAGRAM_TYPES:
        return None, "Escolha um tipo de diagrama válido."
    if not isinstance(nodes, list) or len(nodes) > 300:
        return None, "O diagrama deve ter no máximo 300 símbolos."
    if not isinstance(connections, list) or len(connections) > 600:
        return None, "O diagrama deve ter no máximo 600 conexões."

    clean_nodes = []
    node_ids = set()
    for node in nodes:
        if not isinstance(node, dict):
            return None, "Cada símbolo do diagrama deve ser um objeto."
        node_id = node.get("id")
        symbol_type = node.get("type")
        label = node.get("label")
        x = node.get("x")
        y = node.get("y")
        if not isinstance(node_id, str) or not node_id.strip() or len(node_id) > 64:
            return None, "Cada símbolo precisa ter um identificador válido."
        if node_id in node_ids:
            return None, "O diagrama contém identificadores de símbolo repetidos."
        if not isinstance(symbol_type, str) or symbol_type not in DIAGRAM_SYMBOLS:
            return None, "O diagrama contém um tipo de símbolo desconhecido."
        if not isinstance(label, str) or len(label) > 100:
            return None, "O rótulo de cada símbolo deve ter até 100 caracteres."
        if (
            isinstance(x, bool)
            or not isinstance(x, (int, float))
            or (isinstance(x, float) and not math.isfinite(x))
            or not 0 <= x <= 1200
        ):
            return None, "A posição horizontal de um símbolo é inválida."
        if (
            isinstance(y, bool)
            or not isinstance(y, (int, float))
            or (isinstance(y, float) and not math.isfinite(y))
            or not 0 <= y <= 700
        ):
            return None, "A posição vertical de um símbolo é inválida."
        node_ids.add(node_id)
        clean_nodes.append(
            {
                "id": node_id,
                "type": symbol_type,
                "label": label,
                "x": x,
                "y": y,
            }
        )

    clean_connections = []
    connection_pairs = set()
    for connection in connections:
        if not isinstance(connection, dict):
            return None, "Cada conexão deve ser um objeto."
        source = connection.get("from")
        target = connection.get("to")
        if (
            not isinstance(source, str)
            or not isinstance(target, str)
            or source not in node_ids
            or target not in node_ids
            or source == target
        ):
            return None, "Uma conexão aponta para símbolos inválidos."
        pair = (source, target)
        if pair in connection_pairs:
            return None, "O diagrama contém conexões repetidas."
        connection_pairs.add(pair)
        clean_connections.append({"from": source, "to": target})

    return {
        "type": diagram_type,
        "nodes": clean_nodes,
        "connections": clean_connections,
    }, None


def parse_canvas_payload(data, existing=None):
    if not isinstance(data, dict):
        return None, "O corpo da requisição deve ser um objeto JSON."

    existing = existing or {
        "title": "",
        "description": "",
        "sections": empty_sections(),
        "diagram": empty_diagram(),
    }
    title = data.get("title", existing["title"])
    description = data.get("description", existing["description"])
    sections = data.get("sections", existing["sections"])
    diagram, diagram_error = parse_diagram_payload(
        data.get("diagram", existing["diagram"])
    )

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
    if diagram_error:
        return None, diagram_error

    clean_sections = empty_sections()
    clean_sections.update(sections)
    return {
        "title": title.strip(),
        "description": description.strip(),
        "sections": clean_sections,
        "diagram": diagram,
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
            SELECT id, title, description, sections, diagram, created_at, updated_at
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
            INSERT INTO canvases (user_id, title, description, sections, diagram)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_id,
                payload["title"],
                payload["description"],
                json.dumps(payload["sections"], ensure_ascii=False),
                json.dumps(payload["diagram"], ensure_ascii=False),
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
            SET title = ?, description = ?, sections = ?, diagram = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
            """,
            (
                payload["title"],
                payload["description"],
                json.dumps(payload["sections"], ensure_ascii=False),
                json.dumps(payload["diagram"], ensure_ascii=False),
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