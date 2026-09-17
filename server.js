const express = require("express");
const cors = require("cors");
const { DatabaseSync } = require("node:sqlite");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const db = new DatabaseSync("./cns_chat_pro.db");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

app.get("/", (req, res) => {
    res.json({
        app: "CNS Chat Pro",
        version: "4.0.0",
        status: "online"
    });
});

app.get("/api/health", (req, res) => {
    res.json({
        success: true,
        server: "CNS Chat Pro V4",
        database: "SQLite",
        status: "online"
    });
});

app.post("/api/register", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            success: false,
            message: "Nom d'utilisateur et mot de passe requis"
        });
    }

    try {
        const stmt = db.prepare(
            "INSERT INTO users (username, password) VALUES (?, ?)"
        );

        const result = stmt.run(username, password);

        res.json({
            success: true,
            message: "Compte créé",
            userId: Number(result.lastInsertRowid),
            username
        });
    } catch (error) {
        res.status(409).json({
            success: false,
            message: "Ce nom d'utilisateur existe déjà"
        });
    }
});

app.post("/api/login", (req, res) => {
    const { username, password } = req.body;

    const stmt = db.prepare(
        "SELECT id, username FROM users WHERE username = ? AND password = ?"
    );

    const user = stmt.get(username, password);

    if (!user) {
        return res.status(401).json({
            success: false,
            message: "Identifiants incorrects"
        });
    }

    res.json({
        success: true,
        message: "Connexion réussie",
        user
    });
});

app.post("/api/messages", (req, res) => {
    const { username, message } = req.body;

    if (!username || !message) {
        return res.status(400).json({
            success: false,
            message: "username et message requis"
        });
    }

    const stmt = db.prepare(
        "INSERT INTO messages (username, message) VALUES (?, ?)"
    );

    const result = stmt.run(username, message);

    res.json({
        success: true,
        id: Number(result.lastInsertRowid)
    });
});

app.get("/api/messages", (req, res) => {
    const stmt = db.prepare(`
        SELECT id, username, message, created_at
        FROM messages
        ORDER BY id ASC
    `);

    res.json({
        success: true,
        messages: stmt.all()
    });
});

app.listen(PORT, "0.0.0.0", () => {
    console.log("======================================");
    console.log("       CNS CHAT PRO V4 SERVER");
    console.log("======================================");
    console.log("Node :", process.version);
    console.log("Port :", PORT);
    console.log("SQLite : node:sqlite");
    console.log("Serveur : http://127.0.0.1:" + PORT);
    console.log("======================================");
});
