const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CNS_CHAT_PRO_V4_SECRET_CHANGE_ME";
const DB = path.join(__dirname, "cns_chat_pro.db");

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database(DB);

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        phone TEXT UNIQUE,
        password TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        receiver TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);
});

function auth(req, res, next) {
    const h = req.headers.authorization || "";

    if (!h.startsWith("Bearer ")) {
        return res.status(401).json({
            success: false,
            message: "Token manquant"
        });
    }

    try {
        req.user = jwt.verify(h.substring(7), JWT_SECRET);
        next();
    } catch {
        res.status(401).json({
            success: false,
            message: "Token invalide"
        });
    }
}

app.get("/", (req, res) => {
    res.json({
        success: true,
        app: "CNS Chat Pro",
        version: "4.0.0",
        status: "online"
    });
});

app.get("/health", (req, res) => {
    db.get("SELECT 1 AS ok", (err) => {
        if (err) {
            return res.status(500).json({
                status: "error",
                database: "disconnected"
            });
        }

        res.json({
            status: "ok",
            database: "connected"
        });
    });
});

app.post("/api/register", async (req, res) => {
    try {
        const phone = String(req.body.phone || "").trim();
        const password = String(req.body.password || "");

        if (!phone || !password) {
            return res.status(400).json({
                success: false,
                message: "Numéro et mot de passe requis"
            });
        }

        const hash = await bcrypt.hash(password, 10);

        db.run(
            `INSERT INTO users(username, phone, password)
             VALUES(?,?,?)`,
            [phone, phone, hash],
            function(err) {
                if (err) {
                    return res.status(409).json({
                        success: false,
                        message: "Ce numéro est déjà utilisé"
                    });
                }

                const token = jwt.sign(
                    {
                        id: this.lastID,
                        username: phone,
                        phone: phone
                    },
                    JWT_SECRET,
                    { expiresIn: "7d" }
                );

                res.json({
                    success: true,
                    message: "Compte créé",
                    token,
                    username: phone,
                    phone
                });
            }
        );
    } catch {
        res.status(500).json({
            success: false,
            message: "Erreur serveur"
        });
    }
});

app.post("/api/login", (req, res) => {
    const phone = String(req.body.phone || "").trim();
    const password = String(req.body.password || "");

    db.get(
        `SELECT id, username, phone, password
         FROM users
         WHERE phone = ?`,
        [phone],
        async (err, user) => {
            if (err || !user) {
                return res.status(401).json({
                    success: false,
                    message: "Numéro ou mot de passe incorrect"
                });
            }

            const ok = await bcrypt.compare(password, user.password);

            if (!ok) {
                return res.status(401).json({
                    success: false,
                    message: "Numéro ou mot de passe incorrect"
                });
            }

            const token = jwt.sign(
                {
                    id: user.id,
                    username: user.username,
                    phone: user.phone
                },
                JWT_SECRET,
                { expiresIn: "7d" }
            );

            res.json({
                success: true,
                token,
                username: user.username,
                phone: user.phone
            });
        }
    );
});

app.get("/api/messages", auth, (req, res) => {
    const user1 = String(req.query.user1 || "").trim();
    const user2 = String(req.query.user2 || "").trim();

    db.all(
        `SELECT username AS sender, receiver, message, created_at
         FROM messages
         WHERE
           (username = ? AND receiver = ?)
           OR
           (username = ? AND receiver = ?)
         ORDER BY id ASC`,
        [user1, user2, user2, user1],
        (err, rows) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Erreur serveur"
                });
            }

            res.json({
                success: true,
                messages: rows
            });
        }
    );
});

app.post("/api/messages", auth, (req, res) => {
    const sender = req.user.username;
    const receiver = String(req.body.receiver || "").trim();
    const message = String(req.body.message || "").trim();

    if (!receiver || !message) {
        return res.status(400).json({
            success: false,
            message: "Destinataire et message requis"
        });
    }

    db.run(
        `INSERT INTO messages(username, receiver, message)
         VALUES(?,?,?)`,
        [sender, receiver, message],
        (err) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Erreur serveur"
                });
            }

            res.json({
                success: true,
                message: "Message envoyé"
            });
        }
    );
});

app.listen(PORT, "0.0.0.0", () => {
    console.log("CNS Chat Pro V4 serveur prêt");
    console.log("Port : " + PORT);
});
