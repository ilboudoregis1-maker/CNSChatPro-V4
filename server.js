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

    db.all(`PRAGMA table_info(users)`, (err, columns) => {
        if (err) {
            console.error("DB CHECK USERS:", err.message);
            return;
        }

        const hasPhone = columns.some(c => c.name === "phone");

        const createIndex = () => {
            db.run(
                `CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone)`,
                indexErr => {
                    if (indexErr) {
                        console.error("DB PHONE INDEX:", indexErr.message);
                    } else {
                        console.log("DB READY: users.phone OK");
                    }
                }
            );
        };

        if (!hasPhone) {
            db.run(`ALTER TABLE users ADD COLUMN phone TEXT`, alterErr => {
                if (alterErr) {
                    console.error("DB ADD PHONE:", alterErr.message);
                } else {
                    console.log("DB MIGRATION: colonne phone ajoutée");
                }
                createIndex();
            });
        } else {
            console.log("DB CHECK: colonne phone présente");
            createIndex();
        }
    });
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

function normalizePhone(phone) {
    let p = String(phone || "").trim().replace(/[\s().-]/g, "");

    if (p.startsWith("00226")) {
        p = "+" + p.substring(2);
    } else if (p.startsWith("226") && !p.startsWith("+")) {
        p = "+" + p;
    } else if (/^\d{8}$/.test(p)) {
        p = "+226" + p;
    }

    return p;
}

app.post("/api/register", async (req, res) => {
    try {
        const phone = normalizePhone(req.body.phone);
        const password = String(req.body.password || "");

        if (!phone || !password) {
            return res.status(400).json({
                success: false,
                message: "Numéro et mot de passe requis"
            });
        }

        if (!/^\+226\d{8}$/.test(phone)) {
            return res.status(400).json({
                success: false,
                message: "Numéro de téléphone invalide"
            });
        }

        if (password.length < 4) {
            return res.status(400).json({
                success: false,
                message: "Le mot de passe doit contenir au moins 4 caractères"
            });
        }

        db.get(
            `SELECT id FROM users
             WHERE phone = ? OR username = ?
             LIMIT 1`,
            [phone, phone],
            async (checkErr, existing) => {

                if (checkErr) {
                    return res.status(500).json({
                        success: false,
                        message: "Erreur de vérification du compte"
                    });
                }

                if (existing) {
                    return res.status(409).json({
                        success: false,
                        message: "Ce numéro est déjà utilisé"
                    });
                }

                const hash = await bcrypt.hash(password, 10);

                db.run(
                    `INSERT INTO users(username, phone, password)
                     VALUES(?,?,?)`,
                    [phone, phone, hash],
                    function(err) {

                        if (err) {
                            console.error("REGISTER DB:", err.message);

                            if (err.message.includes("UNIQUE")) {
                                return res.status(409).json({
                                    success: false,
                                    message: "Ce numéro est déjà utilisé"
                                });
                            }

                            return res.status(500).json({
                                success: false,
                                message: "Impossible de créer le compte"
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
            }
        );

    } catch (e) {
        console.error("REGISTER:", e.message);

        res.status(500).json({
            success: false,
            message: "Erreur serveur"
        });
    }
});


app.put("/api/profile", (req, res) => {
    try {
        const auth = req.headers.authorization || "";
        const token = auth.startsWith("Bearer ")
            ? auth.substring(7)
            : "";

        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Connexion requise"
            });
        }

        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET);
        } catch (e) {
            return res.status(401).json({
                success: false,
                message: "Session expirée"
            });
        }

        const username = String(req.body.username || "").trim();

        if (username.length < 2 || username.length > 30) {
            return res.status(400).json({
                success: false,
                message: "Le pseudo doit contenir entre 2 et 30 caractères"
            });
        }

        if (!/^[a-zA-ZÀ-ÿ0-9 _.-]+$/.test(username)) {
            return res.status(400).json({
                success: false,
                message: "Pseudo invalide"
            });
        }

        db.get(
            `SELECT id FROM users
             WHERE username = ? AND id != ?
             LIMIT 1`,
            [username, decoded.id],
            (checkErr, existing) => {

                if (checkErr) {
                    return res.status(500).json({
                        success: false,
                        message: "Erreur serveur"
                    });
                }

                if (existing) {
                    return res.status(409).json({
                        success: false,
                        message: "Ce pseudo est déjà utilisé"
                    });
                }

                db.run(
                    `UPDATE users SET username = ? WHERE id = ?`,
                    [username, decoded.id],
                    function(err) {

                        if (err) {
                            console.error("PROFILE DB:", err.message);
                            return res.status(500).json({
                                success: false,
                                message: "Impossible de modifier le profil"
                            });
                        }

                        const newToken = jwt.sign(
                            {
                                id: decoded.id,
                                username: username,
                                phone: decoded.phone
                            },
                            JWT_SECRET,
                            { expiresIn: "7d" }
                        );

                        res.json({
                            success: true,
                            message: "Profil mis à jour",
                            token: newToken,
                            username: username,
                            phone: decoded.phone
                        });
                    }
                );
            }
        );

    } catch (e) {
        console.error("PROFILE:", e.message);
        res.status(500).json({
            success: false,
            message: "Erreur serveur"
        });
    }
});


app.get("/api/profile", (req, res) => {
    try {
        const auth = req.headers.authorization || "";

        if (!auth.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                message: "Non authentifié"
            });
        }

        const token = auth.substring(7);
        const decoded = jwt.verify(token, JWT_SECRET);

        db.get(
            `SELECT id, username, phone, created_at
             FROM users
             WHERE id = ?`,
            [decoded.id],
            (err, user) => {
                if (err || !user) {
                    return res.status(404).json({
                        success: false,
                        message: "Utilisateur introuvable"
                    });
                }

                res.json({
                    success: true,
                    id: user.id,
                    username: user.username,
                    phone: user.phone,
                    created_at: user.created_at
                });
            }
        );
    } catch (e) {
        return res.status(401).json({
            success: false,
            message: "Session invalide"
        });
    }
});

app.put("/api/profile", (req, res) => {
    try {
        const auth = req.headers.authorization || "";

        if (!auth.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                message: "Non authentifié"
            });
        }

        const token = auth.substring(7);
        const decoded = jwt.verify(token, JWT_SECRET);

        const newUsername =
            String(req.body.username || "").trim();

        if (!newUsername) {
            return res.status(400).json({
                success: false,
                message: "Pseudo requis"
            });
        }

        if (newUsername.length < 3 || newUsername.length > 30) {
            return res.status(400).json({
                success: false,
                message: "Le pseudo doit contenir entre 3 et 30 caractères"
            });
        }

        if (!/^[a-zA-Z0-9_ .-]+$/.test(newUsername)) {
            return res.status(400).json({
                success: false,
                message: "Pseudo invalide"
            });
        }

        db.get(
            `SELECT id FROM users
             WHERE username = ? AND id != ?
             LIMIT 1`,
            [newUsername, decoded.id],
            (checkErr, existing) => {

                if (checkErr) {
                    return res.status(500).json({
                        success: false,
                        message: "Erreur de vérification"
                    });
                }

                if (existing) {
                    return res.status(409).json({
                        success: false,
                        message: "Ce pseudo est déjà utilisé"
                    });
                }

                db.run(
                    `UPDATE users
                     SET username = ?
                     WHERE id = ?`,
                    [newUsername, decoded.id],
                    function(err) {

                        if (err) {
                            console.error(
                                "PROFILE DB:",
                                err.message
                            );

                            return res.status(500).json({
                                success: false,
                                message: "Impossible de modifier le pseudo"
                            });
                        }

                        db.get(
                            `SELECT id, username, phone
                             FROM users
                             WHERE id = ?`,
                            [decoded.id],
                            (selectErr, user) => {

                                if (selectErr || !user) {
                                    return res.status(500).json({
                                        success: false,
                                        message: "Erreur après modification"
                                    });
                                }

                                const newToken = jwt.sign(
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
                                    message: "Profil mis à jour",
                                    token: newToken,
                                    username: user.username,
                                    phone: user.phone
                                });
                            }
                        );
                    }
                );
            }
        );
    } catch (e) {
        return res.status(401).json({
            success: false,
            message: "Session invalide"
        });
    }
});

app.post("/api/login", (req, res) => {
    const phone = normalizePhone(req.body.phone);
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
