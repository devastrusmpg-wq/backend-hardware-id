
const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "10kb" }));

if (!process.env.DATABASE_URL) {
    throw new Error("Missing DATABASE_URL environment variable.");
}

if (!process.env.BAN_ADMIN_KEY) {
    throw new Error("Missing BAN_ADMIN_KEY environment variable.");
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

const ADMIN_KEY = process.env.BAN_ADMIN_KEY;

function hashDeviceId(id) {
    return crypto.createHash("sha256")
        .update(id)
        .digest("hex");
}

function validId(id) {
    return typeof id === "string" &&
        /^[a-f0-9]{64}$/i.test(id);
}

function validGameId(id) {
    return typeof id === "string" &&
        id.length >= 1 && id.length <= 80;
}

function adminOnly(req, res, next) {
    const supplied = req.get("x-admin-key") || "";
    const a = Buffer.from(supplied);
    const b = Buffer.from(ADMIN_KEY);

    if (a.length !== b.length ||
        !crypto.timingSafeEqual(a, b)) {
        return res.status(401).json({
            error: "Unauthorized"
        });
    }

    next();
}

app.get("/health", async (req, res) => {
    try {
        await pool.query("SELECT 1");
        res.json({ status: "ok", database: "connected" });
    } catch (error) {
        console.error("Health check failed:", error.message);
        res.status(503).json({ status: "database unavailable" });
    }
});

app.post("/api/device/check", async (req, res) => {
    const { gameId, installationId } = req.body || {};

    if (!validGameId(gameId) || !validId(installationId)) {
        return res.status(400).json({
            allowed: false,
            banned: false,
            reason: "Invalid request"
        });
    }

    try {
        const result = await pool.query(
            `SELECT reason FROM device_bans
             WHERE game_id = $1 AND device_hash = $2`,
            [gameId, hashDeviceId(installationId)]
        );

        if (result.rows.length > 0) {
            return res.json({
                allowed: false,
                banned: true,
                reason: result.rows[0].reason
            });
        }

        return res.json({
            allowed: true,
            banned: false,
            reason: ""
        });
    } catch (error) {
        console.error("Ban check failed:", error.message);
        return res.status(503).json({
            allowed: false,
            banned: false,
            reason: "Ban service unavailable"
        });
    }
});

app.post("/api/admin/ban", adminOnly, async (req, res) => {
    const { gameId, installationId, reason } = req.body || {};

    if (!validGameId(gameId) ||
        !validId(installationId) ||
        typeof reason !== "string" ||
        reason.length > 300) {
        return res.status(400).json({ error: "Invalid request" });
    }

    try {
        await pool.query(
            `INSERT INTO device_bans
                (game_id, device_hash, reason)
             VALUES ($1, $2, $3)
             ON CONFLICT (game_id, device_hash)
             DO UPDATE SET reason = EXCLUDED.reason`,
            [gameId, hashDeviceId(installationId), reason]
        );

        res.json({ success: true });
    } catch (error) {
        console.error("Ban creation failed:", error.message);
        res.status(500).json({ error: "Could not create ban" });
    }
});

app.post("/api/admin/unban", adminOnly, async (req, res) => {
    const { gameId, installationId } = req.body || {};

    if (!validGameId(gameId) || !validId(installationId)) {
        return res.status(400).json({ error: "Invalid request" });
    }

    try {
        const result = await pool.query(
            `DELETE FROM device_bans
             WHERE game_id = $1 AND device_hash = $2`,
            [gameId, hashDeviceId(installationId)]
        );

        res.json({
            success: true,
            removed: result.rowCount > 0
        });
    } catch (error) {
        console.error("Unban failed:", error.message);
        res.status(500).json({ error: "Could not remove ban" });
    }
});

async function start() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS device_bans (
            game_id TEXT NOT NULL,
            device_hash TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (game_id, device_hash)
        )
    `);

    const port = process.env.PORT || 3000;

    app.listen(port, "0.0.0.0", () => {
        console.log("Device ban backend started on port " + port);
    });
}

start().catch(error => {
    console.error("Backend startup failed:", error);
    process.exit(1);
});
