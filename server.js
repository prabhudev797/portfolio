require("dotenv").config();

const express = require("express");
const fs = require("fs");
const path = require("path");
const cors = require("cors");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");

const app = express();

const PORT = process.env.PORT || 5000;
const MESSAGE_FILE = "messages.txt";

app.disable("x-powered-by");

// CORS Configuration
const allowedOrigin = process.env.FRONTEND_URL || "*";
app.use(cors({
    origin: allowedOrigin === "*" ? true : allowedOrigin,
    credentials: true
}));

// Body Parser (allow up to 10kb to support up to 1500 chars payload)
app.use(express.json({
    limit: "10kb"
}));

// Serve static frontend files (e.g. /confess and /messages)
app.use(express.static(path.join(__dirname)));
app.use("/confess", express.static(path.join(__dirname, "confess")));
app.use("/messages", express.static(path.join(__dirname, "messages")));

// Rate limiter for posting messages (10 requests per 15 minutes per IP)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15,
    message: {
        success: false,
        error: "Too many requests. Please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false
});

// Admin authentication middleware
function verifyAdmin(req, res, next) {
    const key = req.headers["x-admin-key"];
    const expectedKey = process.env.ADMIN_KEY || "admin123";

    if (!key || key !== expectedKey) {
        return res.status(401).json({
            success: false,
            error: "Unauthorized: Invalid or missing admin key."
        });
    }

    next();
}

// Generate a UUID
app.get("/get-uuid", (req, res) => {
    res.json({
        success: true,
        uuid: crypto.randomUUID()
    });
});

app.set("trust proxy", true);

const getClientIp = (req) => {
    const rawIp = (req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || req.socket.remoteAddress || "").split(",")[0].trim();
    return rawIp.replace(/^::ffff:/, ''); // Clean IPv4-mapped IPv6 addresses
};

// Submit anonymous message
app.post("/message", limiter, (req, res) => {
    const rawMessage = (req.body.message || "").trim();
    const clientIp = getClientIp(req);

    if (!rawMessage) {
        return res.status(400).json({
            success: false,
            error: "Message is required."
        });
    }

    if (rawMessage.length > 1500) {
        return res.status(400).json({
            success: false,
            error: "Maximum message length is 1500 characters."
        });
    }

    // Handle message splitting if between 1001 and 1500 characters
    if (rawMessage.length > 1000) {
        const midPoint = Math.ceil(rawMessage.length / 2);
        let splitIndex = rawMessage.indexOf(" ", midPoint);
        if (splitIndex === -1 || splitIndex > 1000) splitIndex = midPoint;

        const part1Text = rawMessage.substring(0, splitIndex).trim() + " (Part 1/2)";
        const part2Text = rawMessage.substring(splitIndex).trim() + " (Part 2/2)";

        const messageId = req.body.uuid || crypto.randomUUID();

        const entry1 = {
            id: messageId,
            time: new Date().toISOString(),
            ip: clientIp,
            message: part1Text
        };

        const entry2 = {
            id: messageId,
            time: new Date().toISOString(),
            ip: clientIp,
            message: part2Text
        };

        fs.appendFileSync(MESSAGE_FILE, JSON.stringify(entry1) + "\n");
        fs.appendFileSync(MESSAGE_FILE, JSON.stringify(entry2) + "\n");

        return res.json({
            success: true,
            message: "Message split into 2 parts and received successfully ❤️"
        });
    }

    // Standard message <= 1000 characters
    const entry = {
        id: req.body.uuid || crypto.randomUUID(),
        time: new Date().toISOString(),
        ip: clientIp,
        message: rawMessage
    };

    fs.appendFileSync(
        MESSAGE_FILE,
        JSON.stringify(entry) + "\n"
    );

    res.json({
        success: true,
        message: "Message received ❤️"
    });
});

// View all messages (Admin only)
app.get("/messages-data", verifyAdmin, (req, res) => {
    if (!fs.existsSync(MESSAGE_FILE)) {
        return res.json([]);
    }

    const messages = fs
        .readFileSync(MESSAGE_FILE, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => {
            try {
                return JSON.parse(line);
            } catch (e) {
                return null;
            }
        })
        .filter(Boolean)
        .reverse(); // Newest first

    res.json(messages);
});

// GET /messages Endpoint - supports both API request (with x-admin-key header) or HTML page serving
app.get("/messages", (req, res) => {
    // If request asks for JSON or sends x-admin-key, handle as API endpoint
    if (req.headers["x-admin-key"] || req.headers["accept"]?.includes("application/json")) {
        return verifyAdmin(req, res, () => {
            if (!fs.existsSync(MESSAGE_FILE)) {
                return res.json([]);
            }

            const messages = fs
                .readFileSync(MESSAGE_FILE, "utf8")
                .split("\n")
                .filter(Boolean)
                .map((line) => {
                    try {
                        return JSON.parse(line);
                    } catch (e) {
                        return null;
                    }
                })
                .filter(Boolean)
                .reverse();

            res.json(messages);
        });
    }

    // Otherwise serve the HTML dashboard page
    res.sendFile(path.join(__dirname, "messages", "index.html"));
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`- Confession page: http://localhost:${PORT}/confess`);
    console.log(`- Admin messages vault: http://localhost:${PORT}/messages`);
});
