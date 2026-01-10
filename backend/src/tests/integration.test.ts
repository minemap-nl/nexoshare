
import { describe, expect, test, beforeAll, afterAll } from "bun:test";
import path from "path";
import fs from "fs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { Pool } from "pg";

// Load environment variables from backend/.env
dotenv.config({ path: path.join(__dirname, "../../.env") });

const PORT = 3001; // Force 3001 for tests
const BASE_URL = `http://localhost:${PORT}/api`;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    console.error("UNKNOWN JWT_SECRET. Cannot run integration tests.");
    process.exit(1);
}

// Global variables for test context
let adminToken: string;
let dbPool: Pool;
let serverProc: any;
let shareId: string;

describe("Integration: File Upload Flow", () => {
    const fileId = "test-file-" + Date.now();
    const fileName = "integration_test.txt";
    const contentPart1 = "Hello ";
    const contentPart2 = "Integration World!";
    const fullContent = contentPart1 + contentPart2;
    const fileSize = Buffer.byteLength(fullContent);

    beforeAll(async () => {
        // 1. Connect to DB to get a real user (prevents audit log FK errors)
        dbPool = new Pool({
            host: process.env.DB_HOST || 'localhost',
            port: parseInt(process.env.DB_PORT || '5432'),
            database: process.env.DB_NAME || 'Nexo Share',
            user: process.env.DB_USER || 'postgres',
            password: process.env.DB_PASSWORD
        });

        const userRes = await dbPool.query("SELECT id, email FROM users LIMIT 1");
        let user;

        if (userRes.rows.length === 0) {
            // Create a temp user if none exist
            const hash = "$2b$10$abcdefghijklmnopqrstuv"; // dummy hash
            const insert = await dbPool.query(
                "INSERT INTO users (email, name, password_hash, is_admin) VALUES ($1, $2, $3, $4) RETURNING id, email",
                ["test@example.com", "Test User", hash, true]
            );
            user = insert.rows[0];
        } else {
            user = userRes.rows[0];
        }

        // 2. Sign token with REAL user ID
        adminToken = jwt.sign(
            { id: user.id, email: user.email, isAdmin: true },
            JWT_SECRET,
            { expiresIn: "1h" }
        );
        console.log(`Using Test User ID: ${user.id}`);


        // 3. Start the server
        console.log("Starting backend server for testing...");
        serverProc = Bun.spawn(["bun", "src/index.ts"], {
            cwd: path.join(__dirname, "../../"),
            env: { ...process.env, PORT: String(PORT) },
            stdout: "ignore", // "inherit" for debug
            stderr: "inherit"
        });

        // Wait for server to be ready
        let retries = 20;
        while (retries > 0) {
            try {
                const res = await fetch(`http://localhost:${PORT}/api/public/shares/000`); // Just check if port is open
                if (res.status !== 500) break;
            } catch (e) {
                // Ignore connection error
            }
            await new Promise(r => setTimeout(r, 500));
            retries--;
        }
        if (retries === 0) {
            console.error("Server failed to start in time.");
            serverProc.kill();
            process.exit(1);
        }
        console.log("Server is up!");
    });

    afterAll(async () => {
        if (serverProc) {
            console.log("Stopping test server...");
            serverProc.kill();
        }
        if (dbPool) await dbPool.end();
    });

    test("POST /shares/init - Create a new share", async () => {
        const res = await fetch(`${BASE_URL}/shares/init`, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${adminToken}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                name: "Integration Test Share",
                expiration: "1", // 1 day
                files: []
            })
        });

        expect(res.status).toBe(200);
        const data = await res.json();
        expect(data.success).toBe(true);
        expect(data.shareId).toBeDefined();
        shareId = data.shareId;
        console.log("Created Share ID:", shareId);
    });

    test("POST /shares/:id/chunk - Upload Chunk", async () => {
        const formData = new FormData();
        formData.append("chunk", new Blob([fullContent]), "chunk0");
        formData.append("chunkIndex", "0");
        formData.append("totalChunks", "1");
        formData.append("fileName", fileName);
        formData.append("fileId", fileId);

        const res = await fetch(`${BASE_URL}/shares/${shareId}/chunk`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${adminToken}` },
            body: formData
        });
        expect(res.status).toBe(200);
    });

    test("POST /shares/:id/finalize - Finalize Upload", async () => {
        const payload = {
            files: [{
                fileName: fileName,
                originalName: fileName, // Frontend sends this
                fileId: fileId,
                size: fileSize,
                mimeType: "text/plain"
            }]
        };

        const res = await fetch(`${BASE_URL}/shares/${shareId}/finalize`, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${adminToken}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });

        if (res.status !== 200) {
            console.error("Finalize Error:", await res.text());
        }
        expect(res.status).toBe(200);
        const data = await res.json();
        expect(data.success).toBe(true);
    });

    test("GET /shares/:id/files/:fileId - Verify Content", async () => {
        // First, we need to get the LIST of files to find the generated internal ID (or use the one we sent if backend keeps it?)
        // Backend generates a new database ID or uses fileId?
        // Wait, the API for download is /shares/:id/files/:fileId
        // The backend `finalize` inserts into `files`. The `files` table is queried by `GET /public/shares/:id` to get list.
        // Or if we are owner (which we are), `GET /shares/:id/files`? Note: API structure might differ.
        // Let's use the public endpoint to list files and find ours.
        // Route: `apiRouter.get('/public/shares/:id', ...)`

        const listRes = await fetch(`${BASE_URL}/public/shares/${shareId}`);
        expect(listRes.status).toBe(200);
        const shareData = await listRes.json();

        expect(shareData.files).toBeDefined();
        expect(shareData.files.length).toBeGreaterThan(0);
        const fileRecord = shareData.files.find((f: any) => f.original_name === fileName);
        expect(fileRecord).toBeDefined();

        // Download using the DB ID
        const dbFileId = fileRecord.id;
        const downloadRes = await fetch(`${BASE_URL}/shares/${shareId}/files/${dbFileId}`, {
            headers: { "Authorization": `Bearer ${adminToken}` }
        });

        expect(downloadRes.status).toBe(200);
        const text = await downloadRes.text();
        expect(text).toBe(fullContent);
    });

    test("DELETE /shares/:id - Cleanup", async () => {
        const res = await fetch(`${BASE_URL}/shares/${shareId}`, {
            method: "DELETE",
            headers: { "Authorization": `Bearer ${adminToken}` }
        });
        expect(res.status).toBe(200);
        const data = await res.json();
        expect(data.success).toBe(true);
        console.log(`cleaned up share ${shareId}`);
    });
});
