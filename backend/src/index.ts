import express, { Request, Response, RequestHandler, NextFunction } from 'express';
import { Pool } from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import cors from 'cors';
import nodemailer from 'nodemailer';
import archiver from 'archiver';
import crypto from 'crypto';
import { promises as fs } from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import axios from 'axios';
import { z } from 'zod';
import cron from 'node-cron';
import NodeClam from 'clamscan';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse
} from '@simplewebauthn/server';
import validator from 'validator';

dotenv.config();

// Validation Schemas
const reverseShareSchema = z.object({
    name: z.string().max(255).optional(),
    maxSize: z.number().positive().max(1000000000000),
    expirationVal: z.number().nonnegative().optional(),
    expirationUnit: z.string().optional(),
    password: z.string().max(255).optional(),
    notify: z.boolean(),
    sendEmailTo: z.string().email('Invalid email address').optional().or(z.literal('')),
    thankYouMessage: z.string().max(1000).optional(),
    customSlug: z.string().max(50).optional()
});

const shareCreateSchema = z.object({
    name: z.string().max(255).optional(),
    password: z.string().max(255).optional(),
    expiration: z.string().regex(/^\d+$/, 'Expiration must be a number').optional(),
    recipients: z.string().max(2000).optional(),
    message: z.string().max(5000).optional(),
    customSlug: z.string().max(50).optional()
});

const userCreateSchema = z.object({
    email: z.string().email('Invalid email address').max(255),
    password: z.string().min(8, 'Password must be at least 8 characters').max(128),
    name: z.string().min(1, 'Name is required').max(255),
    is_admin: z.boolean()
});

// --- Helper: Bepaal de publieke URL ---
const getBaseUrl = (config: any, req?: Request): string => {
    // Vertrouw NOOIT de Origin header voor het genereren van emails/links.
    // 1. Gebruik altijd de geconfigureerde URL indien beschikbaar.
    if (config.appUrl && config.appUrl.trim() !== '') {
        return config.appUrl.replace(/\/$/, '');
    }

    // 2. Fallback: Gebruik de Host header (veiliger dan Origin, mits achter een goede proxy).
    // We gebruiken req.protocol en req.get('host') wat standaard Express gedrag is.
    if (req) {
        const protocol = req.protocol; 
        const host = req.get('host'); 
        return `${protocol}://${host}`;
    }

    return 'http://localhost:3000'; // Veilige fallback als alles faalt
};

// --- Types ---
interface JWTPayload { id: number; email: string; isAdmin: boolean; }
interface AuthRequest extends Request { user?: JWTPayload; uploadId?: string; }

// --- Config Defaults ---
const app = express();
const PORT = parseInt(process.env.PORT || '3001');
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || './uploads');
const pendingUploads = new Map<string, number>(); // Track pending bytes per share ID
const TEMP_DIR = path.join(UPLOAD_DIR, 'temp');
const SYSTEM_DIR = path.join(UPLOAD_DIR, 'system'); // Veilige map voor systeem assets

// Zorg dat mappen bestaan
fs.mkdir(TEMP_DIR, { recursive: true }).catch(() => {});
fs.mkdir(SYSTEM_DIR, { recursive: true }).catch(() => {});
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET === 'dev-secret-change-me') {
    console.error('❌ CRITICAL: JWT_SECRET must be set in environment variables!');
    console.error('Generate one with: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"');
    process.exit(1);
}

fs.mkdir(TEMP_DIR, { recursive: true }).catch(() => {});

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'Nexo share',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  query_timeout: 10000, // 10 Seconds max per query
  statement_timeout: 10000,
  ssl: process.env.DB_SSL === 'true' ? {
    rejectUnauthorized: false
  } : false
});

// Error handling voor database pool
pool.on('error', (err) => {
    console.error('⚠️ Onverwachte database pool error:', err);
});

const CLAMAV_HOST = process.env.CLAMAV_HOST || 'clamav';
const CLAMAV_PORT = parseInt(process.env.CLAMAV_PORT || '3310');
// WebAuthn Configuration
const RP_NAME = 'Nexo share';
const RP_ID = process.env.RP_ID || 'localhost';
const ORIGIN = process.env.ORIGIN || 'http://localhost:5173';

let clamscanInstance: any = null;

new NodeClam().init({
    removeInfected: true,
    quarantineInfected: false,
    debugMode: false,
    clamdscan: {
        host: CLAMAV_HOST,
        port: CLAMAV_PORT,
        timeout: 60000,
        active: true
    },
    preference: 'clamdscan'
}).then((instance: any) => {
    clamscanInstance = instance;
    console.log("✅ ClamAV is active and connected.");
}).catch((err: any) => {
    console.warn("⚠️ ClamAV is not found or can't connect:", err.message);
    console.warn("   Virusscanning is turned off.");
});

const isPrivateIP = (host: string) => {
    // 0. Blokkeer vreemde formaten (Hex, Octal, Integer IPs)
    if (!/^[a-zA-Z0-9.:-]+$/.test(host)) return true;

    // 1. Blokkeer Cloud Metadata Services (Kritiek voor AWS/Azure/GCP)
    if (host === '169.254.169.254') return true;
    if (host.toLowerCase().startsWith('fe80:')) return true;
    if (host.toLowerCase().includes('fd00:ec2')) return true;

    // 2. Localhost & Standaard Private Ranges
    if (host === 'localhost') return true;
    if (host === '0.0.0.0') return true;
    if (host === '::1') return true; // IPv6 localhost
    if (host === '::') return true;

    // IPv4 Private Ranges
    if (host.startsWith('127.')) return true;
    if (host.startsWith('10.')) return true;
    if (host.startsWith('192.168.')) return true;
    if (host.startsWith('169.254.')) return true; // Link-local IPv4

    // Class B (172.16.0.0 - 172.31.255.255)
    if (host.startsWith('172.')) {
        const parts = host.split('.');
        if (parts.length > 1) {
            const second = parseInt(parts[1], 10);
            if (second >= 16 && second <= 31) return true;
        }
    }

    // IPv6 Private Ranges (Unique Local Address)
    if (host.toLowerCase().startsWith('fc') || host.toLowerCase().startsWith('fd')) return true;

    return false;
};

// --- Cronjob (Idee 1) ---
// Draait elk uur op minuut 0 om verlopen shares op te ruimen
cron.schedule('0 * * * *', async () => {
    console.log('🧹 Start automatische opruiming...');
    const client = await pool.connect();
    try {
        // 1. Zoek verlopen shares
        const res = await client.query(`SELECT id FROM shares WHERE expires_at IS NOT NULL AND expires_at < NOW()`);
        
        for (const row of res.rows) {
            const sharePath = path.join(UPLOAD_DIR, row.id);
            // Verwijder fysieke map
            await fs.rm(sharePath, { recursive: true, force: true }).catch(() => {});
            console.log(`Expired share deleted from disk: ${row.id}`);
        }

        // 2. Verwijder uit database (Cascade verwijdert ook de file-records)
        await client.query(`DELETE FROM shares WHERE expires_at IS NOT NULL AND expires_at < NOW()`);
        
        // 3. Zelfde voor reverse shares (hoewel die vaak geen map hebben, maar wel records)
        await client.query(`DELETE FROM reverse_shares WHERE expires_at IS NOT NULL AND expires_at < NOW()`);
        
        // 4. Cleanup sso tokens
        await pool.query('DELETE FROM sso_tokens WHERE expires_at < NOW()');

        // 5. Cleanup oude audit logs (ouder dan 1 jaar bewaren is meestal genoeg)
        await pool.query("DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '1 year'");

        console.log('✅ Opruiming voltooid.');
    } catch (e) {
        console.error('❌ Fout bij opruiming:', e);
    } finally {
        client.release();
    }
});

const cleanupOrphanedFolders = async () => {
    console.log('🧹 Start controle op wees-mappen...');
    try {
        // 1. Haal alle mapnamen op uit de uploads folder
        const dirents = await fs.readdir(UPLOAD_DIR, { withFileTypes: true });
        const folders = dirents
            // VOEG HIER JE MAP TOE AAN DE UITZONDERINGEN:
            .filter(dirent => 
                dirent.isDirectory() && 
                dirent.name !== 'temp' && 
                dirent.name !== 'guest_uploads' &&
                dirent.name !== 'system'
            ) 
            .map(dirent => dirent.name);

        if (folders.length === 0) return;

        // 2. Haal alle actieve share ID's op uit de database
        const dbResult = await pool.query('SELECT id FROM shares');
        const activeIds = new Set(dbResult.rows.map(row => row.id));

        // 3. Vergelijk en verwijder mappen die niet in de DB staan
        for (const folderId of folders) {
            // Check of het een geldig ID formaat is (om systeemmappen te sparen)
            // Aanname: ID's zijn hex strings of slugs. Pas regex aan indien nodig.
            if (!activeIds.has(folderId)) {
                console.log(`🗑️ Wees-map gevonden en verwijderd: ${folderId}`);
                await fs.rm(path.join(UPLOAD_DIR, folderId), { recursive: true, force: true });
            }
        }
    } catch (e) {
        console.error('❌ Fout bij orphan cleanup:', e);
    }
};

// Voeg deze functie toe bij de andere helpers (bijv. onder cleanupOrphanedFolders)
const cleanupOrphanedGuestFiles = async () => {
    console.log('🧹 Start checking for orphan files in guest_uploads...');
    const guestDir = path.join(UPLOAD_DIR, 'guest_uploads');
    try {
        // Check of map bestaat
        await fs.access(guestDir);
        
        const filesOnDisk = await fs.readdir(guestDir);
        if (filesOnDisk.length === 0) return;

        // Haal alle bekende paden op uit de DB die in guest_uploads staan
        // We zoeken op storage_path die 'guest_uploads' bevatten
        const dbResult = await pool.query("SELECT storage_path FROM files WHERE storage_path LIKE '%guest_uploads%'");
        
        // Maak een Set van bestandsnamen (alleen de bestandsnaam, niet het hele pad)
        const knownFiles = new Set(dbResult.rows.map(row => path.basename(row.storage_path)));

        let cleaned = 0;
        for (const file of filesOnDisk) {
            // Als bestand op schijf staat, maar NIET in de DB
            if (!knownFiles.has(file)) {
                const filePath = path.join(guestDir, file);
                try {
                    const stats = await fs.stat(filePath);
                    // Check leeftijd (1 uur) om race conditions te voorkomen
                    if (Date.now() - stats.mtimeMs > 3600000) {
                        await fs.unlink(filePath).catch(() => {});
                        cleaned++;
                    }
                } catch (e) { }
            }
        }
        if (cleaned > 0) console.log(`🗑️ ${cleaned} orphaned guest files removed.`);
    } catch (e) {
        // Map bestaat misschien niet of andere error, geen ramp
    }
};

const cleanupOrphanedShareFiles = async () => {
    // Deze functie scant actieve share mappen op bestanden die niet in de DB staan
    console.log('🧹 Start checking for orphan files in shares...');
    try {
        const shareDirs = (await fs.readdir(UPLOAD_DIR, { withFileTypes: true }))
            .filter(dirent => dirent.isDirectory() && !['temp', 'system', 'guest_uploads'].includes(dirent.name))
            .map(dirent => dirent.name);

        for (const shareId of shareDirs) {
            const dirPath = path.join(UPLOAD_DIR, shareId);
            const filesOnDisk = await fs.readdir(dirPath);
            if (filesOnDisk.length === 0) continue;

            // Haal bekende bestanden voor deze share op uit DB
            const dbRes = await pool.query('SELECT storage_path FROM files WHERE share_id = $1', [shareId]);
            const knownFiles = new Set(dbRes.rows.map(row => path.basename(row.storage_path)));

            for (const file of filesOnDisk) {
                if (!knownFiles.has(file)) {
                    const filePath = path.join(dirPath, file);
                    try {
                        const stats = await fs.stat(filePath);
                        // Alleen verwijderen als ouder dan 1 uur (zodat we geen actieve uploads killen)
                        if (Date.now() - stats.mtimeMs > 3600000) {
                            await fs.unlink(filePath).catch(() => {});
                            console.log(`🗑️ Wees-bestand verwijderd uit share ${shareId}: ${file}`);
                        }
                    } catch (e) {}
                }
            }
        }
    } catch (e) {
        console.error('Fout bij share file cleanup:', e);
    }
};

// Voeg toe aan je bestaande cron (elk uur):
cron.schedule('0 * * * *', async () => {
    // ... je bestaande logica ...
    await cleanupOrphanedFolders();
    await cleanupOrphanedGuestFiles();
    await cleanupOrphanedShareFiles();
});

// Cleanup tijdelijke bestanden: Elke 15 Minutes draaien
cron.schedule('*/15 * * * *', async () => {
    console.log('🧹 Start cleaning up temporary files...');
    try {
        const files = await fs.readdir(TEMP_DIR);
        const now = Date.now();
        
        // Agressievere cleanup: bestanden ouder dan 30 Minutes verwijderen
        // Zolang een upload bezig is, update de 'mtime' en wordt hij niet verwijderd.
        const maxAge = 30 * 60 * 1000;
        
        let deletedCount = 0;
        for (const file of files) {
            try {
                const filePath = path.join(TEMP_DIR, file);
                const stats = await fs.stat(filePath);
                
                // Als bestand ouder is dan 1 uur
                if (now - stats.mtimeMs > maxAge) {
                    await fs.unlink(filePath);
                    deletedCount++;
                }
            } catch (e) {
                // Bestand misschien al weg of locked, negeren
            }
        }
        if (deletedCount > 0) console.log(`✅ Temp cleanup: ${deletedCount} vastgelopen uploads verwijderd.`);
    } catch (e) {
        console.error('❌ Fout bij temp cleanup:', e);
    }
});

// Proxy trust voor Secure Cookies & Rate Limiting achter Synology/Nginx
app.set('trust proxy', 1);

// CORS Configuration
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:5173').split(',').map(o => o.trim());

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (mobile apps, Postman, etc.)
        if (!origin) return callback(null, true);
        
        if (ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            console.warn(`CORS blocked origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
// --- SECURITY HEADERS MIDDLEWARE ---
app.use((req, res, next) => {
    // 1. HSTS (HTTP Strict Transport Security)
    // Forceer HTTPS in productie. Voorkomt downgrade attacks.
    // We checken NODE_ENV of dat het verzoek secure is (via proxy).
    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    if (process.env.NODE_ENV === 'production' && isSecure) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }

    // 2. Anti-Clickjacking
    // Voorkomt dat jouw site in een iframe op een andere site wordt geladen.
    res.setHeader('X-Frame-Options', 'DENY'); 
    
    // 3. MIME-type sniffing preventie
    // Zorgt dat browsers bestanden niet als een ander type interpreteren (bijv. plaatje als script).
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // 4. Referrer Policy
    // 'strict-origin-when-cross-origin' is veilig voor privacy maar houdt analytics werkend.
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    // 5. Content Security Policy (CSP) - DE KRITISCHE BALANS
    // Dit is het beleid dat bepaalt wat mag laden.
    const cspDirectives = [
        "default-src 'self'", // Standaard: alleen dingen van eigen domein laden
        
        // SCRIPTS: Sta eigen scripts toe. 'unsafe-inline' is vaak nodig voor React/Vite in sommige setups.
        // Als je heel strikt wilt zijn, haal je 'unsafe-inline' weg, maar test dan goed!
        "script-src 'self' 'unsafe-inline'", 
        
        // STYLES: 'unsafe-inline' is nodig voor veel CSS-in-JS libraries en inline styles in React.
        "style-src 'self' 'unsafe-inline'",
        
        // AFBEELDINGEN: 
        // We staan 'data:' toe (base64) en 'blob:' (previews).
        // We staan 'https:' toe zodat externe logo URL's (van klanten/config) ALTIJD werken.
        "img-src 'self' data: blob: https:", 
        
        // CONNECT (API & Fetch):
        // 'self' zorgt dat de frontend altijd met de eigen backend mag praten.
        // SSO redirects gebeHours via navigatie, dus die vallen hier niet onder (dat breekt niet).
        "connect-src 'self'", 
        
        // FONTS:
        "font-src 'self' data:",
        
        // OBJECTS: Blokkeer flash/java plugins volledig
        "object-src 'none'",
        
        // BASE: Voorkomt <base> tag hijacking
        "base-uri 'self'",
        
        // FORMS: Zorgt dat formulieren alleen naar eigen domein of veilige doelen mogen posten.
        // SSO Logins via POST kunnen hier 'https:' nodig hebben, maar meestal is SSO een redirect (GET).
        "form-action 'self' https:" 
    ];

    res.setHeader('Content-Security-Policy', cspDirectives.join('; '));

    next();
});
app.use(express.json());

// --- Security: Simple In-Memory Rate Limiter ---
const createRateLimiter = (windowMs: number, max: number, message: string) => {
    const requests = new Map<string, number[]>();
    
    // Cleanup met beter interval management
    const cleanupInterval = setInterval(() => {
        const now = Date.now();
        const cutoff = now - windowMs;
        
        for (const [ip, timestamps] of requests.entries()) {
            const valid = timestamps.filter(t => t > cutoff);
            if (valid.length === 0) {
                requests.delete(ip);
            } else {
                requests.set(ip, valid);
            }
        }
    }, Math.min(windowMs, 60000)); // Max 1 minuut interval voor efficiency
    
    // Cleanup bij process shutdown
    process.on('SIGTERM', () => clearInterval(cleanupInterval));
    process.on('SIGINT', () => clearInterval(cleanupInterval)); // Cleanup interval gelijk aan window

    return (req: Request, res: Response, next: NextFunction) => {
        const ip = getClientIP(req);
        const now = Date.now();
        
        let timestamps = requests.get(ip) || [];
        timestamps = timestamps.filter(t => t > now - windowMs);
        
        if (timestamps.length >= max) {
            return res.status(429).json({ error: message });
        }
        
        timestamps.push(now);
        requests.set(ip, timestamps);
        next();
    };
};

// Initialiseer limiters
const loginLimiter = createRateLimiter(15 * 60 * 1000, 5, "Too many login attempts. Please try again in 15 minutes.");
const passwordResetLimiter = createRateLimiter(60 * 60 * 1000, 3, "Too many reset requests. Please try again in 1 hour.");
// Verhoogd naar 10.000 om grote bestanden (veel chunks) toe te staan. 10.000 chunks * 50MB = 500GB max per uur.
const uploadLimiter = createRateLimiter(60 * 60 * 1000, 10000, "Upload request limit reached for this IP.");
const downloadLimiter = createRateLimiter(60 * 60 * 1000, 100, "Too many downloads. Please try again later.");

// --- Utility Functions ---

// Simple Async Queue om CPU spikes door ZIPs te voorkomen
class AsyncQueue {
    private running = 0;
    private queue: Array<(value: unknown) => void> = [];
    constructor(private maxConcurrent: number) {}

    async wait(): Promise<void> {
        if (this.running >= this.maxConcurrent) {
            await new Promise(resolve => this.queue.push(resolve));
        }
        this.running++;
    }

    release(): void {
        this.running--;
        if (this.queue.length > 0) {
            const next = this.queue.shift();
            if (next) next(null);
        }
    }
}
// Maximaal 2 gelijktijdige zips genereren
const zipQueue = new AsyncQueue(10);

const sanitizeFilename = (name: string) => {
    if (!name) return 'unnamed_file';
    // Prevent reserved names
    if (/^(con|prn|aux|nul|com\d|lpt\d)$/i.test(name.split('.')[0])) {
        return '_' + name;
    }
    // Sta ook spaties (\s) en haakjes () toe, dat oogt vriendelijker
    return name.replace(/[^a-zA-Z0-9._\-\s\(\)]/g, '_');
};

const formatBytes = (bytes: number, decimals = 2) => {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
};

const getTimeInMs = (val: number, unit: string) => {
    const u = unit.toLowerCase();
    const map: any = {
        'minute': 60000,  'minutes': 60000,
        'hour': 3600000,  'hours': 3600000,
        'day': 86400000,  'days': 86400000,
        'week': 604800000, 'weeks': 604800000,
        'month': 2592000000, 'months': 2592000000,
        'year': 31536000000, 'years': 31536000000
    };
    return val * (map[u] || 86400000);
};

const getBytes = (val: number, unit: string) => {
    const k = 1024;
    const map: any = { 'B': 1, 'KB': k, 'KiB': 1024, 'MB': k*k, 'MiB': 1024*1024, 'GB': k*k*k, 'GiB': 1024*1024*1024, 'TB': k*k*k*k, 'TiB': 1024*1024*1024*1024 };
    return val * (map[unit] || k*k*k);
};

// --- Global Cache Variables ---
let configCache: any = null;
let configCacheTime = 0;

async function getConfig() {
    // Return cache als deze jonger is dan 10 Seconds (10000ms)
    if (configCache && Date.now() - configCacheTime < 10000) {
        return configCache;
    }

    try {
        const res = await pool.query('SELECT data, setup_completed FROM config WHERE id = 1');
        
        const defaults = {
            appName: 'Nexo share',
            appUrl: 'http://localhost:3000',
            sessionVal: 7, sessionUnit: 'Days',
            secureCookies: false,
            shareIdLength: 12,
            maxSizeVal: 10, maxSizeUnit: 'GB',
            defaultExpirationVal: 1, defaultExpirationUnit: 'Weeks',
            maxExpirationVal: 0, maxExpirationUnit: 'Months',
            zipLevel: 5, zipNoMedia: true,
            smtpSecure: true, smtpStartTls: false,
            smtpAllowLocal: false,
            ssoAutoRedirect: false,
            ssoLogoutUrl: '',
            faviconUrl: '',
            require2FA: false,
            allowPasskeys: true,
            allowPasswordReset: true,
            appLocale: process.env.APP_LOCALE || 'en-GB', 
            serverTimezone: process.env.TZ || 'UTC'
        };

        let finalConfig = defaults;

        // Check if DB has data
        if (res && res.rows && res.rows.length > 0) {
            finalConfig = { 
                ...defaults, 
                ...(res.rows[0].data || {}), 
                setupCompleted: res.rows[0].setup_completed || false
            };
        }
        
        // Update Cache
        configCache = finalConfig;
        configCacheTime = Date.now();
        
        return finalConfig;
    } catch (e) {
        console.error("GetConfig Error:", e);
        return {}; 
    }
}

const generateSecureId = async () => {
    const config = await getConfig();
    const len = Math.max(8, parseInt(config.shareIdLength) || 12);
    return crypto.randomBytes(Math.ceil(len/2)).toString('hex').slice(0, len);
};

const escapeHtml = (unsafe: string) => {
    if (!unsafe) return "";
    return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
 };

const sanitizeEmailHeader = (input: string): string => {
    if (!input) return "";
    // Verwijder newlines, carriage returns en null bytes (Email Header Injection preventie)
    return input.replace(/[\r\n\0]/g, '').substring(0, 200);
};

const cleanUrl = (url: string) => url ? url.replace(/\/$/, '') : '';

// Safe IP extraction helper
const getClientIP = (req: Request): string => {
    if (req.app.get('trust proxy')) {
        const forwarded = req.headers['x-forwarded-for'];
        if (typeof forwarded === 'string') {
            return forwarded.split(',')[0].trim();
        }
        if (Array.isArray(forwarded)) {
            return forwarded[0];
        }
    }
    return req.ip || 'unknown';
};

const isValidAppUrl = (url: string): boolean => {
    if (!url) return false;
    try {
        const parsed = new URL(url);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
        return false;
    }
};

const isValidEmail = (email: string): boolean => {
    return validator.isEmail(email, { 
        allow_utf8_local_part: false,
        require_tld: true 
    });
};

const validateAndSplitEmails = (emailString: string): string[] => {
    if (!emailString) return [];
    const emails = emailString.split(',').map(e => e.trim()).filter(e => e.length > 0);
    return emails.filter(email => {
        if (!isValidEmail(email)) {
            console.warn(`Invalid email filtered: ${email}`);
            return false;
        }
        return true;
    });
};

// Generate readable backup codes (6 groups of 4 characters)
const generateBackupCodes = (): string[] => {
    const codes = [];
    for (let i = 0; i < 8; i++) {
        const code = crypto.randomBytes(3).toString('hex').toUpperCase().match(/.{1,4}/g)?.join('-') || '';
        codes.push(code);
    }
    return codes;
};

// Encrypt sensitive data (for TOTP secrets and backup codes)
const encryptData = (data: string): string => {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(JWT_SECRET, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    
    return `${iv.toString('hex')}:${authTag}:${encrypted}`;
};

const decryptData = (encryptedData: string): string => {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(JWT_SECRET, 'salt', 32);
    const [ivHex, authTagHex, encrypted] = encryptedData.split(':');
    
    const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
};

const isStrongPassword = (password: string): { valid: boolean; error?: string } => {
    if (!password || typeof password !== 'string') {
        return { valid: false, error: 'Password is required' };
    }
    if (password.length > 128) {
        return { valid: false, error: 'Password cannot exceed 128 characters' };
    }
    if (password.length < 8) {
        return { valid: false, error: 'Password must be at least 8 characters' };
    }
    if (!/[a-z]/.test(password)) {
        return { valid: false, error: 'Password must contain at least one lowercase letter' };
    }
    if (!/[A-Z]/.test(password)) {
        return { valid: false, error: 'Password must contain at least one uppercase letter' };
    }
    if (!/[0-9]/.test(password)) {
        return { valid: false, error: 'Password must contain at least one number' };
    }
    return { valid: true };
};

async function sendEmail(to: string, subject: string, rawMessage: string, ctaLink?: string, ctaText?: string) {
    const config = await getConfig();
    if (!config.smtpHost) return;
    if (!isValidEmail(to)) {
        console.error(`Blocked email send to invalid address: ${to}`);
        return;
    }

    const safeMessage = rawMessage;
    const safeSubject = sanitizeEmailHeader(subject);

    try {
        const transporter = nodemailer.createTransport({
            host: config.smtpHost,
            port: parseInt(config.smtpPort) || 465,
            secure: config.smtpSecure || false,
            auth: { user: config.smtpUser, pass: config.smtpPass },
            tls: { rejectUnauthorized: false }
        });

        const appName = config.appName || 'Nexo share';
        // Sanitize de naam voor gebruik in headers om injection te voorkomen
        const safeHeaderAppName = sanitizeEmailHeader(appName);
        const safeAppName = escapeHtml(appName);
        let safeLink = '#';
        if (ctaLink && (ctaLink.startsWith('http://') || ctaLink.startsWith('https://'))) safeLink = ctaLink;

        const logoHtml = config.logoUrl 
            ? `<img src="${config.logoUrl}" alt="${safeAppName}" style="display: block; margin: 0 auto; max-height: 50px; border: 0; outline: none; text-decoration: none;">` 
            : `<h1 style="margin: 0; color: #7c3aed; font-size: 24px; font-weight: bold; text-align: center;">${safeAppName}</h1>`;

        const buttonHtml = ctaLink ? `
            <table role="presentation" border="0" cellpadding="0" cellspacing="0" class="btn btn-primary" style="margin-top: 20px; width: 100%;">
            <tbody><tr><td align="center"><table role="presentation" border="0" cellpadding="0" cellspacing="0"><tbody><tr><td> <a href="${safeLink}" target="_blank" style="background-color: #7c3aed; border: solid 1px #7c3aed; border-radius: 8px; box-sizing: border-box; color: #ffffff; cursor: pointer; display: inline-block; font-size: 16px; font-weight: bold; margin: 0; padding: 12px 30px; text-decoration: none; text-transform: capitalize;">${escapeHtml(ctaText || 'View')}</a> </td></tr></tbody></table></td></tr></tbody>
            </table>` : '';

        const html = `<!DOCTYPE html><html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"><style>@media only screen and (max-width: 620px) {table.body h1 { font-size: 28px !important; margin-bottom: 10px !important; } table.body p, table.body ul, table.body ol, table.body td, table.body span, table.body a { font-size: 16px !important; } table.body .wrapper, table.body .article { padding: 10px !important; } table.body .content { padding: 0 !important; } table.body .container { padding: 0 !important; width: 100% !important; } table.body .main { border-left-width: 0 !important; border-radius: 0 !important; border-right-width: 0 !important; }} @media (prefers-color-scheme: dark) { body { background-color: #1f2937 !important; color: #ffffff !important; } .email-container { background-color: #111827 !important; border: 1px solid #374151 !important; } h1, h2, h3, p, span, td { color: #f3f4f6 !important; } .content-block { background-color: #1f2937 !important; } .message-box { background-color: #374151 !important; color: #e5e7eb !important; border-left: 4px solid #8b5cf6 !important; } }</style></head><body style="background-color: #f3f4f6; font-family: sans-serif; -webkit-font-smoothing: antialiased; font-size: 14px; line-height: 1.4; margin: 0; padding: 0; -ms-text-size-adjust: 100%; -webkit-text-size-adjust: 100%;"><table role="presentation" border="0" cellpadding="0" cellspacing="0" class="body" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; background-color: #f3f4f6; width: 100%;"><tr><td>&nbsp;</td><td class="container" style="display: block; margin: 0 auto !important; max-width: 580px; padding: 10px; width: 580px;"><div class="content" style="box-sizing: border-box; display: block; margin: 0 auto; max-width: 580px; padding: 10px;"><table role="presentation" class="main email-container" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; background: #ffffff; border-radius: 12px; width: 100%; box-shadow: 0 4px 6px rgba(0,0,0,0.05);"><tr><td class="wrapper" style="font-family: sans-serif; font-size: 14px; vertical-align: top; box-sizing: border-box; padding: 40px;"><table role="presentation" border="0" cellpadding="0" cellspacing="0" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%;"><tr><td style="font-family: sans-serif; font-size: 14px; vertical-align: top; text-align: center;">${logoHtml}<h2 style="color: #1f2937; margin: 20px 0 10px 0; font-size: 24px;">${safeSubject}</h2><div style="text-align: left; width: 100%;">${safeMessage}</div>${buttonHtml}</td></tr></table></td></tr></table><div class="footer" style="clear: both; margin-top: 10px; text-align: center; width: 100%;"><table role="presentation" border="0" cellpadding="0" cellspacing="0" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%;"><tr><td class="content-block" style="font-family: sans-serif; vertical-align: top; padding-bottom: 10px; padding-top: 10px; color: #9ca3af; font-size: 12px; text-align: center;"><span class="apple-link" style="color: #9ca3af; font-size: 12px; text-align: center;">Sent via ${safeAppName}</span></td></tr></table></div></div></td><td>&nbsp;</td></tr></table></body></html>`;

        // Gebruik smtpFrom als die is ingesteld, anders smtpUser
        const fromEmail = config.smtpFrom || config.smtpUser;
        await transporter.sendMail({ from: `"${safeHeaderAppName}" <${fromEmail}>`, to, subject, html });
    } catch (e: any) {
        // Log the SPECIFIC error to the server console so you can see it
        console.error("❌ SMTP SEND ERROR:", e.message);
        throw e; // Rethrow so the 500 triggers (but now you know why)
    }
}

// --- Audit Logging ---
const logAudit = async (
    userId: number | null, 
    action: string, 
    resourceType: string,
    resourceId: string,
    req: Request,
    details?: any
) => {
    try {
        await pool.query(
            `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, user_agent, details) 
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [userId, action, resourceType, resourceId, getClientIP(req), req.headers['user-agent'], details ? JSON.stringify(details) : null]
        );
    } catch (e) {
        console.error('Audit log error:', e);
    }
};

// --- Middleware ---

// Helper om cookies te parsen zonder externe library
const parseCookies = (request: Request) => {
    const list: any = {};
    const cookieHeader = request.headers.cookie;
    if (!cookieHeader) return list;
    cookieHeader.split(';').forEach(function(cookie) {
        let [name, ...rest] = cookie.split('=');
        name = name?.trim();
        if (!name) return;
        const value = rest.join('=').trim();
        if (!value) return;
        list[name] = decodeURIComponent(value);
    });
    return list;
};

const authenticateToken: RequestHandler = (req, res, next) => {
  // Probeer token uit HttpOnly cookie te halen, fallback naar header (voor API calls)
  const cookies = parseCookies(req);
  const token = cookies.token || req.headers['authorization']?.split(' ')[1];

  if (!token) { res.status(401).json({ error: 'Access denied' }); return; }
  
  jwt.verify(token, JWT_SECRET, (err: any, decoded: any) => {
    if (err) { res.status(403).json({ error: 'Invalid token' }); return; }
    (req as AuthRequest).user = decoded as JWTPayload;
    next();
  });
};

const requireAdmin: RequestHandler = (req, res, next) => {
    const authReq = req as AuthRequest;
    if (!authReq.user?.isAdmin) return res.status(403).json({ error: 'Admin required' });
    next();
};

const checkUploadLimits: RequestHandler = async (req, res, next) => {
    const config = await getConfig();
    const maxBytes = getBytes(config.maxSizeVal || 10, config.maxSizeUnit || 'GB');
    const contentLength = parseInt(req.headers['content-length'] || '0');
    if (contentLength > maxBytes) {
        return res.status(413).json({ error: `File too large. Maximum ${config.maxSizeVal} ${config.maxSizeUnit}` });
    }
    next();
};

const RESERVED_SLUGS = ['api', 'admin', 'config', 's', 'r', 'login', 'reset-password'];

const isValidSlug = (slug: string): boolean => {
    if (!slug || typeof slug !== 'string') return false;
    if (slug.length < 3 || slug.length > 50) return false; // Minimaal 3 karakters
    if (RESERVED_SLUGS.includes(slug.toLowerCase())) return false;
    
    // ALLEEN letters, cijfers en koppeltekens/underscores toegestaan
    if (!/^[a-zA-Z0-9-_]+$/.test(slug)) return false;
    
    // Mag niet beginnen of eindigen met een speciaal teken
    if (/^[-_]|[-_]$/.test(slug)) return false;

    // Geen dubbele speciale tekens (zoals -- of __)
    if (/[-_]{2,}/.test(slug)) return false;
    
    return true;
};

const handleUploadId: RequestHandler = async (req, res, next) => {
    const authReq = req as AuthRequest;
    
    // Bij multer uploads is body al geparsed, maar we moeten wel checken of het bestaat
    const customSlug = authReq.body?.customSlug;
    
    if (customSlug && customSlug.trim() !== '') {
        const slug = customSlug.trim();
        if (!isValidSlug(slug)) {
            return res.status(400).json({ error: 'Link may only contain letters, numbers and hyphens.' });
        }
        
        // Check of slug al bestaat, TENZIJ we een bestaande share updaten
        const currentId = authReq.params.id;
        if (!currentId || currentId !== slug) {
            const check = await pool.query('SELECT id FROM shares WHERE id = $1', [slug]);
            if (check.rows.length > 0) {
                return res.status(409).json({ error: 'Link is already in use.' });
            }
        }
        authReq.uploadId = slug;
    } else if (authReq.params.id) {
        if (!isValidSlug(authReq.params.id)) {
            return res.status(400).json({ error: 'Invalid ID' });
        }
        authReq.uploadId = authReq.params.id;
    } else {
        authReq.uploadId = await generateSecureId();
    }
    next();
};

// --- Virusscanner Helper ---
const scanFiles = async (files: Express.Multer.File[]) => {
    // 1. Haal de laatste config op
    const config = await getConfig();

    // 2. Check of scanner beschikbaar is
    if (!clamscanInstance) {
        // Is de 'Verplicht Scannen' optie aangevinkt?
        if (config.clamavMustScan) {
            // FAIL-CLOSED: Scanner verplicht maar offline -> ERROR
            console.error("⛔ Upload blocked: ClamAV is offline, but 'Enforce Virus Scan' is turned on.");
            throw new Error("Security error: Virus scanner unavailable, upload refused.");
        } else {
            // FAIL-OPEN: Scanner niet verplicht -> Warning en doorgaan
            console.warn("⚠️ Virusscan skipped: ClamAV is offline (not enforced).");
            return; 
        }
    }

    // 3. Scanner is actief, voer scan uit
    for (const file of files) {
        try {
            const result = await clamscanInstance.isInfected(file.path);
            if (result.isInfected) {
                await fs.unlink(file.path).catch(() => {});
                throw new Error(`Virus detected in ${file.originalname}! Upload refused.`);
            }
        } catch (e: any) {
            // Als er een error is tijdens het scannen zelf (en het is geen virus melding)
            if (e.message.includes('Virus')) throw e;
            
            // Ook hier: als scannen verplicht is, mag een error niet genegeerd worden
            if (config.clamavMustScan) {
                console.error(`Scan error (Closed): ${e.message}`);
                throw new Error("Error during virusscan. Try again later.");
            } else {
                console.warn(`Scan error (Open): ${e.message}`);
            }
        }
    }
};

const generateUploadId: RequestHandler = async (req, res, next) => {
  (req as AuthRequest).uploadId = await generateSecureId();
  next();
};

const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const authReq = req as AuthRequest;
    const id = authReq.uploadId || await generateSecureId(); 
    authReq.uploadId = id; 
    const safeId = path.basename(id); 
    const dir = path.join(UPLOAD_DIR, safeId);
    try {
        await fs.mkdir(dir, { recursive: true });
        cb(null, dir);
    } catch (e: any) {
        cb(e, dir);
    }
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, crypto.randomBytes(8).toString('hex') + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 1024 * 1024 * 1024 * 1024 } });

// --- SYSTEM UPLOAD CONFIG ---
const systemStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, SYSTEM_DIR),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const name = file.fieldname === 'logo' ? 'logo' : 'favicon';
        // Timestamp toevoegen om caching te voorkomen bij updates
        cb(null, `${name}-${Date.now()}${ext}`);
    }
});

const uploadSystem = multer({
    storage: systemStorage,
    limits: { fileSize: 50 * 1024 * 1024 }, // Max 50MB
    fileFilter: (req, file, cb) => {
        const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/svg+xml', 'image/x-icon', 'image/vnd.microsoft.icon'];
        // SECURITY Check ook de extensie, niet alleen het mime-type
        const ext = path.extname(file.originalname).toLowerCase();
        const allowedExts = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico'];
        
        if (allowedMimeTypes.includes(file.mimetype) && allowedExts.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Only images (PNG, JPG, GIF, SVG, ICO) are allowed'));
        }
    }
});

// --- API Router Definition ---
const apiRouter = express.Router();

// --- ROUTES ---

// AUTH - LOGIN (Met Rate Limiter & Generic Error)
apiRouter.post('/auth/login', loginLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        
        const genericError = 'Invalid account or password';

        // Timing Attack Preventie
        // Als user niet bestaat, doen we TOCH een compare tegen een dummy hash
        // zodat de responstijd altijd ongeveer gelijk is.
        if (result.rows.length === 0) {
            await bcrypt.compare(password, '$2b$10$Xw.sY.f/O/W.S/./././././././././././././././.'); 
            return res.status(401).json({ error: genericError });
        }
        
        const user = result.rows[0];
        const valid = await bcrypt.compare(password, result.rows[0].password_hash);
        if (!valid) return res.status(401).json({ error: genericError });
        
        // Check if 2FA is enabled for this user
        if (user.totp_enabled) {
            return res.json({ requires2FA: true, email: user.email });
        }
        
        const config = await getConfig();
        
        // Check if 2FA is required but not set up (only for non-SSO users)
        if (config.require2FA && !user.totp_enabled) {
            const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '15m' });
            
            // --- OOK HIER HET COOKIE ZETTEN ---
            // Dit is nodig zodat de vervolg-call naar '/auth/2fa/setup' geautoriseerd is
            const isProduction = process.env.NODE_ENV === 'production';
            const forceSecure = config.secureCookies || (config.appUrl && config.appUrl.startsWith('https://'));

            // Let op: we gebruiken hier de '15m' expiry van het tijdelijke token
            res.cookie('token', token, { 
                httpOnly: true, 
                secure: isProduction ? forceSecure : false, 
                sameSite: isProduction ? 'strict' : 'lax', 
                maxAge: 15 * 60 * 1000 // 15 Minutes
            });

            return res.json({ 
                requiresSetup2FA: true, 
                // tempToken mag blijven voor legacy, maar cookie doet het werk
                tempToken: token,
                user: { id: user.id, email: user.email, name: user.name, is_admin: user.is_admin }
            });
        }
        
        const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: getTimeInMs(config.sessionVal, config.sessionUnit) / 1000 });
        await logAudit(user.id, 'login', 'user', user.id.toString(), req);
        
        // Bepaal of we lokaal draaien
        // Als we GEEN https gebruiken (lokaal), moet secure FALSE zijn en SameSite LAX
        const isProduction = process.env.NODE_ENV === 'production';
        const forceSecure = config.secureCookies || (config.appUrl && config.appUrl.startsWith('https://'));

        res.cookie('token', token, { 
            httpOnly: true, 
            secure: isProduction ? forceSecure : false, 
            sameSite: isProduction ? 'strict' : 'lax', 
            maxAge: getTimeInMs(config.sessionVal, config.sessionUnit)
        });
        
        // Stuur user info terug, maar GEEN token in de body (zodat frontend het niet in localStorage zet)
        res.json({ success: true, user: { id: user.id, email: user.email, name: user.name, is_admin: user.is_admin } });
    } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// index.ts
apiRouter.post('/auth/logout', async (req, res) => {
    try {
        // 1. Haal de actuele config op, zodat we weten of secureCookies aan of uit staat
        const config = await getConfig();

        // 2. Clear de cookie met EXACT dezelfde instellingen als bij het inloggen
        res.clearCookie('token', {
            httpOnly: true,
            secure: config.secureCookies, // Dynamisch: true in productie, false lokaal
            sameSite: 'strict',
            path: '/'
        });

        res.json({ success: true });
    } catch (e) {
        console.error('Logout error:', e);
        res.status(500).json({ error: 'Uitloggen failed' });
    }
});

// 2FA - Verify TOTP during login
apiRouter.post('/auth/verify-2fa', loginLimiter, async (req, res) => {
    try {
        const { email, password, code } = req.body;
        
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        
        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
        
        if (!user.totp_enabled) return res.status(400).json({ error: '2FA not enabled' });
        
        const secret = decryptData(user.totp_secret);
        
        // Check TOTP code
        const validToken = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token: code,
            window: 2
        });
        
        if (!validToken) {
            // Check backup codes
            if (user.backup_codes) {
                const backupCodes = JSON.parse(decryptData(user.backup_codes));
                const hashedCode = crypto.createHash('sha256').update(code).digest('hex');
                const codeIndex = backupCodes.findIndex((c: string) => c === hashedCode);
                
                if (codeIndex === -1) {
                    return res.status(401).json({ error: 'Invalid code' });
                }
                
                // Remove used backup code
                backupCodes.splice(codeIndex, 1);
                const encryptedCodes = encryptData(JSON.stringify(backupCodes));
                await pool.query('UPDATE users SET backup_codes = $1 WHERE id = $2', [encryptedCodes, user.id]);
            } else {
                return res.status(401).json({ error: 'Invalid code' });
            }
        }
        
        const config = await getConfig();
        const token = jwt.sign(
            { id: user.id, email: user.email, isAdmin: user.is_admin }, 
            JWT_SECRET, 
            { expiresIn: getTimeInMs(config.sessionVal, config.sessionUnit) / 1000 }
        );
        
        await logAudit(user.id, 'login_2fa', 'user', user.id.toString(), req);

        const isProduction = process.env.NODE_ENV === 'production';
        const forceSecure = config.secureCookies || (config.appUrl && config.appUrl.startsWith('https://'));

        res.cookie('token', token, { 
            httpOnly: true, 
            secure: isProduction ? forceSecure : false, 
            sameSite: isProduction ? 'strict' : 'lax', 
            maxAge: getTimeInMs(config.sessionVal, config.sessionUnit)
        });

        res.json({ token, user: { id: user.id, email: user.email, name: user.name, is_admin: user.is_admin } });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Server error' });
    }
});

// 2FA - Setup (Generate Secret & QR)
apiRouter.post('/auth/2fa/setup', authenticateToken, async (req, res) => {
    try {
        const authReq = req as AuthRequest;
        const config = await getConfig();
        
        const secret = speakeasy.generateSecret({
            name: `${config.appName || 'Nexo share'} (${authReq.user!.email})`,
            length: 32
        });
        
        const qrCode = await QRCode.toDataURL(secret.otpauth_url!);
        
        res.json({ 
            secret: secret.base32, 
            qrCode,
            manualEntry: secret.base32
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Setup failed' });
    }
});

// 2FA - Enable (Verify and Save)
apiRouter.post('/auth/2fa/enable', authenticateToken, async (req, res) => {
    try {
        const authReq = req as AuthRequest;
        const { secret, code } = req.body;
        
        const verified = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token: code,
            window: 2
        });
        
        if (!verified) {
            return res.status(400).json({ error: 'Invalid code, try again' });
        }
        
        // Generate backup codes
        const backupCodes = generateBackupCodes();
        const hashedCodes = backupCodes.map(code => 
            crypto.createHash('sha256').update(code).digest('hex')
        );
        
        const encryptedSecret = encryptData(secret);
        const encryptedBackups = encryptData(JSON.stringify(hashedCodes));
        
        await pool.query(
            'UPDATE users SET totp_secret = $1, totp_enabled = TRUE, backup_codes = $2 WHERE id = $3',
            [encryptedSecret, encryptedBackups, authReq.user!.id]
        );
        
        await logAudit(authReq.user!.id, '2fa_enabled', 'user', authReq.user!.id.toString(), req);
        
        res.json({ success: true, backupCodes });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Enable failed' });
    }
});

// 2FA - Disable
apiRouter.post('/auth/2fa/disable', authenticateToken, async (req, res) => {
    try {
        const authReq = req as AuthRequest;
        const { password } = req.body;
        
        const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [authReq.user!.id]);
        const valid = await bcrypt.compare(password, result.rows[0].password_hash);
        
        if (!valid) {
            return res.status(401).json({ error: 'Incorrect Password' });
        }
        
        await pool.query(
            'UPDATE users SET totp_secret = NULL, totp_enabled = FALSE, backup_codes = NULL WHERE id = $1',
            [authReq.user!.id]
        );
        
        await logAudit(authReq.user!.id, '2fa_disabled', 'user', authReq.user!.id.toString(), req);
        
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Disable failed' });
    }
});

// 2FA - Check Status
apiRouter.get('/auth/2fa/status', authenticateToken, async (req, res) => {
    try {
        const authReq = req as AuthRequest;
        const result = await pool.query(
            'SELECT totp_enabled, backup_codes FROM users WHERE id = $1', 
            [authReq.user!.id]
        );
        
        let backupCodesRemaining = 0;
        if (result.rows[0].backup_codes) {
            const codes = JSON.parse(decryptData(result.rows[0].backup_codes));
            backupCodesRemaining = codes.length;
        }
        
        res.json({ 
            enabled: result.rows[0].totp_enabled,
            backupCodesRemaining
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Failed to retrieve status' });
    }
});

// 2FA - Admin Reset for User
apiRouter.post('/users/:id/2fa/reset', authenticateToken, requireAdmin, async (req, res) => {
    try {
        await pool.query(
            'UPDATE users SET totp_secret = NULL, totp_enabled = FALSE, backup_codes = NULL WHERE id = $1',
            [req.params.id]
        );
        
        const authReq = req as AuthRequest;
        await logAudit(authReq.user!.id, '2fa_admin_reset', 'user', req.params.id, req);
        
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Reset failed' });
    }
});

// PASSKEYS - Registration Options
apiRouter.post('/passkeys/register/options', authenticateToken, async (req, res) => {
    try {
        const authReq = req as AuthRequest;
        const user = await pool.query('SELECT * FROM users WHERE id = $1', [authReq.user!.id]);
        
        // HAAL DOMEIN UIT DATABASE CONFIG OF REQUEST HEADER
        const config = await getConfig();
        const baseUrl = getBaseUrl(config, req);
        const rpID = new URL(baseUrl).hostname; // Pakt alleen 'wetransfer.famretera.nl'
        
        const options = await generateRegistrationOptions({
            rpName: config.appName || 'Nexo share',
            rpID: rpID, // Dynamisch!
            userID: Buffer.from(user.rows[0].id.toString()).toString('base64url'), 
            userName: user.rows[0].email,
            userDisplayName: user.rows[0].name,
            attestationType: 'none',
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'preferred',
            },
        });
        
        req.app.locals[`challenge_${authReq.user!.id}`] = options.challenge;
        res.json(options);
    } catch (e) {
        console.error('Register Options Error:', e);
        res.status(500).json({ error: 'Options genereren failed' });
    }
});

// PASSKEYS - Verify Registration
apiRouter.post('/passkeys/register/verify', authenticateToken, async (req, res) => {
    try {
        const authReq = req as AuthRequest;
        const { response, name } = req.body;
        
        // CONFIG OPHALEN
        const config = await getConfig();
        const baseUrl = getBaseUrl(config, req);
        const rpID = new URL(baseUrl).hostname;
        
        const expectedChallenge = req.app.locals[`challenge_${authReq.user!.id}`];
        
        const verification = await verifyRegistrationResponse({
            response: response as any,
            expectedChallenge,
            expectedOrigin: baseUrl, // Checkt: https://wetransfer.famretera.nl
            expectedRPID: rpID,      // Checkt: wetransfer.famretera.nl
        });
        
        if (verification.verified && verification.registrationInfo) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            
            await pool.query(
                'INSERT INTO passkeys (user_id, credential_id, public_key, counter, name) VALUES ($1, $2, $3, $4, $5)',
                [
                    authReq.user!.id, 
                    Buffer.from(credentialID).toString('base64'),
                    Buffer.from(credentialPublicKey).toString('base64'),
                    counter,
                    name || 'Unnamed Passkey'
                ]
            );
            
            delete req.app.locals[`challenge_${authReq.user!.id}`];
            await logAudit(authReq.user!.id, 'passkey_registered', 'user', authReq.user!.id.toString(), req);
            res.json({ success: true });
        } else {
            res.status(400).json({ error: 'Verification failed' });
        }
    } catch (e) {
        console.error('Register Verify Error:', e);
        res.status(500).json({ error: 'Registratie failed' });
    }
});

// PASSKEYS - List
apiRouter.get('/passkeys', authenticateToken, async (req, res) => {
    try {
        const authReq = req as AuthRequest;
        const result = await pool.query(
            'SELECT id, name, created_at FROM passkeys WHERE user_id = $1 ORDER BY created_at DESC',
            [authReq.user!.id]
        );
        res.json(result.rows);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Retrieval failed' });
    }
});

// PASSKEYS - Delete
apiRouter.delete('/passkeys/:id', authenticateToken, async (req, res) => {
    try {
        const authReq = req as AuthRequest;
        await pool.query(
            'DELETE FROM passkeys WHERE id = $1 AND user_id = $2',
            [req.params.id, authReq.user!.id]
        );
        
        await logAudit(authReq.user!.id, 'passkey_deleted', 'user', authReq.user!.id.toString(), req);
        
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Deletion failed' });
    }
});

// PASSKEYS - Authentication Options (Public)
apiRouter.post('/passkeys/auth/options', async (req, res) => {
    try {
        const config = await getConfig();
        const baseUrl = getBaseUrl(config, req);
        const rpID = new URL(baseUrl).hostname;

        const options = await generateAuthenticationOptions({
            rpID: rpID, // Dynamisch
            userVerification: 'preferred',
        });
        
        // Voorkom memory leak. Verwijder de challenge automatisch na 2 minuten.
        const challengeKey = `auth_challenge_${options.challenge}`;
        req.app.locals[challengeKey] = options.challenge;
        
        setTimeout(() => {
            if (req.app.locals[challengeKey]) delete req.app.locals[challengeKey];
        }, 120000); // 2 minuten

        res.json(options);
    } catch (e) {
        console.error('Auth Options Error:', e);
        res.status(500).json({ error: 'Options genereren failed' });
    }
});

// PASSKEYS - Verify Authentication (Public)
apiRouter.post('/passkeys/auth/verify', async (req, res) => {
    try {
        const { response, challenge } = req.body;
        const credentialID = Buffer.from(response.id, 'base64url').toString('base64');
        
        const passkeyResult = await pool.query(
            'SELECT p.*, u.id as user_id, u.email, u.name, u.is_admin FROM passkeys p JOIN users u ON p.user_id = u.id WHERE p.credential_id = $1',
            [credentialID]
        );
        
        if (passkeyResult.rows.length === 0) {
            return res.status(400).json({ error: 'Passkey not found' });
        }
        
        const passkey = passkeyResult.rows[0];
        const expectedChallenge = req.app.locals[`auth_challenge_${challenge}`];
        
        const config = await getConfig();
        const baseUrl = getBaseUrl(config, req);
        const rpID = new URL(baseUrl).hostname;

        const verification = await verifyAuthenticationResponse({
            response: response as any,
            expectedChallenge,
            expectedOrigin: baseUrl, // Dynamisch
            expectedRPID: rpID,      // Dynamisch
            authenticator: {
                credentialID: Buffer.from(passkey.credential_id, 'base64'),
                credentialPublicKey: Buffer.from(passkey.public_key, 'base64'),
                counter: parseInt(passkey.counter)
            }
        });
        
        if (verification.verified) {
            await pool.query(
                'UPDATE passkeys SET counter = $1 WHERE id = $2',
                [verification.authenticationInfo.newCounter, passkey.id]
            );
            
            const token = jwt.sign(
                { id: passkey.user_id, email: passkey.email, isAdmin: passkey.is_admin }, 
                JWT_SECRET, 
                { expiresIn: getTimeInMs(config.sessionVal, config.sessionUnit) / 1000 }
            );
            
            delete req.app.locals[`auth_challenge_${response.response.challenge}`];

            // COOKIE ZETTEN (Net als bij SSO en Login)
            const isProduction = process.env.NODE_ENV === 'production';
            const forceSecure = config.secureCookies || (config.appUrl && config.appUrl.startsWith('https://'));

            res.cookie('token', token, { 
                httpOnly: true, 
                secure: isProduction ? forceSecure : false, 
                sameSite: isProduction ? 'strict' : 'lax', 
                maxAge: getTimeInMs(config.sessionVal, config.sessionUnit)
            });
            
            res.json({ 
                user: { id: passkey.user_id, email: passkey.email, name: passkey.name, is_admin: passkey.is_admin } 
            });
        } else {
            res.status(400).json({ error: 'Verification failed' });
        }
    } catch (e) {
        console.error('Auth Verify Error:', e);
        res.status(500).json({ error: 'Authenticatie failed' });
    }
});

// PASSWORD RESET - Request
apiRouter.post('/auth/password-reset/request', passwordResetLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        
        const config = await getConfig();
        if (!config.allowPasswordReset) {
            return res.status(403).json({ error: 'Password reset is disabled' });
        }
        
        if (!config.smtpHost) {
            return res.status(503).json({ error: 'Email is not configured' });
        }
        
        const userResult = await pool.query('SELECT id, name FROM users WHERE LOWER(email) = LOWER($1)', [email]);

        // Always return success to prevent email enumeration
        if (userResult.rows.length === 0) {
            // Voeg een nep-vertraging toe om timing attacks te voorkomen.
            // We simuleren de tijd die het kost om een token te genereren en email te sturen.
            await new Promise(resolve => setTimeout(resolve, Math.random() * 200 + 100)); // 100-300ms delay
            return res.json({ success: true });
        }
        
        const user = userResult.rows[0];
        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
        
        await pool.query(
            'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
            [user.id, token, expiresAt]
        );
        
        // Geef 'req' mee aan de functie
        const baseUrl = getBaseUrl(config, req);
        if (!baseUrl) return res.status(500).json({ error: 'Server URL niet geconfigureerd' });

        const resetUrl = `${baseUrl}/reset-password?token=${token}`;
        
        await sendEmail(
            email,
            'Reset Password',
            `<p>Hello ${escapeHtml(user.name)},</p>
             <p>You have requested a password reset. Click the button below to proceed.</p>
             <p>This link is valid for 1 hour.</p>`,
            resetUrl,
            'Reset Password'
        );
        
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Request failed' });
    }
});

// PASSWORD RESET - Verify Token
apiRouter.post('/auth/password-reset/verify', async (req, res) => {
    try {
        const { token } = req.body;
        
        const result = await pool.query(
            'SELECT user_id, expires_at, used FROM password_reset_tokens WHERE token = $1',
            [token]
        );
        
        if (result.rows.length === 0 || result.rows[0].used) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }
        
        if (new Date() > new Date(result.rows[0].expires_at)) {
            return res.status(400).json({ error: 'Token expired' });
        }
        
        res.json({ valid: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Verification failed' });
    }
});

// PASSWORD RESET - Complete
apiRouter.post('/auth/password-reset/complete', async (req, res) => {
    try {
        const { token, password } = req.body;
        
        const passwordCheck = isStrongPassword(password);
        if (!passwordCheck.valid) {
            return res.status(400).json({ error: passwordCheck.error });
        }
        
        const result = await pool.query(
            'SELECT user_id, expires_at, used FROM password_reset_tokens WHERE token = $1',
            [token]
        );
        
        if (result.rows.length === 0 || result.rows[0].used) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }
        
        if (new Date() > new Date(result.rows[0].expires_at)) {
            return res.status(400).json({ error: 'Token expired' });
        }
        
        const hash = await bcrypt.hash(password, 10);
        
        await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, result.rows[0].user_id]);
        await pool.query('UPDATE password_reset_tokens SET used = TRUE WHERE token = $1', [token]);
        
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Reset failed' });
    }
});

// Check if user needs 2FA setup (for forced 2FA)
apiRouter.get('/auth/check-2fa-requirement', authenticateToken, async (req, res) => {
    try {
        const authReq = req as AuthRequest;
        const config = await getConfig();
        
        if (!config.require2FA) {
            return res.json({ required: false });
        }
        
        const result = await pool.query(
            'SELECT totp_enabled FROM users WHERE id = $1',
            [authReq.user!.id]
        );
        
        res.json({ required: !result.rows[0].totp_enabled });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Check failed' });
    }
});

// --- Utility Route voor ID generatie (Idee: ID Feature) ---
apiRouter.get('/utils/generate-id', authenticateToken, async (req, res) => {
    const length = parseInt(req.query.length as string) || 12;
    // Cap length voor veiligheid
    const safeLength = Math.min(Math.max(length, 8), 64);
    const id = crypto.randomBytes(Math.ceil(safeLength/2)).toString('hex').slice(0, safeLength);
    res.json({ id });
});

// QR Code Generator
apiRouter.get('/utils/qr', async (req, res) => {
    try {
        const url = req.query.url as string;
        if (!url) return res.status(400).send('URL required');
        
        // Genereer QR als Data URL
        const qr = await QRCode.toDataURL(url, {
            margin: 1,
            color: {
                dark: '#000000',  // Zwarte blokjes
                light: '#00000000' // Transparante achtergrond
            }
        });
        res.json({ qr });
    } catch (e) {
        console.error('QR Error:', e);
        res.status(500).json({ error: 'QR Generation failed' });
    }
});

// AUTH - SSO INIT (HTTP Redirect)
apiRouter.get('/auth/sso', async (req, res) => {
    try {
        const config = await getConfig();
        if (!config.ssoEnabled) return res.status(404).send('SSO not active');

        // Validate appUrl
        if (!isValidAppUrl(config.appUrl)) {
            console.error('[SSO] Invalid appUrl configured:', config.appUrl);
            return res.status(500).send('Invalid SSO configuration');
        }

        let issuerOrigin = '';
        try { 
            issuerOrigin = new URL(config.oidcIssuer).origin; 
        } catch (e) {
            console.error('[SSO DEBUG] Invalid Issuer URL:', config.oidcIssuer);
            return res.status(500).send('Invalid SSO Configuration');
        }

        const redirectUri = `${cleanUrl(config.appUrl)}/api/auth/callback`;
        const params = new URLSearchParams({
            client_id: config.oidcClientId,
            redirect_uri: redirectUri,
            response_type: 'code',
            scope: 'openid profile email',
        });

        const targetUrl = `${issuerOrigin}/application/o/authorize/?${params.toString()}`;
        
        // Zet een tijdelijke cookie om CSRF te voorkomen
        res.cookie('sso_init', '1', { httpOnly: true, maxAge: 300000, sameSite: 'lax' });
        
        console.log('[SSO DEBUG] Redirecting to:', targetUrl);
        res.redirect(targetUrl);
    } catch (e: any) {
        console.error('[SSO DEBUG] Error:', e.message);
        res.status(500).send('SSO Error: ' + e.message);
    }
});

// AUTH - SSO CALLBACK
apiRouter.get('/auth/callback', async (req, res) => {
    try {
        const { code } = req.query;
        if (!code) return res.status(400).send('No code received');

        // Check of de sso_init cookie bestaat. Zo niet -> CSRF aanval of sessie verlopen.
        const cookies = parseCookies(req);
        if (!cookies.sso_init) {
            return res.status(400).send('Invalid SSO session (CSRF detected). Try again.');
        }
        res.clearCookie('sso_init'); // Cookie opruimen

        const config = await getConfig();
        
        // Validate appUrl
        if (!isValidAppUrl(config.appUrl)) {
            console.error('[SSO] Invalid appUrl configured');
            return res.status(500).send('Invalid SSO configuration');
        }
        
        let issuerOrigin = '';
        try { issuerOrigin = new URL(config.oidcIssuer).origin; } catch (e) {}

        const redirectUri = `${cleanUrl(config.appUrl)}/api/auth/callback`;
        console.log('[SSO DEBUG] Callback received.');

        const tokenRes = await axios.post(`${issuerOrigin}/application/o/token/`, new URLSearchParams({
            grant_type: 'authorization_code',
            code: code as string,
            redirect_uri: redirectUri,
            client_id: config.oidcClientId,
            client_secret: config.oidcSecret,
        }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });

        const { access_token } = tokenRes.data;
        const userRes = await axios.get(`${issuerOrigin}/application/o/userinfo/`, {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        const userData = userRes.data;
        const email = userData.email;

        if (!email) return res.status(400).send('No email received from provider');

        let userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        let user;

        if (userResult.rows.length === 0) {
            console.log('[SSO DEBUG] Creating new user:', email);
            const countRes = await pool.query('SELECT COUNT(*) FROM users');
            const isAdmin = parseInt(countRes.rows[0].count) === 0;
            const dummyHash = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), 10);
            
            const insertRes = await pool.query(
                'INSERT INTO users (email, password_hash, name, is_admin) VALUES ($1, $2, $3, $4) RETURNING *',
                [email, dummyHash, userData.name || userData.preferred_username || 'SSO User', isAdmin]
            );
            user = insertRes.rows[0];
        } else {
            user = userResult.rows[0];
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, isAdmin: user.is_admin }, 
            JWT_SECRET, 
            { expiresIn: getTimeInMs(config.sessionVal, config.sessionUnit) / 1000 }
        );

        // Store token securely in database with nonce
        const nonce = crypto.randomUUID();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

        // Encrypt JWT in database
        const encryptedToken = encryptData(token);
        await pool.query(
            'INSERT INTO sso_tokens (nonce, token, user_data, expires_at) VALUES ($1, $2, $3, $4)',
            [nonce, encryptedToken, JSON.stringify({ id: user.id, email: user.email, name: user.name, is_admin: user.is_admin }), expiresAt]
        );

        // Cleanup expired tokens
        await pool.query('DELETE FROM sso_tokens WHERE expires_at < NOW()');

        res.redirect(`${cleanUrl(config.appUrl)}/login?nonce=${nonce}`);

    } catch (e: any) {
        // BETERE ERROR LOGGING
        console.error('❌ SSO CALLBACK ERROR:');
        if (e.response) {
            // Error kwam terug van de SSO provider (b.v. 400 Bad Request)
            console.error(`Status: ${e.response.status}`);
            console.error('Data:', JSON.stringify(e.response.data));
        } else if (e.request) {
            // Geen antwoord ontvangen (b.v. netwerk timeout / DNS fout)
            console.error('Geen antwoord van SSO provider. Check netwerk/DNS/Docker link.');
            console.error('Error details:', e.message);
        } else {
            // Code fout
            console.error('Code Error:', e.message);
        }
        res.status(500).send(`Login failed: ${e.message}`);
    }
});

// SSO Token Exchange - Exchange nonce for JWT
apiRouter.post('/auth/sso-exchange', async (req, res) => {
    try {
        const { nonce } = req.body;
        
        if (!nonce || typeof nonce !== 'string') {
            return res.status(400).json({ error: 'Nonce required' });
        }
        
        // Atomische operatie (Check & Delete in één keer)
        const result = await pool.query(
            'DELETE FROM sso_tokens WHERE nonce = $1 RETURNING token, user_data, expires_at',
            [nonce]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid or expired nonce' });
        }
        
        let { token, user_data, expires_at } = result.rows[0];
        
        // Decrypt token
        try { token = decryptData(token); } catch(e) { return res.status(500).json({error: 'Token decryption error'}); }

        // Check expiration
        if (new Date() > new Date(expires_at)) {
            return res.status(401).json({ error: 'Nonce expired' });
        }

        // COOKIE INSTELLEN
        const config = await getConfig();
        const isProduction = process.env.NODE_ENV === 'production';
        const forceSecure = config.secureCookies || (config.appUrl && config.appUrl.startsWith('https://'));

        res.cookie('token', token, { 
            httpOnly: true, 
            secure: isProduction ? forceSecure : false, 
            sameSite: isProduction ? 'strict' : 'lax', 
            maxAge: getTimeInMs(config.sessionVal, config.sessionUnit)
        });
        
        res.json({ token, user: user_data });
    } catch (e: any) {
        console.error('[SSO Exchange Error]:', e.message);
        res.status(500).json({ error: 'Token uitwisseling failed' });
    }
});

// CONFIG OPHALEN
apiRouter.get('/config', async (req, res) => {
    try {
        const config = await getConfig();
        const authReq = req as AuthRequest;
        
        const publicConfig = { 
            appName: config.appName, 
            logoUrl: config.logoUrl,
            faviconUrl: config.faviconUrl,
            ssoEnabled: config.ssoEnabled,
            ssoAutoRedirect: config.ssoAutoRedirect,
            ssoLogoutUrl: config.ssoLogoutUrl,
            // Voeg deze regels toe zodat de login pagina weet wat mag:
            allowPasskeys: config.allowPasskeys,
            allowPasswordReset: config.allowPasswordReset,
            smtpConfigured: !!config.smtpHost, // Stuurt true/false i.p.v. de server gegevens
            appLocale: config.appLocale || 'en-GB'
        };

        const cookies = parseCookies(req);
        const token = cookies.token || (authReq.headers['authorization'] && authReq.headers['authorization'].split(' ')[1]);

        if (!token) return res.json(publicConfig);
        
        jwt.verify(token!, JWT_SECRET!, (err: any, decoded: any) => {
            if (err) return res.json(publicConfig);
            if (decoded && decoded.isAdmin) {
                // VEILIGHEIDS Maskeer geheimen voordat ze naar frontend gaan
                const safeConfig = { ...config };
                if (safeConfig.smtpPass) safeConfig.smtpPass = '********';
                if (safeConfig.oidcSecret) safeConfig.oidcSecret = '********';
                
                res.json(safeConfig);
            } else {
                res.json(publicConfig);
            }
        });
    } catch (e) { res.status(500).json({ error: 'Config error' }); }
});

// SYSTEM BRANDING UPLOAD
// Checkt: Mag dit verzoek? (Ja als setup nog niet klaar is, anders alleen Admin)
const checkConfigPermission = async (req: Request, res: Response): Promise<boolean> => {
    const config = await getConfig();
    if (!config.setupCompleted) return true; // Setup mode: Alles mag

    // Normale mode: Check Admin Token
    const cookies = parseCookies(req);
    const token = cookies.token || req.headers['authorization']?.split(' ')[1];
    if (!token) { res.status(401).json({ error: 'Access denied' }); return false; }
    try {
        const decoded: any = jwt.verify(token, JWT_SECRET);
        if (!decoded.isAdmin) { res.status(403).json({ error: 'Admin required' }); return false; }
        (req as AuthRequest).user = decoded;
        return true;
    } catch (e) { res.status(403).json({ error: 'Invalid token' }); return false; }
};

// SYSTEM BRANDING UPLOAD
apiRouter.post('/config/branding', uploadSystem.fields([{ name: 'logo', maxCount: 1 }, { name: 'favicon', maxCount: 1 }]), async (req, res) => {
    if (!await checkConfigPermission(req, res)) return;
    try {
        const files = req.files as { [fieldname: string]: Express.Multer.File[] };
        const currentConfig = await getConfig();
        
        if (files.logo && files.logo[0]) currentConfig.logoUrl = `/api/uploads/system/${files.logo[0].filename}`;
        if (files.favicon && files.favicon[0]) currentConfig.faviconUrl = `/api/uploads/system/${files.favicon[0].filename}`;

        await pool.query('UPDATE config SET data = $1 WHERE id = 1', [currentConfig]);
        res.json({ success: true, logoUrl: currentConfig.logoUrl, faviconUrl: currentConfig.faviconUrl });
    } catch (e: any) {
        console.error('Branding upload error:', e);
        res.status(500).json({ error: e.message || 'Upload failed' });
    }
});

// CONFIG Save
apiRouter.put('/config', async (req, res) => {
    if (!await checkConfigPermission(req, res)) return;
    const authReq = req as AuthRequest;
    const newConfig = authReq.body;

    try {
        const currentConfig = await getConfig();
        if (newConfig.smtpPass === '********') newConfig.smtpPass = currentConfig.smtpPass;
        if (newConfig.oidcSecret === '********') newConfig.oidcSecret = currentConfig.oidcSecret;

        // Behoud setup_completed status tenzij expliciet meegegeven (voorkomt per ongeluk resetten)
        newConfig.setup_completed = currentConfig.setupCompleted; 

        await pool.query(
            `INSERT INTO config (id, data, setup_completed) VALUES (1, $1, $2) 
             ON CONFLICT (id) DO UPDATE SET data = $1`, 
            [newConfig, currentConfig.setupCompleted || false]
        );
        
        configCache = null; // Cache invalidatie
        configCacheTime = 0;
        res.json({ success: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Could not save config' });
    }
});

// Markeer setup als voltooid
apiRouter.post('/config/setup-complete', async (req, res) => {
    if (!await checkConfigPermission(req, res)) return;
    try {
        await pool.query('UPDATE config SET setup_completed = TRUE WHERE id = 1');
        configCache = null;
        res.json({ success: true });
    } catch (e: any) {
        console.error('Setup complete error:', e);
        res.status(500).json({ error: 'Failed to update setup status' });
    }
});

// TEST EMAIL FUNCTIE
apiRouter.post('/config/test-email', async (req, res) => {
    if (!await checkConfigPermission(req, res)) return;
    try {
        const { smtpHost, smtpPort, smtpUser, smtpPass, smtpSecure, testEmail, smtpFrom, smtpAllowLocal } = req.body;
        if (!testEmail) return res.status(400).json({ error: 'No test email address provided' });

        if (!smtpAllowLocal && isPrivateIP(smtpHost)) {
            return res.status(403).json({ error: 'Internal/Local IPs are blocked. Enable "Allow Local IPs" in settings if this is intentional.' });
        }

        let finalPass = smtpPass;
        if (!finalPass || finalPass === '********') {
            const currentConfig = await getConfig();
            finalPass = currentConfig.smtpPass;
        }

        const transporter = nodemailer.createTransport({
            host: smtpHost, port: parseInt(smtpPort), secure: smtpSecure,
            auth: { user: smtpUser, pass: finalPass },
            tls: { rejectUnauthorized: false }
        });

        const config = await getConfig();
        await transporter.sendMail({
            from: `"${config.appName || 'Nexo share'}" <${smtpFrom || smtpUser}>`,
            to: testEmail,
            subject: `Test Email from ${config.appName || 'Nexo share'}`,
            html: `<div style="font-family: sans-serif; padding: 20px; background: #f3f4f6; border-radius: 8px;">
                    <h2 style="color: #7c3aed; margin-top: 0;">Success! 🎉</h2>
                    <p>Your SMTP settings are correct.</p>
                   </div>`
        });
        res.json({ success: true });
    } catch (e: any) {
        console.error("Test email error:", e);
        res.status(500).json({ error: e.message || 'Could not send email' });
    }
});

// USERS
apiRouter.get('/users', authenticateToken, requireAdmin, async (req, res) => {
    const result = await pool.query('SELECT id, email, name, is_admin, created_at FROM users ORDER BY id ASC');
    res.json(result.rows);
});

apiRouter.post('/users', async (req, res) => {
    // SECURITY Allow creation without token ONLY if DB is empty (First Setup)
    const countCheck = await pool.query('SELECT COUNT(*) FROM users');
    const userCount = parseInt(countCheck.rows[0].count);

    if (userCount > 0) {
        // Normal flow: Check Token & Admin rights manually since we removed middleware
        const cookies = parseCookies(req);
        const token = cookies.token || req.headers['authorization']?.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'Access denied' });
        try {
            const decoded: any = jwt.verify(token, JWT_SECRET);
            if (!decoded.isAdmin) return res.status(403).json({ error: 'Admin required' });
            (req as AuthRequest).user = decoded;
        } catch (e) { return res.status(403).json({ error: 'Invalid token' }); }
    }

    const { email, password, name, is_admin } = req.body;
    
    // Validate email
    if (!isValidEmail(email)) {
        return res.status(400).json({ error: 'Invalid email address' });
    }
    
    // Validate password strength
    const passwordCheck = isStrongPassword(password);
    if (!passwordCheck.valid) {
        return res.status(400).json({ error: passwordCheck.error });
    }
    
    const hash = await bcrypt.hash(password, 10);
    try { 
        const result = await pool.query('INSERT INTO users (email, password_hash, name, is_admin) VALUES ($1, $2, $3, $4) RETURNING id', [email, hash, name, is_admin]); 
        await logAudit((req as AuthRequest).user!.id, 'user_created', 'user', result.rows[0].id.toString(), req, { email, is_admin });
        res.json({ success: true });
    } catch (e) { 
        console.error(e);
        res.status(500).json({ error: 'Could not create user' }); 
    }
});

// --- 1. EERST de specifieke routes (Profile & Me) ---

// USER - Get Own Profile
apiRouter.get('/users/me', authenticateToken, async (req, res) => {
    try {
        const authReq = req as AuthRequest;
        const result = await pool.query(
            'SELECT id, email, name, is_admin, totp_enabled, created_at FROM users WHERE id = $1',
            [authReq.user!.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(result.rows[0]);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Profile retrieval failed' });
    }
});

// USER - Update Own Profile
apiRouter.put('/users/profile', authenticateToken, async (req, res) => {
    const authReq = req as AuthRequest;
    const { email, password, name } = authReq.body;
    const myId = authReq.user!.id;

    // Validate email
    if (!isValidEmail(email)) {
        return res.status(400).json({ error: 'Invalid email address' });
    }

    let updates = [`name = $1`, `email = $2`];
    let values = [name, email];
    let i = 3;

    if (password && password.trim() !== "") {
        // Require Current Password
        const { currentPassword } = authReq.body;
        if (!currentPassword) return res.status(400).json({ error: 'Current password is required to change.' });
        
        const userRes = await pool.query('SELECT password_hash FROM users WHERE id = $1', [myId]);
        const valid = await bcrypt.compare(currentPassword, userRes.rows[0].password_hash);
        if (!valid) return res.status(401).json({ error: 'Current password is wrong' });

        // Validate password strength
        const passwordCheck = isStrongPassword(password);
        if (!passwordCheck.valid) {
            return res.status(400).json({ error: passwordCheck.error });
        }
        
        const hash = await bcrypt.hash(password, 10);
        updates.push(`password_hash = $${i}`);
        values.push(hash);
        i++;
    }

    values.push(myId);

    try {
        // Nu klopt de nummering: $1, $2, ($3 Optional), en ID is de laatste
        await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${i}`, values);
        
        // Ververs het JWT Cookie met de nieuwe gegevens
        const config = await getConfig();
        const userRes = await pool.query('SELECT id, email, name, is_admin FROM users WHERE id = $1', [myId]);
        const updatedUser = userRes.rows[0];
        
        const token = jwt.sign(
            { id: updatedUser.id, email: updatedUser.email, isAdmin: updatedUser.is_admin }, 
            JWT_SECRET, 
            { expiresIn: getTimeInMs(config.sessionVal, config.sessionUnit) / 1000 }
        );

        const isProduction = process.env.NODE_ENV === 'production';
        const forceSecure = config.secureCookies || (config.appUrl && config.appUrl.startsWith('https://'));

        res.cookie('token', token, { 
            httpOnly: true, 
            secure: isProduction ? forceSecure : false, 
            sameSite: isProduction ? 'strict' : 'lax', 
            maxAge: getTimeInMs(config.sessionVal, config.sessionUnit)
        });

        res.json({ success: true, user: updatedUser });
    } catch (e: any) { 
        if (e.code === '23505') {
            return res.status(409).json({ error: 'This email address is already in use.' });
        }
        console.error(e);
        res.status(500).json({ error: 'Server error' }); 
    }
});

// USER - Delete Own Account
apiRouter.delete('/users/me/delete', authenticateToken, async (req, res) => {
    try {
        const authReq = req as AuthRequest;
        const { password } = req.body;
        
        // Verify password
        const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [authReq.user!.id]);
        const valid = await bcrypt.compare(password, result.rows[0].password_hash);
        
        if (!valid) {
            return res.status(401).json({ error: 'Incorrect Password' });
        }
        
        await logAudit(authReq.user!.id, 'self_delete', 'user', authReq.user!.id.toString(), req);
        await pool.query('DELETE FROM users WHERE id = $1', [authReq.user!.id]);
        
        res.json({ success: true });
    } catch (e) { 
        console.error(e);
        res.status(500).json({ error: 'Deletion failed' }); 
    }
});

// --- 2. DAARNA pas de generieke routes met :id (Admin Routes) ---

// ADMIN - Update User
apiRouter.put('/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    const authReq = req as AuthRequest;
    const { email, password, name, is_admin } = authReq.body;
    const targetId = authReq.params.id;
    
    // Voorkom dat een admin zichzelf degradeert
    if (parseInt(targetId) === authReq.user!.id && is_admin === false) {
        return res.status(403).json({ error: 'You cannot remove your own admin privileges.' });
    }

    // Validate email
    if (!isValidEmail(email)) {
        return res.status(400).json({ error: 'Invalid email address' });
    }
    
    let updates = [`name = $1`, `email = $2`, `is_admin = $3`];
    let values = [name, email, is_admin];
    let i = 4; 

    if (password && password.trim() !== "") {
        const passwordCheck = isStrongPassword(password);
        if (!passwordCheck.valid) {
            return res.status(400).json({ error: passwordCheck.error });
        }
        
        const hash = await bcrypt.hash(password, 10);
        updates.push(`password_hash = $${i}`); 
        values.push(hash);
        i++; 
    }

    values.push(targetId);

    try {
        await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${i}`, values);
        res.json({ success: true });
    } catch (e: any) { 
        if (e.code === '23505') {
            return res.status(409).json({ error: 'This email address is already in use.' });
        }
        console.error(e);
        res.status(500).json({ error: 'Server error' }); 
    }
});

// ADMIN - Delete User
apiRouter.delete('/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    const userId = req.params.id;
    const authReq = req as AuthRequest;
    
    // Prevent self-delete via admin panel
    if (authReq.user!.id === parseInt(userId)) {
        return res.status(403).json({ error: 'Use profile options to delete yourself.' });
    }

    try {
        // 1. Haal alle shares van deze gebruiker op
        const userShares = await pool.query('SELECT id FROM shares WHERE user_id = $1', [userId]);
        
        // 2. Verwijder fysieke mappen van deze shares
        for (const row of userShares.rows) {
            await fs.rm(path.join(UPLOAD_DIR, row.id), { recursive: true, force: true }).catch(() => {});
        }

        // 3. Verwijder gebruiker (Cascade zou shares/files uit DB moeten halen als FK goed staat, 
        // maar voor de zekerheid doen we shares expliciet als je schema geen cascade heeft)
        await pool.query('DELETE FROM shares WHERE user_id = $1', [userId]);
        await pool.query('DELETE FROM reverse_shares WHERE user_id = $1', [userId]); // Ook reverse shares!
        await pool.query('DELETE FROM users WHERE id = $1', [userId]);
        
        await logAudit(authReq.user!.id, 'user_deleted', 'user', userId, req);
        res.json({ success: true });
    } catch (e) { 
        console.error(e);
        res.status(500).json({ error: 'Server error while deleting user' }); 
    }
});

apiRouter.get('/contacts', authenticateToken, async (req, res) => {
    const authReq = req as AuthRequest;
    const result = await pool.query('SELECT * FROM contacts WHERE user_id = $1 ORDER BY email ASC', [authReq.user!.id]);
    res.json(result.rows);
});
apiRouter.delete('/contacts/:id', authenticateToken, async (req, res) => {
    const authReq = req as AuthRequest;
    await pool.query('DELETE FROM contacts WHERE id = $1 AND user_id = $2', [authReq.params.id, authReq.user!.id]);
    res.json({ success: true });
});

// CHUNKED UPLOAD ROUTES

// STAP 1: Initialiseer de upload (Metadata Save)
apiRouter.post('/shares/init', authenticateToken, uploadLimiter, handleUploadId, async (req, res) => {
    const client = await pool.connect();
    const authReq = req as AuthRequest;
    try {
        const { name, expirationVal, expirationUnit, recipients, message, password, maxDownloads } = authReq.body;
        const shareId = authReq.uploadId!;
        
        const passwordHash = password ? await bcrypt.hash(password, 10) : null;
        const config = await getConfig();
        
        let expiresAt = null;
        
        // 1. Definiëer unit (standaard uit config als niet meegegeven)
        let unit = expirationUnit || config.defaultExpirationUnit;

        let val;
        // 2. Check of de gebruiker expliciet iets heeft meegestuurd (inclusief 0 of lege string)
        if (expirationVal !== undefined && expirationVal !== null && expirationVal !== '') {
            val = parseInt(expirationVal);
            
            // Als parseInt faalt (bijv. lege string ""), maak er expliciet 0 van (Nooit)
            if (isNaN(val)) val = 0;
        } else {
            // 3. Pas als er ÉCHT niets in het request zit, vallen we terug op de server default
            val = config.defaultExpirationVal;
        }

        // Check Max Expiration Limiet (als die is ingesteld op > 0)
        if (config.maxExpirationVal > 0) {
            const reqMs = getTimeInMs(val, unit);
            const maxMs = getTimeInMs(config.maxExpirationVal, config.maxExpirationUnit);
            if (reqMs > maxMs) {
                // Als de gevraagde tijd langer is dan max, cap hem op max
                val = config.maxExpirationVal;
                unit = config.maxExpirationUnit;
            }
        }

        // Als val > 0, bereken de datum. Zo niet (0), dan verloopt hij nooit.
        if (val > 0) {
            expiresAt = new Date(Date.now() + getTimeInMs(val, unit));
        }

        try {
            await client.query(`INSERT INTO shares (id, user_id, name, password_hash, expires_at, recipients, message, max_downloads) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, 
                [shareId, authReq.user!.id, name || 'Share', passwordHash, expiresAt, recipients, message, maxDownloads || null]);
        } catch (err: any) {
            // Check voor Postgres Unique Violation error code (23505)
            if (err.code === '23505') {
                return res.status(409).json({ error: 'This ID/Link is already in use. Please try another.' });
            }
            throw err;
        }
        
        // Maak alvast de map aan
        const shareDir = path.join(UPLOAD_DIR, shareId);
        await fs.mkdir(shareDir, { recursive: true });

        res.json({ success: true, shareId });
    } catch (e: any) {
        console.error(e);
        res.status(500).json({ error: 'Init failed' });
    } finally {
        client.release();
    }
});

// STAP 2: Upload een chunk (stukje bestand)
// We zetten de limiet hier ruim (500MB), de echte beperking wordt bepaald door
// de chunk-grootte die de frontend hanteert (via config) en de Cloudflare limiet.
const chunkStorage = multer.diskStorage({
  destination: TEMP_DIR,
  filename: (req, file, cb) => {
    // Sla de chunk op met een willekeurige naam
    cb(null, `chunk_${crypto.randomBytes(8).toString('hex')}`);
  }
});

// 1. Authenticated Uploads (Alles toegestaan, want gebruiker is vertrouwd)
const chunkUploadAuth = multer({ 
    storage: chunkStorage, 
    limits: { fileSize: 500 * 1024 * 1024, files: 1 }
});

// 2. Public / Reverse Uploads (STRENGE Blacklist)
const chunkUploadPublic = multer({ 
    storage: chunkStorage, 
    limits: { fileSize: 500 * 1024 * 1024, files: 1 },
    fileFilter: (req, file, cb) => {
        const dangerousTypes = [
            '.exe', '.bat', '.cmd', '.sh', '.ps1', '.vbs', 
            '.php', '.php3', '.php4', '.phtml', '.pl', '.py', '.cgi', 
            '.jsp', '.asp', '.aspx', 
            '.jar', '.msi', '.com', '.scr', '.hta', 
            '.app', '.dmg', '.pkg'
        ];
        // Extra check: dubbele extensies (bijv. image.php.jpg)
        const parts = file.originalname.split('.');
        if (parts.length > 2) {
             const secondLast = '.' + parts[parts.length - 2].toLowerCase();
             if (dangerousTypes.includes(secondLast)) {
                 return cb(new Error('Double extensions with executable types are not allowed.'));
             }
        }

        const ext = path.extname(file.originalname).toLowerCase();
        if (dangerousTypes.includes(ext)) {
            cb(new Error('This file type is not allowed for security reasons.'));
        } else {
            cb(null, true);
        }
    }
});

apiRouter.post('/shares/:id/chunk', authenticateToken, uploadLimiter, chunkUploadAuth.single('chunk'), async (req, res) => {
    const { id } = req.params;
    const { fileName, chunkIndex, fileId } = req.body;
    
    if (!req.file) return res.status(400).json({ error: 'No data' });

    // 1: Path Traversal preventie
    // Gebruik path.basename() zodat "foo/../../evil.js" verandert in "evil.js"
    const safeFileName = path.basename(fileName);
    
    // Doelbestand (het samengestelde bestand)
    const targetFilePath = path.join(TEMP_DIR, `${id}_${fileId}_${safeFileName}`);

    try {
        // Valideer totale bestandsgrootte van het doelbestand
        let currentSize = 0;
        try {
            const stats = await fs.stat(targetFilePath);
            currentSize = stats.size;
        } catch(e) {
            // Bestand bestaat nog niet
        }
        
        const config = await getConfig();
        const maxBytes = getBytes(config.maxSizeVal || 10, config.maxSizeUnit || 'GB');

        // Check bij de start van een bestand of de TOTALE share grootte niet wordt overschreden.
        // Anders kan iemand 10x een bestand van 1GB uploaden terwijl de limiet 2GB is.
        if (parseInt(chunkIndex) === 0) {
            const usageRes = await pool.query('SELECT COALESCE(SUM(size), 0) as total FROM files WHERE share_id = $1', [id]);
            const currentTotal = parseInt(usageRes.rows[0].total);
            if (currentTotal + req.file.size > maxBytes) {
                await fs.unlink(req.file.path).catch(() => {});
                return res.status(413).json({ error: `Share limit exceeded. Max: ${config.maxSizeVal}${config.maxSizeUnit}` });
            }
        }
        
        if (currentSize + req.file.size > maxBytes) {
            // Verwijder de zojuist geüploade chunk van disk
            await fs.unlink(req.file.path).catch(() => {});
            // Cleanup incomplete target file
            await fs.unlink(targetFilePath).catch(() => {});
            return res.status(413).json({ error: `File too large. Maximum is ${config.maxSizeVal} ${config.maxSizeUnit}` });
        }

        // 2: Memory Exhaustion preventie (Streams)
        // We moeten 'fs' (niet promises) importeren voor streams
        const { createReadStream, createWriteStream } = require('fs');
        const flags = parseInt(chunkIndex) === 0 ? 'w' : 'a';

        await new Promise((resolve, reject) => {
            // req.file!.path komt van Multer diskStorage, dus die bestaat op disk
            const source = createReadStream(req.file!.path);
            const dest = createWriteStream(targetFilePath, { flags });
            source.on('error', reject);
            dest.on('error', reject);
            dest.on('finish', resolve);
            source.pipe(dest);
        });

        // Verwijder de tijdelijke chunk file direct na gebruik
        await fs.unlink(req.file.path).catch(() => {});

        res.json({ success: true });
    } catch (e) {
        // Ruim de chunk op bij errors
        if (req.file) {
            await fs.unlink(req.file.path).catch(() => {});
            // Correctie pending bytes bij error (anders blijft limiet 'vol' hangen)
            const val = pendingUploads.get(id);
            if (val) pendingUploads.set(id, Math.max(0, val - req.file.size));
        }
        console.error('Chunk error:', e);
        res.status(500).json({ error: 'Chunk write failed' });
    }
});

// STAP 3: Finalize (Verplaatsen, Scannen, Database, Email)
apiRouter.post('/shares/:id/finalize', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { files } = req.body; // Array van { fileName, fileId, originalName, mimeType, size }
    const authReq = req as AuthRequest;
    
    const client = await pool.connect();

    try {
        const config = await getConfig();
        const shareDir = path.join(UPLOAD_DIR, id);

        const checkOwner = await client.query('SELECT user_id FROM shares WHERE id = $1', [id]);
        if (checkOwner.rows.length === 0) throw new Error('Share not found');
        if (checkOwner.rows[0].user_id !== authReq.user!.id) throw new Error('Access denied to this share');

        await client.query('BEGIN');

        for (const f of files) {
            const tempPath = path.join(TEMP_DIR, `${id}_${f.fileId}_${f.fileName}`);
            const safeExt = path.extname(path.basename(f.fileName)); // ✅ Dubbele sanitizatie
            const finalPath = path.join(shareDir, crypto.randomBytes(8).toString('hex') + safeExt);
            
            // Check of temp file bestaat
            try {
                await fs.access(tempPath);
            } catch {
                throw new Error(`File ${f.fileName} is incomplete or corrupt.`);
            }

            // --- VIRUSSCAN ---
            if (clamscanInstance) {
                try {
                    const result = await clamscanInstance.isInfected(tempPath);
                    if (result.isInfected) {
                        await fs.unlink(tempPath).catch(() => {});
                        throw new Error(`Virus detected in ${f.originalName}!`);
                    }
                } catch (e: any) {
                    if (e.message.includes('Virus')) throw e;
                    console.warn('Scan warning:', e);
                    // Voeg hier eventueel ook een check toe als scannen MOET lukken bij errors
                    if (config.clamavMustScan) throw new Error("Virus scanner error and scanning is mandatory."); 
                }
            } else if (config.clamavMustScan) {
                // --- Blokkeer als scanner offline is maar wel verplicht ---
                await fs.unlink(tempPath).catch(() => {}); // Ruim temp bestand op
                console.error("⛔ Upload blocked: ClamAV is offline, but 'Enforce Virus Scan' is turned on.");
                throw new Error("Security error: Virus scanner unavailable, upload refused.");
            }

            // Verplaats van temp naar final
            await fs.rename(tempPath, finalPath);

            // Sanitize de originalName voordat deze de DB in gaat
            const safeOriginalName = sanitizeFilename(f.originalName);

            // Insert file record
            await client.query(`INSERT INTO files (share_id, filename, original_name, size, mime_type, storage_path) VALUES ($1, $2, $3, $4, $5, $6)`, 
                [id, path.basename(finalPath), safeOriginalName, f.size, f.mimeType, finalPath]);
        }

        // Haal share info op voor email
        const shareRes = await client.query('SELECT * FROM shares WHERE id = $1', [id]);
        const share = shareRes.rows[0];

        await client.query('COMMIT');

        // Emails versturen (In try-catch zodat upload niet faalt als mail faalt)
        if (share.recipients) {
            try {
                const list = validateAndSplitEmails(share.recipients);
                const baseUrl = getBaseUrl(config, req);
                const url = `${baseUrl}/s/${id}`;
                for (const email of list) {
                    await pool.query(`INSERT INTO contacts (user_id, email) VALUES ($1, $2) ON CONFLICT (user_id, email) DO NOTHING`, [authReq.user!.id, email]);
                    await sendEmail(email, 'Files received', 
                        `<p><strong>${escapeHtml(authReq.user!.email)}</strong> shared files with you.</p>
                        <div class="message-box" style="background: #f3f4f6; padding: 15px; border-radius: 8px; margin: 20px 0; color: #4b5563;">
                        ${share.message ? escapeHtml(share.message).replace(/\n/g, '<br>') : 'No message was added.'}
                        </div>`, url, 'Download Files');
                }
            } catch (mailErr) {
                console.error("⚠️ Sending email failed, but share was created:", mailErr);
                // We gooien de error NIET omhoog, zodat de client gewoon 'success' krijgt
            }
        }

        await logAudit(authReq.user!.id, 'share_created', 'share', id, req, {
            fileCount: files.length,
            totalSize: files.reduce((acc: number, f: any) => acc + f.size, 0),
            expiresAt: share.expires_at
        });

        res.json({ success: true, shareUrl: `${config.appUrl || 'http://localhost:5173'}/s/${id}` });

    } catch (e: any) {
        await client.query('ROLLBACK');
        console.error('Finalize error:', e);
        const status = e.message.includes('Virus') ? 400 : 500;
        res.status(status).json({ error: e.message || 'Finalize failed' });
    } finally {
        client.release();
    }
});

apiRouter.put('/shares/:id', authenticateToken, upload.array('files'), handleUploadId, async (req, res) => {
    const client = await pool.connect();
    const authReq = req as AuthRequest;
    try {
        const { name, expiration, password, customSlug, remove_password } = authReq.body; // remove_password toegevoegd
        const currentId = authReq.params.id;
        
        // --- SCAN FILES ---
        if (authReq.files) {
            await scanFiles(authReq.files as Express.Multer.File[]);
        }
        
        let newId = currentId;
        if (customSlug && customSlug !== currentId) {
            if (!isValidSlug(customSlug)) return res.status(400).json({ error: 'Invalid characters in link.' });
            const check = await client.query('SELECT id FROM shares WHERE id = $1', [customSlug]);
            if(check.rows.length > 0) return res.status(409).json({ error: 'Link is already in use' });
            newId = customSlug;
        }

        const updates = []; 
        let values = []; 
        let i = 1;

        if (name !== undefined) { 
            updates.push(`name = $${i++}`); 
            values.push(name); 
        }

        if (remove_password === 'true' || remove_password === true) {
            // Password verwijderen
            updates.push(`password_hash = NULL`);
        } else if (password && password.trim() !== '') { 
            // Nieuw Password instellen
            const hash = await bcrypt.hash(password, 10); 
            updates.push(`password_hash = $${i++}`); 
            values.push(hash); 
        }

        if (authReq.body.expirationVal !== undefined && authReq.body.expirationVal !== null) { 
            let val = parseInt(authReq.body.expirationVal);
            
            // BELANGRIJK: Als parseInt failed (bijv. lege string) of waarde is 0 -> Maak er 0 van.
            if (isNaN(val)) val = 0;

            const unit = authReq.body.expirationUnit || 'Days';
            
            // Als val > 0 is, bereken datum. Als val 0 is, wordt het NULL (Nooit verlopen).
            // We gebruiken hier GEEN config fallback, want bij een edit is 0 = oneindig.
            const date = val > 0 ? new Date(Date.now() + getTimeInMs(val, unit)) : null; 
            
            updates.push(`expires_at = $${i++}`); 
            values.push(date); 
        }

        await client.query('BEGIN');

        // Als het ID verandert, hernoem de map en update paden
        if (newId !== currentId) {
            const oldPath = path.join(UPLOAD_DIR, currentId);
            const newPath = path.join(UPLOAD_DIR, newId);

            try {
                // 1. Probeer de map te hernoemen
                await fs.access(oldPath); // Check of map bestaat
                await fs.rename(oldPath, newPath);

                // 2. Update de fysieke paden in de database voor alle bestanden in deze share
                // We vervangen het oude pad-deel door het nieuwe pad-deel
                await client.query(
                    `UPDATE files SET storage_path = REPLACE(storage_path, $1, $2) WHERE share_id = $3`,
                    [oldPath, newPath, currentId]
                );
            } catch (err: any) {
                // Negeer error als map niet bestaat (lege share), anders loggen
                if (err.code !== 'ENOENT') console.error('Fout bij hernoemen map:', err);
            }
        }
        
        if(updates.length > 0) {
            values.push(currentId); 
            values.push(authReq.user!.id);
            // Let op: index i en i+1 gebruiken voor WHERE clause
            await client.query(`UPDATE shares SET ${updates.join(', ')} WHERE id = $${i++} AND user_id = $${i++}`, values);
        }

        if (authReq.files && (authReq.files as any).length > 0) {
            for (const file of (authReq.files as Express.Multer.File[])) {
                await client.query(`INSERT INTO files (share_id, filename, original_name, size, mime_type, storage_path) VALUES ($1, $2, $3, $4, $5, $6)`, [newId, file.filename, file.originalname, file.size, file.mimetype, file.path]);
            }
        }
        await client.query('COMMIT');
        res.json({ success: true, newId });
    } catch(e: any) { 
        await client.query('ROLLBACK'); 
        if (authReq.files && Array.isArray(authReq.files)) {
            for (const f of authReq.files as Express.Multer.File[]) {
                // We proberen elk geüpload bestand direct weer te verwijderen
                await fs.unlink(f.path).catch(() => {}); 
            }
        }
        console.error('Share update error:', e); 
        // We lekken alleen de error als het een bewuste validatie/virus error is
        const isSafeError = e.message.includes('Security error') || e.message.includes('Link is already in use') || e.message.includes('Virus');
        
        res.status(isSafeError ? 400 : 500).json({
            error: isSafeError ? e.message : 'An internal error occurred while updating.'
        });
    } finally { 
        client.release(); 
    }
});

apiRouter.get('/shares', authenticateToken, async (req, res) => {
    const authReq = req as AuthRequest;
    const config = await getConfig();
    const baseUrl = config.appUrl || process.env.FRONTEND_URL || 'http://localhost:5173';
    const result = await pool.query(`SELECT s.*, (SELECT json_agg(f.*) FROM files f WHERE f.share_id = s.id) as files, (SELECT SUM(size) FROM files WHERE share_id = s.id) as total_size FROM shares s WHERE s.user_id = $1 ORDER BY created_at DESC`, [authReq.user!.id]);
    res.json(result.rows.map(r => ({ ...r, url: `${baseUrl}/s/${r.id}`, protected: !!r.password_hash })));
});

apiRouter.post('/shares/:id/resend', authenticateToken, async (req, res) => {
    const authReq = req as AuthRequest;
    const { recipients, message } = authReq.body;
    const share = await pool.query('SELECT * FROM shares WHERE id = $1 AND user_id = $2', [authReq.params.id, authReq.user!.id]);
    if (share.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    const config = await getConfig();
    const baseUrl = config.appUrl || process.env.FRONTEND_URL || 'http://localhost:5173';
    const shareUrl = `${baseUrl}/s/${authReq.params.id}`;

    if (recipients) {
        const list = validateAndSplitEmails(recipients);
        if (list.length === 0 && recipients.trim().length > 0) {
            return res.status(400).json({ error: 'No valid email addresses found' });
        }
        // Try/Catch om crash te voorkomen bij SMTP errors
        try {
            for (const email of list) await sendEmail(email, 'Reminder: Files received', `<p><strong>${escapeHtml(authReq.user!.email)}</strong> sent the link again.</p><div class="message-box" style="background: #f3f4f6; padding: 15px; border-radius: 8px; margin: 20px 0; color: #4b5563;">${message ? escapeHtml(message).replace(/\n/g, '<br>') : 'Here is the link.'}</div>`, shareUrl, 'Download Files');
        } catch (e: any) {
            console.error("Resend email failed:", e.message);
            return res.status(500).json({ error: 'Failed to send emails. Check server logs.' });
        }
    }
    res.json({ success: true });
});

apiRouter.get('/shares/:id/download', downloadLimiter, async (req, res) => {
    // Wacht op een plekje in de queue
    try {
        await zipQueue.wait();
    } catch (e) {
        return res.status(503).send('Server too busy, please try again later.');
    }

    // Zorg dat we de queue maar 1 keer vrijgeven per request (voorkomt dubbele telling)
    let released = false;
    const release = () => { if (!released) { released = true; zipQueue.release(); } };

    res.on('finish', release);
    res.on('close', release);
    res.on('error', release);

    try {
        const { id } = req.params;
        const cookieName = `dl_${id}`;
        const cookies = parseCookies(req);
        const hasDownloaded = cookies[cookieName];

        // Stap 1: Check of share bestaat en geldig is
        const shareCheck = await pool.query(
            'SELECT max_downloads, download_count, expires_at FROM shares WHERE id = $1',
            [id]
        );
        
        if (shareCheck.rows.length === 0) return res.status(404).send('Share not found');
        const share = shareCheck.rows[0];
        
        if (share.expires_at && new Date() > new Date(share.expires_at)) {
            return res.status(410).json({ error: 'Share has Expired' });
        }

        // Stap 2: Teller logica
        if (!hasDownloaded) {
            const updateRes = await pool.query(
                `UPDATE shares 
                 SET download_count = download_count + 1 
                 WHERE id = $1 
                 AND (max_downloads IS NULL OR download_count < max_downloads)
                 RETURNING download_count`,
                [id]
            );

            if (updateRes.rows.length === 0) {
                return res.status(410).end();
            }
            res.cookie(cookieName, '1', { httpOnly: true, sameSite: 'lax' });
        } else {
            if (share.max_downloads && share.download_count >= share.max_downloads) {
                // Optioneel: Blokkeer alsnog als limiet bereikt is
            }
        }
        
        // Stap 3: ZIP Genereren
        const config = await getConfig();
        const files = (await pool.query('SELECT * FROM files WHERE share_id = $1', [id])).rows;
        if(files.length === 0) return res.status(404).send('Empty');

        const totalSize = files.reduce((acc: number, f: any) => acc + parseInt(f.size), 0);
        const useCompression = totalSize < 100 * 1024 * 1024;

        const archive = archiver('zip', { 
            zlib: { level: useCompression ? (config.zipLevel || 5) : 0 },
            store: !useCompression
        });

        res.setHeader('Content-Type', 'application/zip');

        res.attachment(`${id}.zip`);
        archive.pipe(res);

        const usedNames = new Set<string>();

        files.forEach(f => {
            const isMedia = config.zipNoMedia && (f.mime_type?.startsWith('image') || f.mime_type?.startsWith('video') || f.mime_type?.startsWith('audio'));
            const shouldStore = !useCompression || isMedia;

            let entryName = f.original_name;

            if (usedNames.has(entryName)) {
                let counter = 1;
                const ext = path.extname(entryName);
                const base = path.basename(entryName, ext);
                while (usedNames.has(`${base} (${counter})${ext}`)) {
                    counter++;
                }
                entryName = `${base} (${counter})${ext}`;
            }
            usedNames.add(entryName);

            archive.file(f.storage_path, { name: entryName, store: shouldStore } as archiver.EntryData);
        });
        
        // Audit log
        await logAudit(null, 'download_zip', 'share', id, req, { size: totalSize });
        
        await archive.finalize();

    } catch (e: any) {
        release(); // Gebruik de veilige release functie
        console.error('Download error:', e);
        if (!res.headersSent) res.status(500).send('Download failed');
    }
});

apiRouter.delete('/shares/:id', authenticateToken, async (req, res) => {
    const authReq = req as AuthRequest;
    const share = await pool.query('SELECT id FROM shares WHERE id = $1 AND user_id = $2', [authReq.params.id, authReq.user!.id]);
    
    if(share.rows.length > 0) {
        // EERST proberen bestanden te verwijderen
        try { 
            await fs.rm(path.join(UPLOAD_DIR, authReq.params.id), { recursive: true, force: true }); 
        } catch(e: any) {
            console.error(`⚠️ Couldn't delete files for ${authReq.params.id}:`, e.message);
            // We gaan wel door met DB verwijderen, anders blijft de share 'hangen' in de UI
        }

        await logAudit(authReq.user!.id, 'share_deleted', 'share', authReq.params.id, req);
        await pool.query('DELETE FROM shares WHERE id = $1', [authReq.params.id]);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Not found' });
    }
});

apiRouter.delete('/shares/:id/files/:fileId', authenticateToken, async (req, res) => {
    const authReq = req as AuthRequest;
    const { id, fileId } = req.params;

    // 1. Haal bestand info op
    const file = await pool.query(
        'SELECT f.storage_path FROM files f JOIN shares s ON f.share_id = s.id WHERE f.id = $1 AND s.user_id = $2 AND s.id = $3', 
        [fileId, authReq.user!.id, id]
    );

    if (file.rows.length > 0) {
        // 2. Verwijder bestand uit DB en disk
        await pool.query('DELETE FROM files WHERE id = $1', [fileId]);
        try { await fs.unlink(file.rows[0].storage_path); } catch(e) {}

        const remaining = await pool.query('SELECT COUNT(*) FROM files WHERE share_id = $1', [id]);
        const count = parseInt(remaining.rows[0].count);

        if (count === 0) {
            // Share is leeg, ruim alles op (folder + share record)
            try { 
                await fs.rm(path.join(UPLOAD_DIR, id), { recursive: true, force: true }); 
            } catch(e) {}
            
            await pool.query('DELETE FROM shares WHERE id = $1', [id]);
            await logAudit(authReq.user!.id, 'share_deleted_empty', 'share', id, req, { reason: 'last_file_deleted' });
            
            // Stuur terug dat share ook verwijderd is
            return res.json({ success: true, shareDeleted: true });
        }

        res.json({ success: true, shareDeleted: false });
    } else {
        res.status(404).json({ error: 'Not found' });
    }
});

// REVERSE
apiRouter.post('/reverse', authenticateToken, async (req, res) => {
    const authReq = req as AuthRequest;
    try {
        const validated = reverseShareSchema.parse(authReq.body);
        // Haal de nieuwe expiration velden op
        const { name, maxSize, expirationVal, expirationUnit, password, notify, sendEmailTo, thankYouMessage, customSlug } = validated;
        
        // Default naam instellen als deze leeg is
        const finalName = (name && name.trim() !== '') ? name : 'Reverse Share';

        let id;
        if (customSlug && customSlug.trim() !== '') {
            id = customSlug.trim();
            if (!isValidSlug(id)) return res.status(400).json({ error: 'Link may only contain letters, numbers and hyphens.' });
            
            // Check of ID al bestaat in reverse_shares
            const check = await pool.query('SELECT id FROM reverse_shares WHERE id = $1', [id]);
            if (check.rows.length > 0) return res.status(409).json({ error: 'This Link is already in use.' });
        } else {
            id = await generateSecureId();
        }
        
        // Bereken expiresAt met de helper functie (net zoals bij normale shares)
        let expiresAt = null;
        if (expirationVal && expirationVal > 0) {
            expiresAt = new Date(Date.now() + getTimeInMs(expirationVal, expirationUnit || 'Days'));
        }

        const passHash = password ? await bcrypt.hash(password, 10) : null;
        
        // Voeg thank_you_message toe aan insert
        await pool.query(
            `INSERT INTO reverse_shares (id, user_id, name, max_size, expires_at, password_hash, notify_email, thank_you_message) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, 
            [id, authReq.user!.id, finalName, maxSize, expiresAt, passHash, notify, thankYouMessage || null]
        );
        const config = await getConfig();
        const baseUrl = getBaseUrl(config, req);
        const link = `${baseUrl}/r/${id}`;
        if (sendEmailTo) { await sendEmail(sendEmailTo, 'Upload Request', `<strong>${escapeHtml(authReq.user!.email)}</strong> invited you to upload files.`, link, 'Upload Files'); }
        res.json({ success: true, url: link });
    } catch (e) {
        if (e instanceof z.ZodError) {
            return res.status(400).json({ error: e.issues[0].message });
        }
        res.status(500).json({ error: 'Server error' });
    }
});

apiRouter.get('/reverse', authenticateToken, async (req, res) => {
    const authReq = req as AuthRequest;
    const config = await getConfig();
    const result = await pool.query(`SELECT r.*, (SELECT COUNT(*) FROM files f WHERE f.reverse_share_id = r.id) as file_count FROM reverse_shares r WHERE r.user_id = $1 ORDER BY created_at DESC`, [authReq.user!.id]);
    res.json(result.rows.map(r => ({ ...r, url: `${config.appUrl || 'http://localhost:5173'}/r/${r.id}` })));
});

apiRouter.delete('/reverse/:id', authenticateToken, async (req, res) => {
    const authReq = req as AuthRequest;
    await pool.query('DELETE FROM reverse_shares WHERE id = $1 AND user_id = $2', [authReq.params.id, authReq.user!.id]);
    res.json({ success: true });
});

apiRouter.get('/reverse/:id/files', authenticateToken, async (req, res) => {
    const authReq = req as AuthRequest;
    const check = await pool.query('SELECT id FROM reverse_shares WHERE id = $1 AND user_id = $2', [authReq.params.id, authReq.user!.id]);
    if(check.rows.length === 0) return res.status(403).json({ error: 'Access denied' });
    const files = await pool.query('SELECT * FROM files WHERE reverse_share_id = $1 ORDER BY created_at DESC', [authReq.params.id]);
    res.json(files.rows);
});

apiRouter.get('/reverse/files/:fileId/download', authenticateToken, async (req, res) => {
    const authReq = req as AuthRequest;
    
    // Check of de file bestaat EN of de huidige user eigenaar is van de reverse share
    const result = await pool.query(
        `SELECT f.storage_path, f.original_name 
         FROM files f 
         JOIN reverse_shares r ON f.reverse_share_id = r.id 
         WHERE f.id = $1 AND r.user_id = $2`, 
        [req.params.fileId, authReq.user!.id]
    );

    if (result.rows.length === 0) {
        return res.status(404).send('File not found or access denied.');
    }

    const file = result.rows[0];
    res.download(file.storage_path, file.original_name);
});

// 2. Download ALLES als ZIP uit Reverse Share (Authenticated)
apiRouter.get('/reverse/:id/download', authenticateToken, async (req, res) => {
    // Wacht op queue
    try {
        await zipQueue.wait();
    } catch (e) {
        return res.status(503).send('Server too busy.');
    }

    // Release handlers
    res.on('finish', () => zipQueue.release());
    res.on('close', () => zipQueue.release());
    res.on('error', () => zipQueue.release());

    try {
        const authReq = req as AuthRequest;
        
        // Check eigenaarschap
    const shareCheck = await pool.query(
        'SELECT id FROM reverse_shares WHERE id = $1 AND user_id = $2',
        [req.params.id, authReq.user!.id]
    );
    if (shareCheck.rows.length === 0) return res.status(403).send('Access denied');

    const files = await pool.query('SELECT * FROM files WHERE reverse_share_id = $1', [req.params.id]);
    if(files.rows.length === 0) return res.status(404).send('No files');

    // ZIP maken
    const config = await getConfig();
    const archive = archiver('zip', { zlib: { level: config.zipLevel || 5 } });

    res.attachment(`reverse_share_${req.params.id}.zip`);
    archive.pipe(res);

    for (const f of files.rows) {
            archive.file(f.storage_path, { name: f.original_name });
        }
        
        // Audit log voor eigenaar download
        await logAudit(authReq.user!.id, 'reverse_download_zip', 'reverse_share', req.params.id, req);
        
        await archive.finalize();
        
    } catch (e: any) {
        zipQueue.release();
        console.error('Reverse download error:', e);
        if (!res.headersSent) res.status(500).send('Download failed');
    }
});

const publicLimiter = createRateLimiter(60 * 1000, 100, "Too many requests");

// PUBLIC
apiRouter.get('/public/shares/:id', publicLimiter, async (req, res) => {
    // 1. Haal ook max_downloads en download_count op
    const share = await pool.query('SELECT name, password_hash, expires_at, message, max_downloads, download_count FROM shares WHERE id = $1', [req.params.id]);
    
    if (share.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    
    const s = share.rows[0];

    // 2. Check Expiratie
    if (s.expires_at && new Date() > new Date(s.expires_at)) return res.status(410).json({ error: 'Expired' });

    // 3. Check Download Limiet (Dit zorgt dat de bestanden verborgen blijven)
    if (s.max_downloads && s.download_count >= s.max_downloads) {
        return res.status(410).json({ error: 'Download limit reached' });
    }

    const isProtected = !!s.password_hash;
    const files = isProtected ? [] : (await pool.query('SELECT id, original_name, size, mime_type FROM files WHERE share_id = $1', [req.params.id])).rows;
    res.json({ name: s.name, message: s.message, protected: isProtected, files });
});

apiRouter.post('/shares/:id/verify', loginLimiter, async (req, res) => {
    const result = await pool.query('SELECT password_hash FROM shares WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    const valid = await bcrypt.compare(req.body.password, result.rows[0].password_hash);
    if (valid) {
        const files = (await pool.query('SELECT id, original_name, size, mime_type FROM files WHERE share_id = $1', [req.params.id])).rows;
        res.json({ valid: true, files });
    } else res.json({ valid: false });
});

apiRouter.get('/shares/:id/download', downloadLimiter, async (req, res) => {
    // Wacht op een plekje in de queue
    try {
        await zipQueue.wait();
    } catch (e) {
        return res.status(503).send('Server too busy, please try again later.');
    }

    // Zorg dat we de queue maar 1 keer vrijgeven per request (voorkomt dubbele telling)
    let released = false;
    const release = () => { if (!released) { released = true; zipQueue.release(); } };

    res.on('finish', release);
    res.on('close', release);
    res.on('error', release);

    try {
        const { id } = req.params;
        const cookieName = `dl_${id}`;
        const cookies = parseCookies(req);
        const hasDownloaded = cookies[cookieName];

        // Stap 1: Check of share bestaat en geldig is
        const shareCheck = await pool.query(
            'SELECT max_downloads, download_count, expires_at FROM shares WHERE id = $1',
            [id]
        );
        
        if (shareCheck.rows.length === 0) return res.status(404).send('Share not found');
        const share = shareCheck.rows[0];
        
        if (share.expires_at && new Date() > new Date(share.expires_at)) {
            return res.status(410).json({ error: 'Share has Expired' });
        }

        // Stap 2: Teller logica
        if (!hasDownloaded) {
            const updateRes = await pool.query(
                `UPDATE shares 
                 SET download_count = download_count + 1 
                 WHERE id = $1 
                 AND (max_downloads IS NULL OR download_count < max_downloads)
                 RETURNING download_count`,
                [id]
            );

            if (updateRes.rows.length === 0) {
                return res.status(410).end();
            }
            res.cookie(cookieName, '1', { httpOnly: true, sameSite: 'lax' });
        } else {
            if (share.max_downloads && share.download_count >= share.max_downloads) {
                // Optioneel: Blokkeer alsnog als limiet bereikt is
            }
        }
        
        // Stap 3: ZIP Genereren
        const config = await getConfig();
        const files = (await pool.query('SELECT * FROM files WHERE share_id = $1', [id])).rows;
        if(files.length === 0) return res.status(404).send('Empty');

        const totalSize = files.reduce((acc: number, f: any) => acc + parseInt(f.size), 0);
        const useCompression = totalSize < 100 * 1024 * 1024;

        const archive = archiver('zip', { 
            zlib: { level: useCompression ? (config.zipLevel || 5) : 0 },
            store: !useCompression
        });

        res.setHeader('Content-Type', 'application/zip');

        res.attachment(`${id}.zip`);
        archive.pipe(res);

        const usedNames = new Set<string>();

        files.forEach(f => {
            const isMedia = config.zipNoMedia && (f.mime_type?.startsWith('image') || f.mime_type?.startsWith('video') || f.mime_type?.startsWith('audio'));
            const shouldStore = !useCompression || isMedia;

            let entryName = f.original_name;

            if (usedNames.has(entryName)) {
                let counter = 1;
                const ext = path.extname(entryName);
                const base = path.basename(entryName, ext);
                while (usedNames.has(`${base} (${counter})${ext}`)) {
                    counter++;
                }
                entryName = `${base} (${counter})${ext}`;
            }
            usedNames.add(entryName);

            archive.file(f.storage_path, { name: entryName, store: shouldStore } as archiver.EntryData);
        });
        
        // Audit log
        await logAudit(null, 'download_zip', 'share', id, req, { size: totalSize });
        
        await archive.finalize();

    } catch (e: any) {
        release(); // Gebruik de veilige release functie
        console.error('Download error:', e);
        if (!res.headersSent) res.status(500).send('Download failed');
    }
});

apiRouter.get('/shares/:id/files/:fileId', downloadLimiter, async (req, res) => {
    const { id, fileId } = req.params;
    const cookieName = `dl_${id}`; // Zelfde cookie naam als bij de ZIP (per share, niet per file)
    const cookies = parseCookies(req);
    const hasDownloaded = cookies[cookieName];

    // Stap 1: Metadata checken
    const check = await pool.query(
        'SELECT s.max_downloads, s.download_count, s.expires_at, f.storage_path, f.original_name FROM files f JOIN shares s ON f.share_id = s.id WHERE s.id = $1 AND f.id = $2', 
        [id, fileId]
    );
    
    if (check.rows.length === 0) return res.status(404).send('Not found');
    const data = check.rows[0];

    if (data.expires_at && new Date() > new Date(data.expires_at)) {
        return res.status(410).send('Expired');
    }

    // Stap 2: Teller ophogen indien nodig
    if (!hasDownloaded) {
        const updateRes = await pool.query(
            `UPDATE shares 
             SET download_count = download_count + 1 
             WHERE id = $1 
             AND (max_downloads IS NULL OR download_count < max_downloads)`,
            [id]
        );

        if (updateRes.rowCount === 0) {
            return res.status(410).end();
        }
        
        // Cookie zetten
        res.cookie(cookieName, '1', { httpOnly: true, sameSite: 'lax' });
    }

    // Stap 3: Bestand sturen
    res.download(data.storage_path, data.original_name);
});

// GUEST UPLOAD
apiRouter.get('/public/reverse/:id', async (req, res) => {
    // Selecteer ook thank_you_message
    const result = await pool.query('SELECT name, max_size, expires_at, password_hash, thank_you_message FROM reverse_shares WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    const share = result.rows[0];
    if (share.expires_at && new Date() > new Date(share.expires_at)) return res.status(410).json({ error: 'Expired' });
    
    res.json({ 
        name: share.name, 
        maxSize: share.max_size, 
        protected: !!share.password_hash,
        thankYouMessage: share.thank_you_message
    });
});

apiRouter.post('/public/reverse/:id/verify', loginLimiter, async (req, res) => {
    const result = await pool.query('SELECT password_hash FROM reverse_shares WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    const valid = await bcrypt.compare(req.body.password, result.rows[0].password_hash);
    res.json({ valid });
});

// REVERSE SHARE CHUNKED UPLOAD (GUEST)

// STAP 1: Init Guest Upload
apiRouter.post('/public/reverse/:id/init', checkUploadLimits, uploadLimiter, async (req, res) => {
    const { id } = req.params;
    // Check of share bestaat en geldig is
    const shareRes = await pool.query('SELECT * FROM reverse_shares WHERE id = $1', [id]);
    if (shareRes.rows.length === 0) return res.status(404).json({ error: 'Link not found' });
    
    const share = shareRes.rows[0];
    if (share.expires_at && new Date() > new Date(share.expires_at)) {
        return res.status(410).json({ error: 'Link has expired' });
    }

    res.json({ success: true, reverseShareId: id });
});

// STAP 2: Chunk Guest Upload
// We hergebruiken de 'chunkUpload' multer configuratie van hierboven (memoryStorage)
apiRouter.post('/public/reverse/:id/chunk', checkUploadLimits, uploadLimiter, chunkUploadPublic.single('chunk'), async (req, res) => {
    const { id } = req.params;
    const { fileName, chunkIndex, fileId } = req.body;

    // TypeScript check: garandeer dat file bestaat
    if (!req.file) return res.status(400).json({ error: 'No data' });
    const uploadedFile = req.file; // Lokale referentie voor TS

    // Path Traversal preventie
    const safeFileName = path.basename(fileName);
    const tempFilePath = path.join(TEMP_DIR, `rev_${id}_${fileId}_${safeFileName}`);

    try {
        // 1. Haal de share limiet EN het huidige gebruik op uit de database
        // We tellen alle REEDS geüploade bestanden op (files tabel) die aan deze share hangen
        const shareCheck = await pool.query(
            `SELECT r.max_size, COALESCE(SUM(f.size), 0) as current_used 
             FROM reverse_shares r 
             LEFT JOIN files f ON r.id = f.reverse_share_id 
             WHERE r.id = $1 
             GROUP BY r.id`,
            [id]
        );

        if (shareCheck.rows.length === 0) {
            // Ruim chunk op als share niet bestaat
            await fs.unlink(req.file.path).catch(() => {});
            return res.status(404).json({ error: 'Link not found' });
        }

        const { max_size, current_used } = shareCheck.rows[0];
        const maxSize = parseInt(max_size);
        const currentDbUsage = parseInt(current_used);
        
        // Race condition preventie via in-memory tracking
        const currentPending = pendingUploads.get(id) || 0;

        // 2. Bepaal grootte van het bestand dat NU wordt opgebouwd in temp
        let currentTempSize = 0;
        try {
            const stats = await fs.stat(tempFilePath);
            currentTempSize = stats.size;
        } catch(e) {
            // Bestand bestaat nog niet (eerste chunk)
        }

        // 3. Totale controle: (DB) + (Pending in RAM) + (Temp Disk) + (Nieuwe Chunk)
        const totalProjectedSize = currentDbUsage + currentPending + uploadedFile.size;

        if (maxSize > 0 && totalProjectedSize > maxSize) {
            await fs.unlink(uploadedFile.path).catch(() => {}); 
            await fs.unlink(tempFilePath).catch(() => {}); 
            return res.status(413).json({ error: `Share limit exceeded. Maximum ${formatBytes(maxSize)}.` });
        }

        // 4. Controleer globale server limiet
        const config = await getConfig();
        const globalMaxBytes = getBytes(config.maxSizeVal || 10, config.maxSizeUnit || 'GB');
        
        if (currentTempSize + uploadedFile.size > globalMaxBytes) {
            await fs.unlink(uploadedFile.path).catch(() => {});
            return res.status(413).json({ error: `File too large for server policy.` });
        }

        // 5. Schrijf de chunk (Streams)
        const { createReadStream, createWriteStream } = require('fs');
        const flags = parseInt(chunkIndex) === 0 ? 'w' : 'a';

        await new Promise((resolve, reject) => {
            const source = createReadStream(uploadedFile.path);
            const dest = createWriteStream(tempFilePath, { flags });
            source.on('error', reject);
            dest.on('error', reject);
            dest.on('finish', resolve);
            source.pipe(dest);
        });

        // Update pending bytes tracker (Race Condition Fix)
        pendingUploads.set(id, (pendingUploads.get(id) || 0) + uploadedFile.size);
        
        // Cleanup na 1 uur (safety net)
        setTimeout(() => {
            const val = pendingUploads.get(id);
            if (val !== undefined) {
                const newVal = Math.max(0, val - uploadedFile.size);
                // Als de teller op 0 staat, verwijder de entry uit het geheugen!
                if (newVal === 0) pendingUploads.delete(id);
                else pendingUploads.set(id, newVal);
            }
        }, 3600000);

        await fs.unlink(uploadedFile.path).catch(() => {});
        res.json({ success: true });
    } catch (e: any) {
        if (req.file) {
            await fs.unlink(req.file.path).catch(() => {});
            // Correctie pending bytes bij error
            const val = pendingUploads.get(id);
            if (val) pendingUploads.set(id, Math.max(0, val - uploadedFile.size));
        }
        console.error('Guest Chunk error:', e);
        res.status(500).json({ error: 'Chunk write failed' });
    }
});

// STAP 3: Finalize Guest Upload
apiRouter.post('/public/reverse/:id/finalize', async (req, res) => {
    const { id } = req.params;
    const { files } = req.body;
    
    // Bereken totaal direct aan het begin
    const totalUploadSize = files.reduce((acc: number, f: any) => acc + f.size, 0);

    const client = await pool.connect();

    try {
        const config = await getConfig();
        
        // Check quota ook tijdens finalize (voorkomt bypass bij server restart of API abuse)
        const shareRes = await client.query(`
            SELECT r.*, COALESCE(SUM(f.size), 0) as current_used 
            FROM reverse_shares r 
            LEFT JOIN files f ON r.id = f.reverse_share_id 
            WHERE r.id = $1 
            GROUP BY r.id`, [id]);

        if (shareRes.rows.length === 0) throw new Error('Invalid share');
        const share = shareRes.rows[0];

        if (share.max_size > 0 && (parseInt(share.current_used) + totalUploadSize > parseInt(share.max_size))) {
            throw new Error(`Upload exceeds the limit of ${formatBytes(share.max_size)}.`);
        }

        await client.query('BEGIN');

        for (const f of files) {
            const tempPath = path.join(TEMP_DIR, `rev_${id}_${f.fileId}_${f.fileName}`);
            
            // We genereren een unieke bestandsnaam in de guest_uploads map
            const uniqueName = crypto.randomBytes(8).toString('hex') + path.extname(f.fileName);
            const GUEST_DIR = path.join(UPLOAD_DIR, 'guest_uploads');
            await fs.mkdir(GUEST_DIR, { recursive: true }); 

            const finalPath = path.join(GUEST_DIR, uniqueName);

            try {
                await fs.access(tempPath);
            } catch {
                throw new Error(`The file ${f.fileName} is incomplete.`);
            }

            // Virusscan
            if (clamscanInstance) {
                const result = await clamscanInstance.isInfected(tempPath);
                if (result.isInfected) {
                    await fs.unlink(tempPath).catch(() => {});
                    throw new Error(`Virus in ${f.originalName}!`);
                }
            } else if (config.clamavMustScan) {
                await fs.unlink(tempPath).catch(() => {});
                console.error("⛔ Guest upload blocked: ClamAV is offline.");
                throw new Error("Security error: Virus scanner is unavailable.");
            }

            await fs.rename(tempPath, finalPath);

            const safeOriginalName = sanitizeFilename(f.originalName);
            
            // SECURITY Controleer extensie opnieuw bij finalizeren
            const dangerousTypes = ['.exe', '.bat', '.cmd', '.sh', '.ps1', '.vbs', '.php', '.php3', '.php4', '.phtml', '.pl', '.py', '.cgi', '.jsp', '.asp', '.aspx', '.jar', '.msi', '.com', '.scr', '.hta', '.app', '.dmg', '.pkg'];
            if (dangerousTypes.includes(path.extname(safeOriginalName).toLowerCase())) {
                 // Bestand verwijderen en error gooien
                 await fs.unlink(finalPath).catch(() => {});
                 throw new Error(`Security violation: File type ${path.extname(safeOriginalName)} is not allowed.`);
            }

            await client.query(
                `INSERT INTO files (reverse_share_id, filename, original_name, size, mime_type, storage_path) VALUES ($1, $2, $3, $4, $5, $6)`, 
                [id, uniqueName, safeOriginalName, f.size, f.mimeType, finalPath]
            );
        }

        await client.query('COMMIT');

        // Notificatie Email
        if (share.notify_email) {
            try {
                const creator = await pool.query('SELECT email FROM users WHERE id = $1', [share.user_id]);
                if (creator.rows.length > 0) {
                    const baseUrl = getBaseUrl(config, req);
                    await sendEmail(
                        creator.rows[0].email, 
                        `New Upload in "${share.name}"`, 
                        `<p>There are ${files.length} new files uploaded via your public link.</p>`, 
                        `${baseUrl}/reverse`, 
                        'View Dashboard'
                    );
                }
            } catch (mailErr) {
                 console.error("⚠️ Notificatie mail failed:", mailErr);
            }
        }

        res.json({ success: true });

    } catch (e: any) {
        await client.query('ROLLBACK');
        const status = e.message.includes('Virus') ? 400 : 500;
        res.status(status).json({ error: e.message || 'Fail' });
    } finally {
        // Pending bytes opschonen
        pendingUploads.delete(id);
        client.release();
    }
});

// --- CLI ---
async function runCLI() {
    const args = process.argv.slice(2);
    if (args.length === 0) return;
    const command = args[0]; const params = args.slice(1);
    console.log('--- Nexo share CLI v2.0 ---');
    
    try {
        if(command==='help'){ 
            console.log('\nUser Management:');
            console.log('  list-users                               - Show all users');
            console.log('  create-user <email> <name> <pass> <adm?> - Create new user (adm?=true/false)');
            console.log('  set-admin <email> <true/false>           - Promote or demote user');
            console.log('  reset-password <email> <newpass>         - Force reset password');
            console.log('  delete-user <email>                      - Delete user and their data');
            console.log('  2fa-disable <email>                      - Emergency disable 2FA for user');
            
            console.log('\nConfiguration (General):');
            console.log('  config-list                              - Show all current settings');
            console.log('  config-get <key>                         - Show single value');
            console.log('  config-set <key> <value>                 - Set value (auto-detects bool/number)');
            console.log('  config-unset <key>                       - Remove key (reset to default)');
            console.log('  setup-reset                              - Set setup_completed=false (Force Wizard)');

            console.log('\nConfiguration (Bulk Helpers):');
            console.log('  config-smtp <host> <port> <user> <pass> <from> <secure?> - Set all SMTP settings');
            console.log('  config-sso <issuer> <client_id> <secret>                 - Set OIDC settings');
            console.log('  security-toggle <feature> <true/false>                   - Features: 2fa, passkeys, reset');

            console.log('\nSystem:');
            console.log('  cleanup                                  - Run manual garbage collection');
            console.log('  system-info                              - Show server environment info');
        }
        
        // --- USER COMMANDS ---
        else if(command==='list-users'){ const r=await pool.query('SELECT id, email, name, is_admin, totp_enabled FROM users'); console.table(r.rows); }
        else if(command==='create-user'){ 
            if(params.length < 4) { console.log('Usage: create-user <email> <name> <pass> <is_admin>'); return; }
            await pool.query('INSERT INTO users (email, name, password_hash, is_admin) VALUES ($1, $2, $3, $4)', [params[0], params[1], await bcrypt.hash(params[2], 10), params[3]==='true']); 
            console.log(`User ${params[0]} created.`); 
        }
        else if(command==='set-admin'){ await pool.query('UPDATE users SET is_admin=$1 WHERE email=$2', [params[1]==='true', params[0]]); console.log(`Admin status for ${params[0]} set to ${params[1]}`); }
        else if(command==='reset-password'){ await pool.query('UPDATE users SET password_hash=$1 WHERE email=$2', [await bcrypt.hash(params[1], 10), params[0]]); console.log(`Password reset for ${params[0]}`); }
        else if(command==='delete-user'){ await pool.query('DELETE FROM users WHERE email=$1', [params[0]]); console.log(`User ${params[0]} deleted.`); }
        else if(command==='2fa-disable'){ 
            const r=await pool.query('SELECT id FROM users WHERE email=$1',[params[0]]);
            if(r.rows.length===0)console.log('User not found'); 
            else{await pool.query('UPDATE users SET totp_secret=NULL,totp_enabled=FALSE,backup_codes=NULL WHERE id=$1',[r.rows[0].id]);console.log(`2FA disabled for ${params[0]}`);}
        }

        // --- CONFIG COMMANDS ---
        else if(command==='config-list'){ 
            const r=await pool.query('SELECT data, setup_completed FROM config WHERE id=1');
            const c = r.rows[0]?.data || {};
            // Mask secrets
            if(c.smtpPass) c.smtpPass = '********';
            if(c.oidcSecret) c.oidcSecret = '********';
            console.log('Setup Completed:', r.rows[0]?.setup_completed);
            console.table(Object.entries(c).map(([k,v]) => ({ Key: k, Value: String(v).substring(0, 50) })));
        }
        else if(command==='config-get'){ 
            const r=await pool.query('SELECT data FROM config WHERE id=1');
            console.log(r.rows[0]?.data?.[params[0]] ?? 'Not set');
        }
        else if(command==='config-set'){ 
            if(params.length < 2) { console.log('Usage: config-set <key> <value>'); return; }
            const r=await pool.query('SELECT data FROM config WHERE id=1');
            const c=r.rows[0]?.data||{};
            let v:any=params[1];
            
            // Smart Type Detection
            if(v==='true') v=true;
            else if(v==='false') v=false;
            // Alleen naar nummer converteren als het geen wachtwoord/secret/host is
            else if(!isNaN(Number(v)) && !['smtpPass', 'oidcSecret', 'smtpUser', 'smtpHost', 'appName'].includes(params[0])) {
                v = Number(v);
            }
            
            c[params[0]]=v;
            await pool.query('UPDATE config SET data=$1 WHERE id=1',[c]);
            console.log(`Set ${params[0]} = ${v} [Type: ${typeof v}]`);
        }
        else if(command==='config-unset'){ 
            const r=await pool.query('SELECT data FROM config WHERE id=1');
            const c=r.rows[0]?.data||{};
            if(c[params[0]] !== undefined) {
                delete c[params[0]];
                await pool.query('UPDATE config SET data=$1 WHERE id=1',[c]);
                console.log(`Key '${params[0]}' removed (reset to default).`);
            } else {
                console.log('Key not found.');
            }
        }
        else if(command==='setup-reset'){
            await pool.query('UPDATE config SET setup_completed = FALSE WHERE id=1');
            console.log('✅ Setup wizard re-enabled. Reload the page to see the wizard.');
        }

        // --- BULK HELPERS ---
        else if(command==='config-smtp'){
            if(params.length < 5) { console.log('Usage: config-smtp <host> <port> <user> <pass> <from> [secure=true]'); return; }
            const r=await pool.query('SELECT data FROM config WHERE id=1');
            const c=r.rows[0]?.data||{};
            c.smtpHost = params[0];
            c.smtpPort = parseInt(params[1]);
            c.smtpUser = params[2];
            c.smtpPass = params[3];
            c.smtpFrom = params[4];
            c.smtpSecure = params[5] === 'true';
            await pool.query('UPDATE config SET data=$1 WHERE id=1',[c]);
            console.log('✅ SMTP configuration updated.');
        }
        else if(command==='config-sso'){
            if(params.length < 3) { console.log('Usage: config-sso <issuer_url> <client_id> <client_secret>'); return; }
            const r=await pool.query('SELECT data FROM config WHERE id=1');
            const c=r.rows[0]?.data||{};
            c.ssoEnabled = true;
            c.oidcIssuer = params[0];
            c.oidcClientId = params[1];
            c.oidcSecret = params[2];
            await pool.query('UPDATE config SET data=$1 WHERE id=1',[c]);
            console.log('✅ SSO configuration updated & enabled.');
        }
        else if(command==='security-toggle'){
            const feature = params[0];
            const enabled = params[1] === 'true';
            const r=await pool.query('SELECT data FROM config WHERE id=1');
            const c=r.rows[0]?.data||{};
            
            if(feature === '2fa') c.require2FA = enabled;
            else if(feature === 'passkeys') c.allowPasskeys = enabled;
            else if(feature === 'reset') c.allowPasswordReset = enabled;
            else { console.log('Unknown feature. Use: 2fa, passkeys, or reset'); return; }

            await pool.query('UPDATE config SET data=$1 WHERE id=1',[c]);
            console.log(`Security feature '${feature}' set to ${enabled}`);
        }

        // --- SYSTEM ---
        else if(command==='cleanup'){
            console.log('🧹 Starting manual cleanup...');
            await cleanupOrphanedFolders();
            await cleanupOrphanedGuestFiles();
            await cleanupOrphanedShareFiles();
            console.log('✅ Manual cleanup finished.');
        }
        else if(command==='system-info'){
            const config = await getConfig();
            console.log('\n--- System Info ---');
            console.log(`App Name:      ${config.appName}`);
            console.log(`App URL:       ${config.appUrl}`);
            console.log(`Environment:   ${process.env.NODE_ENV || 'development'}`);
            console.log(`Upload Dir:    ${UPLOAD_DIR}`);
            console.log(`SMTP Status:   ${config.smtpHost ? 'Configured' : 'Not configured'}`);
            console.log(`Timezone:      ${process.env.TZ || 'UTC'}`);
            console.log(`DB Host:       ${process.env.DB_HOST}:${process.env.DB_PORT}`);
        }
        else console.log('Unknown command. Type "help" for a list of commands.');

    } catch(e:any){
        console.error('CLI Error:', e.message);
    } finally{
        await pool.end(); 
        process.exit(0);
    }
}

async function initDB() {
    let retries = 5;
    while (retries > 0) {
        try {
            // STAP 1: Database Connectie
            const client = await pool.connect();
            try {
                // 1a. Basis Tabellen (Create if not exists)
                await client.query(`
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY, 
                        email VARCHAR(255) UNIQUE, 
                        password_hash VARCHAR(255), 
                        name VARCHAR(255), 
                        is_admin BOOLEAN DEFAULT FALSE, 
                        totp_secret TEXT,
                        totp_enabled BOOLEAN DEFAULT FALSE,
                        backup_codes TEXT,
                        created_at TIMESTAMP DEFAULT NOW()
                    );
                    CREATE TABLE IF NOT EXISTS shares (id VARCHAR(32) PRIMARY KEY, user_id INTEGER, name VARCHAR(255), password_hash VARCHAR(255), expires_at TIMESTAMP, recipients TEXT, message TEXT, max_downloads INTEGER, download_count INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT NOW());
                    CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY, data JSONB);
                    CREATE TABLE IF NOT EXISTS reverse_shares (id VARCHAR(32) PRIMARY KEY, user_id INTEGER, name VARCHAR(255), max_size BIGINT, expires_at TIMESTAMP, password_hash VARCHAR(255), notify_email BOOLEAN, created_at TIMESTAMP DEFAULT NOW());
                    CREATE TABLE IF NOT EXISTS contacts (id SERIAL PRIMARY KEY, user_id INTEGER, email VARCHAR(255), created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, email));
                    CREATE TABLE IF NOT EXISTS files (
                        id SERIAL PRIMARY KEY, share_id VARCHAR(32) REFERENCES shares(id) ON DELETE CASCADE ON UPDATE CASCADE, 
                        reverse_share_id VARCHAR(32) REFERENCES reverse_shares(id) ON DELETE CASCADE ON UPDATE CASCADE, 
                        filename VARCHAR(255), original_name VARCHAR(255), size BIGINT, mime_type VARCHAR(100), storage_path VARCHAR(500), created_at TIMESTAMP DEFAULT NOW()
                    );
                    CREATE TABLE IF NOT EXISTS sso_tokens (
                        id SERIAL PRIMARY KEY,
                        nonce VARCHAR(64) UNIQUE NOT NULL,
                        token TEXT NOT NULL,
                        user_data JSONB NOT NULL,
                        expires_at TIMESTAMP NOT NULL,
                        created_at TIMESTAMP DEFAULT NOW()
                    );
                    CREATE INDEX IF NOT EXISTS idx_sso_tokens_nonce ON sso_tokens(nonce);
                    CREATE INDEX IF NOT EXISTS idx_sso_tokens_expires ON sso_tokens(expires_at);
                    
                    CREATE TABLE IF NOT EXISTS passkeys (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        credential_id TEXT UNIQUE NOT NULL,
                        public_key TEXT NOT NULL,
                        counter BIGINT DEFAULT 0,
                        name VARCHAR(255),
                        created_at TIMESTAMP DEFAULT NOW()
                    );
                    CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id);
                    CREATE INDEX IF NOT EXISTS idx_passkeys_credential ON passkeys(credential_id);

                    CREATE TABLE IF NOT EXISTS password_reset_tokens (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        token VARCHAR(64) UNIQUE NOT NULL,
                        expires_at TIMESTAMP NOT NULL,
                        used BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP DEFAULT NOW()
                    );
                    CREATE INDEX IF NOT EXISTS idx_reset_tokens ON password_reset_tokens(token);
                    CREATE INDEX IF NOT EXISTS idx_reset_expires ON password_reset_tokens(expires_at);
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                        action VARCHAR(50) NOT NULL,
                        resource_type VARCHAR(50),
                        resource_id VARCHAR(255),
                        ip_address VARCHAR(45),
                        user_agent TEXT,
                        details JSONB,
                        created_at TIMESTAMP DEFAULT NOW()
                    );
                    CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
                    CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
                    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
                    
                    -- Performance indexen
                    CREATE INDEX IF NOT EXISTS idx_shares_user_created ON shares(user_id, created_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_shares_expires ON shares(expires_at) WHERE expires_at IS NOT NULL;
                    CREATE INDEX IF NOT EXISTS idx_files_share ON files(share_id);
                    CREATE INDEX IF NOT EXISTS idx_files_reverse ON files(reverse_share_id);
                    CREATE INDEX IF NOT EXISTS idx_reverse_user ON reverse_shares(user_id);
                    CREATE INDEX IF NOT EXISTS idx_contacts_user_email ON contacts(user_id, email);
                `);

                // 1b. AUTO-HEALING / MIGRATIES (Dit lost je fout op)
                // We proberen altijd kolommen toe te voegen die in nieuwere versies zijn geïntroduceerd.
                // 'IF NOT EXISTS' zorgt dat dit geen fout geeft als ze er al zijn.
                const schemaFixes = [
                    `ALTER TABLE shares ADD COLUMN IF NOT EXISTS max_downloads INTEGER`,
                    `ALTER TABLE shares ADD COLUMN IF NOT EXISTS download_count INTEGER DEFAULT 0`,
                    `ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT`,
                    `ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN DEFAULT FALSE`,
                    `ALTER TABLE users ADD COLUMN IF NOT EXISTS backup_codes TEXT`,
                    `ALTER TABLE reverse_shares ADD COLUMN IF NOT EXISTS thank_you_message TEXT`,
                    `ALTER TABLE config ADD COLUMN IF NOT EXISTS setup_completed BOOLEAN DEFAULT FALSE`,
                    `ALTER TABLE config ADD COLUMN IF NOT EXISTS smtp_from TEXT`,
                    `ALTER TABLE config ADD COLUMN IF NOT EXISTS smtp_starttls BOOLEAN DEFAULT TRUE`,
                    `ALTER TABLE config ADD COLUMN IF NOT EXISTS smtp_allow_local BOOLEAN DEFAULT FALSE`,
                    `ALTER TABLE config ADD COLUMN IF NOT EXISTS clamav_must_scan BOOLEAN DEFAULT FALSE`,
                    `ALTER TABLE config ADD COLUMN IF NOT EXISTS trust_proxy BOOLEAN DEFAULT FALSE`,
                ];

                for (const fix of schemaFixes) {
                    try {
                        await client.query(fix);
                    } catch (migrationErr: any) {
                        // We loggen alleen een waarschuwing, we laten de app niet crashen hierop
                        console.warn(`⚠️ Auto-fix waarschuwing (niet kritiek): ${migrationErr.message}`);
                    }
                }

                // 1c. Admin Check & Setup
                const adminCheck = await client.query('SELECT COUNT(*) FROM users');
                if (adminCheck.rows && adminCheck.rows.length > 0) {
                    if (parseInt(adminCheck.rows[0].count) === 0) {
                        const hash = await bcrypt.hash('admin123', 10);
                        await client.query(`INSERT INTO users (email, password_hash, name, is_admin) VALUES ($1, $2, $3, $4)`, ['admin@Nexo share.com', hash, 'Super Admin', true]);
                        console.log('✅ DB Initialized & Healed. Login: admin@Nexo share.com / admin123');
                    } else {
                        console.log('✅ DB Ready & Up-to-date');
                    }
                }
            } finally {
                client.release();
            }

            // STAP 2: Server Starten
            if (process.argv.length > 2) { 
                await runCLI(); 
            } else {
                if (JWT_SECRET === 'dev-secret-change-me') console.error('⚠️ DEFAULT SECRET IN USE');
                
                app.use('/api', apiRouter);
                // XSS Preventie op user uploads (SVG scripts blokkeren)
                app.use('/api/uploads/system', (req, res, next) => {
                    res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; sandbox");
                    next();
                }, express.static(SYSTEM_DIR));
                app.use(express.static(path.join(__dirname, '../../frontend/dist')));

                app.get(/(.*)/, async (req, res) => {
                    try {
                        const indexPath = path.join(__dirname, '../../frontend/dist/index.html');
                        try {
                            await fs.access(indexPath);
                        } catch (error) {
                            console.error('CRITICAL: index.html Not found op:', indexPath);
                            return res.status(404).send('Frontend build not found.');
                        }
                        const html = await fs.readFile(indexPath, 'utf-8');
                        res.send(html);
                    } catch (e) {
                        console.error('Server error while loading frontend:', e);
                        res.status(500).send('Server Error');
                    }
                });
                
                app.listen(PORT, () => console.log(`🚀 API on ${PORT}`));
            }
            return; // Succesvolle start, verlaat de retry loop

        } catch (e:any) {
            console.error(`⚠️ Startup failed: ${e.message}`);
            retries -= 1;
            if (retries === 0) { console.error('❌ Exiting after multiple retries.'); process.exit(1); }
            console.log(`♻️ Retrying in 2 seconds... (${retries} attempts left)`);
            await new Promise(res => setTimeout(res, 2000));
        }
    }
}

initDB();