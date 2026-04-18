import path from 'path';

/** Resolved path must stay under dir (defense in depth vs path.join / platform edge cases). */
export function isResolvedPathInsideDir(dir: string, candidatePath: string): boolean {
    const base = path.resolve(dir);
    const resolved = path.resolve(candidatePath);
    return resolved === base || resolved.startsWith(base + path.sep);
}

/** Multer (or similar) paths must be a string and stay under the given root. */
export function isPathUnderDir(rootDir: string, filePath: string | undefined): boolean {
    return typeof filePath === 'string' && isResolvedPathInsideDir(rootDir, filePath);
}

/**
 * Single-segment client-provided filename for temp .part paths (rejects separators / obvious traversal in basename).
 */
export function safeUploadBaseName(fileName: unknown): string | null {
    if (typeof fileName !== 'string' || !fileName.trim()) return null;
    const base = path.basename(fileName.trim());
    if (!base || base === '.' || base === '..') return null;
    if (/[/\\]/.test(base)) return null;
    return base;
}
