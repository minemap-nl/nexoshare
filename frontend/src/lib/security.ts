/**
 * Alleen http: en https: — blokkeert o.a. javascript:, data:, blob: voor gebruik als logo-URL / openbare href.
 */
export function isValidHttpUrl(url?: string): boolean {
    if (!url) return false;
    try {
        const u = new URL(url);
        return u.protocol === 'http:' || u.protocol === 'https:';
    } catch {
        return false;
    }
}
