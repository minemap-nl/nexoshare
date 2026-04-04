/**
 * Upload state in sessionStorage for refresh-resilience.
 * Never persist share passwords or other secrets — strip before JSON.stringify.
 */
export type UploadStatePayload = {
    files?: any[];
    /** Share options from upload form; `password` is never persisted to sessionStorage. */
    options?: any;
    progress?: number;
    uploading?: boolean;
    result?: any;
};

function sanitizeOptionsForStorage(options: any): any {
    if (!options || typeof options !== 'object') return options;
    const { password: _p, ...rest } = options;
    return rest;
}

export function saveUploadState(data: UploadStatePayload) {
    try {
        const safeData: UploadStatePayload = { ...data };
        if (safeData.files) {
            safeData.files = safeData.files.map((f: any) => ({
                ...f,
                file: undefined,
            }));
        }
        if (safeData.options) {
            safeData.options = sanitizeOptionsForStorage(safeData.options as Record<string, unknown>);
        }
        sessionStorage.setItem('uploadState', JSON.stringify(safeData));
    } catch {
        /* ignore quota / private mode */
    }
}

export function loadUploadState(): UploadStatePayload | null {
    try {
        const data = sessionStorage.getItem('uploadState');
        if (!data) return null;
        return JSON.parse(data) as UploadStatePayload;
    } catch {
        return null;
    }
}

export function clearUploadState() {
    try {
        sessionStorage.removeItem('uploadState');
    } catch {
        /* ignore */
    }
}
