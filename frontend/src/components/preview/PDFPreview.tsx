/** Must run before `Document` / `Page`: react-pdf's entry sets a bogus default `workerSrc` on first import. */
import '../../setupPdfWorker';
import React, { useState, useEffect, useRef } from 'react';
import { Document, Page } from 'react-pdf';
import { Loader2, ZoomIn, ZoomOut } from 'lucide-react';
import 'react-pdf/dist/Page/AnnotationLayer.css';
import 'react-pdf/dist/Page/TextLayer.css';

/** Pad zonder querystring. */
function urlForPreviewStreamFetch(url: string): string {
    if (url.startsWith('blob:') || url.startsWith('data:')) return url;
    try {
        const u = new URL(url, typeof window !== 'undefined' ? window.location.origin : 'http://localhost');
        u.search = '';
        return url.startsWith('/') ? `${u.pathname}${u.hash}` : u.toString();
    } catch {
        const i = url.indexOf('?');
        return i === -1 ? url : url.slice(0, i);
    }
}

/**
 * Share-PDF: POST /api/ui/payload met { a, b } — antwoord is JSON { t, d } (base64), geen ruwe PDF-bytes
 * (download-managers onderscheppen anders nog steeds dezelfde URL).
 */
function getShareInlineFetchArgs(url: string): { url: string; body: string } | null {
    if (url.startsWith('blob:') || url.startsWith('data:')) return null;
    try {
        const u = new URL(url, typeof window !== 'undefined' ? window.location.origin : 'http://localhost');
        const m = u.pathname.match(/\/(?:api\/)?shares\/([^/]+)\/files\/([^/]+)/);
        if (!m) return null;
        const [, shareId, fileId] = m;
        const hasApi = u.pathname.includes('/api/');
        const origin = u.origin;
        const fetchUrl = hasApi ? `${origin}/api/ui/payload` : `${origin}/ui/payload`;
        return { url: fetchUrl, body: JSON.stringify({ a: shareId, b: fileId }) };
    } catch {
        return null;
    }
}

/** Reverse-share bestand (eigenaar): POST /api/ui/reverse-file { e: fileId }. */
function getReverseInlineFetchArgs(url: string): { url: string; body: string } | null {
    if (url.startsWith('blob:') || url.startsWith('data:')) return null;
    try {
        const u = new URL(url, typeof window !== 'undefined' ? window.location.origin : 'http://localhost');
        const m = u.pathname.match(/\/(?:api\/)?reverse\/files\/([^/]+)\/download/);
        if (!m) return null;
        const fileId = decodeURIComponent(m[1]);
        const hasApi = u.pathname.includes('/api/');
        const origin = u.origin;
        const fetchUrl = hasApi ? `${origin}/api/ui/reverse-file` : `${origin}/ui/reverse-file`;
        return { url: fetchUrl, body: JSON.stringify({ e: fileId }) };
    } catch {
        return null;
    }
}

/** Staged file preview (GET /shares/preview-stage/… bestaat; SPA gebruikt POST /api/ui/staged + JSON i.p.v. POST naar die URL). */
function getStagedPreviewFetchArgs(url: string): { url: string; body: string } | null {
    if (url.startsWith('blob:') || url.startsWith('data:')) return null;
    try {
        const u = new URL(url, typeof window !== 'undefined' ? window.location.origin : 'http://localhost');
        const m = u.pathname.match(/\/(?:api\/)?shares\/preview-stage\/([^/?]+)/);
        if (!m) return null;
        const tempId = decodeURIComponent(m[1]);
        const hasApi = u.pathname.includes('/api/');
        const origin = u.origin;
        const fetchUrl = hasApi ? `${origin}/api/ui/staged` : `${origin}/ui/staged`;
        return { url: fetchUrl, body: JSON.stringify({ c: tempId }) };
    } catch {
        return null;
    }
}

/** Base64 (JSON) → Blob voor pdf.js */
function blobFromJsonPayload(t: string, d: string): Blob {
    const binary = atob(d);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new Blob([bytes], { type: t || 'application/pdf' });
}

interface PDFPreviewProps {
    file: File | Blob | string;
}

const PDFPreview: React.FC<PDFPreviewProps> = ({ file }) => {
    const [numPages, setNumPages] = useState<number | null>(null);
    const [scale, setScale] = useState(1.0);
    const [url, setUrl] = useState<string | null>(null);
    const [fetchError, setFetchError] = useState(false);
    /** blob: URLs we created (must revoke); not used for passed-through blob:/data: http strings */
    const ownedBlobUrlRef = useRef<string | null>(null);

    // Intersection Observer state
    const [visiblePage, setVisiblePage] = useState(1);
    const observer = useRef<IntersectionObserver | null>(null);
    const pageRefs = useRef<(HTMLDivElement | null)[]>([]);

    // Remote: POST /api/ui/payload (share-bestanden) of /api/ui/staged (staged temp) → JSON → Blob.
    useEffect(() => {
        let cancelled = false;

        const revokeOwned = () => {
            if (ownedBlobUrlRef.current) {
                URL.revokeObjectURL(ownedBlobUrlRef.current);
                ownedBlobUrlRef.current = null;
            }
        };

        revokeOwned();
        setUrl(null);
        setFetchError(false);

        const run = async () => {
            if (typeof file === 'string') {
                if (file.startsWith('blob:') || file.startsWith('data:')) {
                    setUrl(file);
                    return;
                }
                try {
                    const jsonPayloadArgs =
                        getShareInlineFetchArgs(file) ?? getStagedPreviewFetchArgs(file) ?? getReverseInlineFetchArgs(file);
                    const fetchUrl = jsonPayloadArgs?.url ?? urlForPreviewStreamFetch(file);
                    const res = await fetch(fetchUrl, {
                        method: 'POST',
                        credentials: 'include',
                        cache: 'no-store',
                        headers: {
                            'Content-Type': 'application/json',
                            ...(jsonPayloadArgs
                                ? { Accept: 'application/json' }
                                : {
                                      'X-Preview-Stream': '1',
                                      Accept: 'application/pdf, application/octet-stream;q=0.9, */*;q=0.1'
                                  })
                        },
                        body: jsonPayloadArgs?.body ?? '{}'
                    });
                    if (!res.ok) throw new Error(String(res.status));
                    let blob: Blob;
                    if (jsonPayloadArgs) {
                        const j = (await res.json()) as { t?: string; d?: string };
                        if (!j?.d || typeof j.d !== 'string') throw new Error('invalid payload');
                        blob = blobFromJsonPayload(j.t || 'application/pdf', j.d);
                    } else {
                        const buf = await res.arrayBuffer();
                        if (buf.byteLength === 0) throw new Error('empty body');
                        const ct = res.headers.get('content-type') || 'application/pdf';
                        blob = new Blob([buf], { type: ct });
                    }
                    const u = URL.createObjectURL(blob);
                    if (cancelled) {
                        URL.revokeObjectURL(u);
                        return;
                    }
                    ownedBlobUrlRef.current = u;
                    setUrl(u);
                } catch {
                    if (!cancelled) {
                        setUrl(null);
                        setFetchError(true);
                    }
                }
            } else {
                const u = URL.createObjectURL(file);
                ownedBlobUrlRef.current = u;
                setUrl(u);
            }
        };

        run();

        return () => {
            cancelled = true;
            revokeOwned();
        };
    }, [file]);

    // Setup Intersection Observer
    useEffect(() => {
        if (!numPages) return;

        observer.current = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    const pageNum = Number(entry.target.getAttribute('data-page-number'));
                    setVisiblePage(pageNum);
                }
            });
        }, {
            root: null, // viewport
            rootMargin: '-50% 0px -50% 0px', // Trigger when page is in middle of screen
            threshold: 0
        });

        pageRefs.current.forEach((ref) => {
            if (ref) observer.current?.observe(ref);
        });

        return () => {
            observer.current?.disconnect();
        };
    }, [numPages, scale]); // Re-observe when scale changes or pages load

    function onDocumentLoadSuccess({ numPages }: { numPages: number }) {
        setNumPages(numPages);
    }

    if (!url) {
        if (fetchError) {
            return (
                <div className="flex flex-col justify-center items-center h-full gap-2 text-red-400 px-4 text-center">
                    <span className="text-sm">Could not load PDF (network or access denied).</span>
                </div>
            );
        }
        return (
            <div className="flex flex-col justify-center items-center h-full gap-2 text-neutral-400">
                <Loader2 className="w-8 h-8 animate-spin text-purple-500" />
                <span className="text-sm">Loading PDF…</span>
            </div>
        );
    }

    return (
        <div className="flex flex-col h-full w-full bg-neutral-900 rounded-xl overflow-hidden">
            {/* Toolbar */}
            <div className="flex items-center justify-between p-2 bg-neutral-800 border-b border-neutral-700">
                <div className="flex items-center gap-2">
                    <span className="text-white text-sm font-mono ml-2">
                        Page {visiblePage} of {numPages || '--'}
                    </span>
                </div>

                <div className="flex items-center gap-2">
                    <button onClick={() => setScale(s => Math.max(0.5, s - 0.1))} className="p-1 hover:bg-neutral-700 rounded text-white">
                        <ZoomOut className="w-5 h-5" />
                    </button>
                    <span className="text-white text-sm w-12 text-center">{Math.round(scale * 100)}%</span>
                    <button onClick={() => setScale(s => Math.min(3, s + 0.1))} className="p-1 hover:bg-neutral-700 rounded text-white">
                        <ZoomIn className="w-5 h-5" />
                    </button>
                </div>
            </div>

            {/* Document - Vertical Scroll */}
            <div className="flex-1 overflow-auto flex justify-center p-4 bg-neutral-900 custom-scrollbar">
                <Document
                    file={url}
                    onLoadSuccess={onDocumentLoadSuccess}
                    className="flex flex-col gap-4 items-center"
                    loading={<div className="text-white flex gap-2"><Loader2 className="animate-spin" /> Loading PDF...</div>}
                    error={<div className="text-red-400">Failed to load PDF.</div>}
                >
                    {Array.from(new Array(numPages), (_, index) => (
                        <div
                            key={`page_${index + 1}`}
                            data-page-number={index + 1}
                            ref={(el) => { pageRefs.current[index] = el; }}
                            className="shadow-xl"
                        >
                            <Page
                                pageNumber={index + 1}
                                scale={scale}
                                renderTextLayer={true}
                                renderAnnotationLayer={true}
                                className="shadow-lg bg-white"
                                width={undefined} // Let scale control it
                            />
                        </div>
                    ))}
                </Document>
            </div>
        </div>
    );
};

export default PDFPreview;
