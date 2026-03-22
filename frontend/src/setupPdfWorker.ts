/**
 * pdf.js in de browser: eerst Web Worker (kan blob:-wrapper + CSP raken), anders "fake worker".
 * Fake worker laadt normaal WorkerMessageHandler via dynamic import(workerSrc) → kan unpkg / CSP raken.
 *
 * Door WorkerMessageHandler statisch te importeren en op globalThis.pdfjsWorker te zetten, gebruikt
 * pdf.js het main-thread pad zonder extra Worker, blob: of import() naar externe scripts.
 * Zie pdfjs-dist PDFWorker.#mainThreadWorkerMessageHandler en _setupFakeWorkerGlobal.
 *
 * Import dit bestand vóór `import { Document } from 'react-pdf'` in hetzelfde feature (b.v. PDFPreview):
 * react-pdf 10 `dist/index.js` zet bij eerste load `GlobalWorkerOptions.workerSrc = 'pdf.worker.mjs'`;
 * deze module moet daarna draaien om dat te overschrijven.
 */
import { pdfjs } from 'react-pdf';
import { WorkerMessageHandler } from 'pdfjs-dist/build/pdf.worker.min.mjs';
import pdfWorkerSrc from 'pdfjs-dist/build/pdf.worker.min.mjs?url';

declare global {
    // eslint-disable-next-line no-var
    var pdfjsWorker: { WorkerMessageHandler: unknown } | undefined;
}

globalThis.pdfjsWorker = { WorkerMessageHandler };

const u = typeof pdfWorkerSrc === 'string' ? pdfWorkerSrc : String(pdfWorkerSrc);
pdfjs.GlobalWorkerOptions.workerSrc =
    typeof window !== 'undefined' && u.startsWith('/') ? new URL(u, window.location.origin).href : u;
