import React, { useState, useEffect, useRef } from 'react';
import { Document, Page, pdfjs } from 'react-pdf';
import { Loader2, ZoomIn, ZoomOut } from 'lucide-react';
import 'react-pdf/dist/Page/AnnotationLayer.css';
import 'react-pdf/dist/Page/TextLayer.css';

// Configure worker locally (standard approach for Vite)
pdfjs.GlobalWorkerOptions.workerSrc = `//unpkg.com/pdfjs-dist@${pdfjs.version}/build/pdf.worker.min.mjs`;

interface PDFPreviewProps {
    file: File | Blob | string;
}

const PDFPreview: React.FC<PDFPreviewProps> = ({ file }) => {
    const [numPages, setNumPages] = useState<number | null>(null);
    const [scale, setScale] = useState(1.0);
    const [url, setUrl] = useState<string | null>(null);

    // Intersection Observer state
    const [visiblePage, setVisiblePage] = useState(1);
    const observer = useRef<IntersectionObserver | null>(null);
    const pageRefs = useRef<(HTMLDivElement | null)[]>([]);

    useEffect(() => {
        if (typeof file === 'string') {
            setUrl(file);
        } else {
            const objectUrl = URL.createObjectURL(file);
            setUrl(objectUrl);
            return () => URL.revokeObjectURL(objectUrl);
        }
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

    if (!url) return <div className="flex justify-center items-center h-full"><Loader2 className="w-8 h-8 animate-spin text-purple-500" /></div>;

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
