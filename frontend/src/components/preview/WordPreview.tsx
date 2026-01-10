import React, { useState, useEffect } from 'react';
import mammoth from 'mammoth';
import { Loader2 } from 'lucide-react';
import DOMPurify from 'dompurify';

interface WordPreviewProps {
    file: File | Blob | string;
}

const WordPreview: React.FC<WordPreviewProps> = ({ file }) => {
    const [html, setHtml] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const load = async () => {
            try {
                let arrayBuffer;
                if (typeof file === 'string') {
                    const res = await fetch(file, { credentials: 'include' });
                    if (!res.ok) {
                        if (res.status === 401 || res.status === 403) {
                            throw new Error("Access Denied: You don't have permission to view this file.");
                        }
                        throw new Error(`Failed to load file: ${res.status} ${res.statusText}`);
                    }
                    arrayBuffer = await res.arrayBuffer();
                } else {
                    arrayBuffer = await file.arrayBuffer();
                }

                const result = await mammoth.convertToHtml({ arrayBuffer });
                const cleanHtml = DOMPurify.sanitize(result.value);
                setHtml(cleanHtml);
            } catch (e) {
                console.error(e);
                setError("Failed to parse Word document.");
            } finally {
                setLoading(false);
            }
        };
        load();
    }, [file]);

    if (loading) return <div className="flex justify-center items-center h-full"><Loader2 className="w-8 h-8 animate-spin text-purple-500" /></div>;
    if (error) return <div className="flex justify-center items-center h-full text-red-400">{error}</div>;

    return (
        <div className="h-full w-full bg-white rounded-xl overflow-auto p-8 custom-scrollbar">
            <div className="prose max-w-none text-black" dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html || '') }} />
        </div>
    );
};

export default WordPreview;
