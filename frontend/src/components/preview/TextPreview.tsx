import React, { useState, useEffect } from 'react';
import { Loader2, ShieldAlert, FileX } from 'lucide-react';
import Prism from 'prismjs';
import 'prismjs/themes/prism-tomorrow.css';
import 'prismjs/components/prism-javascript';
import 'prismjs/components/prism-typescript';
import 'prismjs/components/prism-css';
import 'prismjs/components/prism-json';
import 'prismjs/components/prism-markdown';
import 'prismjs/components/prism-python';
import 'prismjs/components/prism-bash';
import 'prismjs/components/prism-sql';

interface TextPreviewProps {
    file: File | Blob | string;
    fileName: string;
}

const TextPreview: React.FC<TextPreviewProps> = ({ file, fileName }) => {
    const [content, setContent] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<'restricted' | 'error' | null>(null);

    useEffect(() => {
        const loadContent = async () => {
            try {
                let text = '';
                if (typeof file === 'string') {
                    const res = await fetch(file, { credentials: 'include' });
                    if (res.status === 403) {
                        setError('restricted');
                        return;
                    }
                    if (!res.ok) throw new Error('Load failed');
                    text = await res.text();
                } else {
                    text = await file.text();
                }
                setContent(text);
            } catch (e) {
                console.error("Failed to load text", e);
                setError('error');
            } finally {
                setLoading(false);
            }
        };
        loadContent();
    }, [file]);

    useEffect(() => {
        if (content) {
            Prism.highlightAll();
        }
    }, [content]);

    // Determine language based on extension
    const getLanguage = (name: string) => {
        const ext = name.split('.').pop()?.toLowerCase();
        switch (ext) {
            case 'js': return 'javascript';
            case 'ts': case 'tsx': return 'typescript';
            case 'css': return 'css';
            case 'json': return 'json';
            case 'md': return 'markdown';
            case 'py': return 'python';
            case 'sh': return 'bash';
            case 'sql': return 'sql';
            default: return 'none';
        }
    };

    if (loading) return <div className="flex justify-center items-center h-full"><Loader2 className="w-8 h-8 animate-spin text-purple-500" /></div>;

    if (error === 'restricted') {
        return (
            <div className="flex flex-col items-center justify-center h-full text-neutral-400">
                <ShieldAlert className="w-16 h-16 mb-4 text-orange-500 opacity-80" />
                <h3 className="text-lg font-medium text-white mb-2">Preview Restricted</h3>
                <p className="text-center max-w-md px-4">This file type is not supported for previews due to security reasons.</p>
                <p className="text-sm mt-4 opacity-50">Please download the file to view it.</p>
            </div>
        );
    }

    if (error === 'error') {
        return (
            <div className="flex flex-col items-center justify-center h-full text-neutral-400">
                <FileX className="w-16 h-16 mb-4 opacity-50" />
                <p>Failed to load content.</p>
            </div>
        );
    }

    const lang = getLanguage(fileName);

    return (
        <div className="h-full w-full bg-[#2d2d2d] rounded-xl overflow-auto p-4 custom-scrollbar">
            <pre className={lang !== 'none' ? `language-${lang}` : ''} style={{ margin: 0, minHeight: '100%' }}>
                <code className={lang !== 'none' ? `language-${lang}` : ''}>
                    {content}
                </code>
            </pre>
        </div>
    );
};

export default TextPreview;
