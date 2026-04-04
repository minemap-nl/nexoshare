import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { Download, FileQuestion, Loader2, Eye, Folder as FolderIcon } from 'lucide-react';
import DOMPurify from 'dompurify';
import { API_URL } from '../api/constants';
import { sortFiles, synthesizeDirectoryItems, formatBytes } from '../lib';
import type { UploadItem } from '../types/upload';
import { useUI } from '../context/UIContext';
import { GlobalStyles } from '../components/layout/GlobalStyles';
import { Footer } from '../components/layout/Footer';


export function DownloadPage() {
    const { id } = useParams();
    const [data, setData] = useState<any>(null);
    const [viewFiles, setViewFiles] = useState<UploadItem[]>([]); // New state for transformed files
    const [error, setError] = useState<string | null>(null);
    const [password, setPassword] = useState('');
    const { notify, preview } = useUI();

    useEffect(() => {
        // We passen de fetch aan om errors af te vangen
        fetch(`${API_URL}/public/shares/${id}`)
            .then(async r => {
                if (r.status === 404) { setError('Share not found'); return null; }
                if (r.status === 410) { setError('This share is no longer available (expired or limit reached)'); return null; }
                if (!r.ok) { setError('An error occurred'); return null; }
                return r.json();
            })
            .then(d => {
                if (d) {
                    setData(d);
                    // Transform backend files to UploadItem format
                    const backendFiles = d.files || [];
                    const mapped: UploadItem[] = backendFiles.map((f: any) => ({
                        file: null,
                        path: f.original_name, // Backend path e.g. Folder/File.txt
                        name: f.original_name.split('/').pop() || f.original_name,
                        id: f.id,
                        isDirectory: false,
                        size: f.size
                    }));
                    setViewFiles(sortFiles(synthesizeDirectoryItems(mapped)));
                }
            })
            .catch(() => setError('Network error'));
    }, [id]);

    const verify = async () => {
        const res = await fetch(`${API_URL}/shares/${id}/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }) });
        const json = await res.json();
        if (json.valid) {
            setData({ ...data, files: json.files, protected: false });
            // Also update viewFiles
            const mapped: UploadItem[] = (json.files || []).map((f: any) => ({
                file: null,
                path: f.original_name,
                name: f.original_name.split('/').pop() || f.original_name,
                id: f.id,
                isDirectory: false,
                size: f.size
            }));
            setViewFiles(sortFiles(synthesizeDirectoryItems(mapped)));
        } else notify('Wrong password', "error");
    };

    // Error Scherm
    if (error) return (
        <div className="min-h-screen bg-app flex items-center justify-center p-4">
            <div className="bg-neutral-900 p-8 rounded-2xl border border-neutral-800 max-w-md w-full text-center anim-scale">
                <div className="w-16 h-16 bg-neutral-800 rounded-full flex items-center justify-center mx-auto mb-4">
                    <FileQuestion className="w-8 h-8 text-neutral-500" />
                </div>
                <h2 className="heading-panel mb-2">Unavailable</h2>
                <p className="text-neutral-400">{error}</p>
                <a href="/" className="mt-6 inline-block text-primary-300 hover:text-white transition text-sm font-medium">Go to home</a>
            </div>
        </div>
    );

    if (!data) return <div className="min-h-screen bg-app flex items-center justify-center text-white"><Loader2 className="w-8 h-8 animate-spin text-primary-400" /></div>;

    return (
        <div className="min-h-screen bg-app flex items-center justify-start pt-24 md:pt-32 p-4 flex-col">
            <GlobalStyles />
            <div className="bg-neutral-900 rounded-2xl p-6 md:p-8 max-w-lg w-full border border-neutral-800 shadow-2xl anim-scale mb-8">
                <div className="text-center mb-8">
                    <div className="w-16 h-16 bg-primary/20 rounded-2xl flex items-center justify-center mx-auto mb-4"><Download className="text-primary-400 w-8 h-8" /></div>
                    <h1 className="heading-section mb-1">{data.name}</h1>
                    <p className="text-neutral-400 text-sm">Shared with {data.appName || 'Nexo Share'}</p>
                </div>
                {data.protected ? (
                    <form
                        onSubmit={(e) => { e.preventDefault(); verify(); }}
                        className="text-center space-y-4 anim-fade"
                    >
                        <div className="bg-yellow-500/10 text-yellow-500 p-3 rounded-lg text-sm mb-4 border border-yellow-500/20">
                            This download is protected with a password.
                        </div>
                        <input
                            className="input-field text-center"
                            type="password"
                            placeholder="Enter password"
                            value={password}
                            onChange={e => setPassword(e.target.value)}
                            autoFocus
                        />
                        <button
                            type="submit"
                            className="bg-gradient-brand hover:brightness-110 text-white px-6 py-3 rounded-lg font-bold w-full transition-all btn-press"
                        >
                            Unlock
                        </button>
                    </form>
                ) : (
                    <div className="anim-fade">
                        {data.message && (
                            <div className="bg-black/50 p-4 rounded-xl border border-neutral-800 mb-6 text-neutral-300 text-sm italic relative">
                                <span className="absolute -top-3 left-4 bg-neutral-900 px-2 text-xs text-primary-300 font-bold uppercase">Message</span>
                                <div dangerouslySetInnerHTML={{
                                    __html: DOMPurify.sanitize(data.message, {
                                        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'br', 'p'],
                                        ALLOWED_ATTR: []
                                    })
                                }} />
                            </div>
                        )}

                        <div className="mb-6 max-h-[400px] overflow-y-auto bg-black/50 rounded-lg border border-neutral-800" style={{ "--indent-step": "24px" } as React.CSSProperties}>
                            <style>{`@media (max-width: 768px) { [style*="--indent-step"] { --indent-step: 12px !important; } }`}</style>
                            {viewFiles.map((item) => {
                                const segments = item.path.split('/');
                                const depth = Math.max(0, segments.length - 1);

                                return (
                                    <div key={item.id} className={`flex justify-between items-center px-3 py-2 md:px-4 md:py-3 border-b border-neutral-800 last:border-0 hover:bg-neutral-800/50 transition gap-2 ${item.isDirectory ? 'bg-neutral-800/30' : ''}`}>
                                        {/* Klik op naam = Preview */}
                                        <div
                                            className="flex items-center gap-2 md:gap-4 overflow-hidden flex-1 min-w-0 cursor-pointer group"
                                            style={{ paddingLeft: `calc(${depth} * var(--indent-step, 12px))` }}
                                            onClick={() => !item.isDirectory && preview(`${API_URL}/shares/${id}/files/${item.id}`, item.name)}
                                        >
                                            <div className="bg-black p-2 rounded-lg flex-shrink-0 relative group-hover:bg-neutral-700 transition">
                                                {item.isDirectory ? <FolderIcon className="w-4 h-4 text-primary-300" /> : <div className="uppercase text-xs font-bold text-primary-300 min-w-[2.5rem] w-auto text-center">{item.name.split('.').pop()}</div>}
                                                {depth > 0 && <div className="absolute -left-3 top-1/2 -translate-y-1/2 w-2 h-[1px] bg-neutral-600"></div>}
                                            </div>
                                            <div className="min-w-0 flex-1">
                                                <p className={`text-neutral-200 font-medium truncate text-sm md:text-base ${item.isDirectory ? 'text-primary-200' : 'group-hover:text-primary-200 transition'}`}>{item.name}</p>
                                                {!item.isDirectory && <p className="text-neutral-500 text-xs">{formatBytes(item.size)}</p>}
                                            </div>
                                        </div>

                                        {!item.isDirectory && (
                                            <div className="flex items-center gap-2">
                                                <button
                                                    onClick={() => preview(`${API_URL}/shares/${id}/files/${item.id}`, item.name)}
                                                    className="text-neutral-400 hover:text-white p-2 rounded hover:bg-neutral-800 transition hidden md:block"
                                                    title="Preview"
                                                >
                                                    <Eye className="w-4 h-4" />
                                                </button>
                                                <a
                                                    href={`${API_URL}/shares/${encodeURIComponent(id!)}/files/${encodeURIComponent(item.id)}`}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="text-primary-300 hover:text-white p-2 rounded hover:bg-neutral-800 transition flex-shrink-0"
                                                    title="Download"
                                                >
                                                    <Download className="w-4 h-4" />
                                                </a>
                                            </div>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                        <a
                            href={`${API_URL}/shares/${encodeURIComponent(id!)}/download`}
                            target="_blank"             // Opent in nieuw tabblad
                            rel="noopener noreferrer"
                            className="block w-full bg-gradient-brand hover:brightness-90 text-center text-white font-bold py-3 rounded-lg transition btn-press shadow-lg shadow-green-900/20"
                        >
                            Download everything (.zip)
                        </a>
                    </div>
                )}
            </div>
            <Footer />
        </div>
    );
};
