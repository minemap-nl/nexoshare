import React, { useState, useEffect, useRef } from 'react';
import { useParams } from 'react-router-dom';
import {
    Download, Upload, File as FileIcon, Folder as FolderIcon, X, Check,
    Loader2, FileQuestion, CloudUpload, Eye, XCircle,
} from 'lucide-react';
import axios from 'axios';
import { API_URL } from '../api/constants';
import {
    computeChunkHash,
    getBackoffDelay,
    generateUUID,
    sortFiles,
    synthesizeDirectoryItems,
    traverseFileTree,
    processHandle,
    formatBytes,
} from '../lib';
import type { UploadItem } from '../types/upload';
import { useAppConfig } from '../context/AppConfigContext';
import { useUI } from '../context/UIContext';
import { GlobalStyles } from '../components/layout/GlobalStyles';
import { Footer } from '../components/layout/Footer';


export function GuestUploadPage() {
    const { id } = useParams();
    const [info, setInfo] = useState<any>(null);
    const [error, setError] = useState<string | null>(null); // State toevoegen
    const [password, setPassword] = useState('');
    const [unlocked, setUnlocked] = useState(false);
    const { notify, preview } = useUI();
    const { config: guestCfg } = useAppConfig();
    const [files, setFiles] = useState<UploadItem[]>([]);
    const [uploading, setUploading] = useState(false);
    const [finalizing, setFinalizing] = useState(false);
    const [success, setSuccess] = useState(false);
    const [progress, setProgress] = useState(0);
    const fileInputRef = useRef<HTMLInputElement>(null);
    const folderInputRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        // Fetch met error handling
        fetch(`${API_URL}/public/reverse/${id}`)
            .then(async r => {
                if (r.status === 404) { setError('Upload link not found'); return null; }
                if (r.status === 410) { setError('This upload link has expired'); return null; }
                if (!r.ok) { setError('Error loading upload page'); return null; }
                return r.json();
            })
            .then(data => {
                if (data) {
                    setInfo(data);
                    if (!data.protected) setUnlocked(true);
                }
            })
            .catch(() => setError('Network error'));
    }, [id]);

    const verify = async () => { const res = await fetch(`${API_URL}/public/reverse/${id}/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }) }); const json = await res.json(); if (json.valid) setUnlocked(true); else notify('Wrong password', "error"); };

    // Reuse logic from UploadView
    const handleDrop = async (e: any) => {
        e.preventDefault();
        const items = e.dataTransfer.items;
        if (items) {
            const promises = [];
            for (let i = 0; i < items.length; i++) {
                const item = items[i].webkitGetAsEntry ? items[i].webkitGetAsEntry() : null;
                if (item) promises.push(traverseFileTree(item));
                else if (items[i].kind === 'file') {
                    const f = items[i].getAsFile();
                    if (f) promises.push(Promise.resolve([{ file: f, path: f.name, name: f.name, id: generateUUID(), isDirectory: false, size: f.size }]));
                }
            }
            const results = await Promise.all(promises);
            setFiles(prev => sortFiles(synthesizeDirectoryItems([...prev, ...results.flat()])));
        } else if (e.target.files) {
            const newFiles = Array.from(e.target.files as FileList).map((f: any) => ({
                file: f, path: f.webkitRelativePath || f.name, name: f.name, id: generateUUID(), isDirectory: false, size: f.size
            }));
            setFiles(prev => sortFiles(synthesizeDirectoryItems([...prev, ...newFiles])));
        }
    };

    const onPickFolder = async () => {
        try {
            // @ts-ignore
            if (window.showDirectoryPicker) {
                // @ts-ignore
                const dirHandle = await window.showDirectoryPicker();
                const items = await processHandle(dirHandle);
                setFiles(prev => sortFiles(synthesizeDirectoryItems([...prev, ...items])));
            } else folderInputRef.current?.click();
        } catch (err: any) { if (err.name !== 'AbortError') folderInputRef.current?.click(); }
    };

    // Warn before leaving page during upload
    useEffect(() => {
        const handleBeforeUnload = (e: BeforeUnloadEvent) => {
            if ((window as any).__uploading) {
                e.preventDefault();
                e.returnValue = 'Upload in progress. Are you sure you want to leave?';
                return e.returnValue;
            }
        };
        window.addEventListener('beforeunload', handleBeforeUnload);
        return () => window.removeEventListener('beforeunload', handleBeforeUnload);
    }, []);

    const handleUpload = async () => {
        setUploading(true);
        setProgress(0);
        (window as any).__uploading = true;


        try {
            const cfg = guestCfg;
            const k = 1024;
            const sizeMap: any = { 'KB': k, 'MB': k * k, 'GB': k * k * k, 'TB': k * k * k * k };
            const chunkSizeVal = (cfg?.chunkSizeVal as number) || 20;
            const chunkSizeUnit = (cfg?.chunkSizeUnit as string) || 'MB';
            const CHUNK_SIZE = chunkSizeVal * (sizeMap[chunkSizeUnit] || sizeMap['MB']);

            // Init call
            const initRes = await axios.post(`${API_URL}/public/reverse/${id}/init`);
            if (!initRes.data.success) throw new Error('Init failed');

            const uploadableFiles = files.filter(f => !f.isDirectory && f.file && !f.cancelled);
            const uploadedFilesMeta = [];
            const totalUploadSize = uploadableFiles.reduce((acc, f) => acc + f.size, 0);
            let uploadedBytes = 0;

            // Abort controller for guest uploads
            const abortController = new AbortController();
            (window as any).__uploadAbortController = abortController;

            const uploadChunk = async (file: File, fileId: string, chunkIndex: number, _totalChunks: number): Promise<boolean> => {
                const start = chunkIndex * CHUNK_SIZE;
                const end = Math.min(start + CHUNK_SIZE, file.size);
                const chunk = file.slice(start, end);
                
                const chunkHash = await computeChunkHash(chunk);
                
                const fd = new FormData();
                fd.append('chunk', chunk);
                fd.append('chunkIndex', chunkIndex.toString());
                fd.append('fileName', file.name);
                fd.append('fileId', fileId);
                fd.append('chunkHash', chunkHash);

                let attempts = 0;
                const maxAttempts = 10;
                while (attempts < maxAttempts) {
                    try {
                        await axios.post(`${API_URL}/public/reverse/${id}/chunk`, fd, {
                            headers: { 'X-Chunk-Size': CHUNK_SIZE.toString() },
                            signal: abortController.signal
                        });
                        return true;
                    } catch (err: any) {
                        attempts++;
                        if (err.name === 'AbortError' || err.message?.includes('cancel')) return false;
                        if (err.response?.status === 400 || err.response?.status === 413) throw err;
                        if (attempts >= maxAttempts) throw new Error('Upload failed');
                        await new Promise(res => setTimeout(res, getBackoffDelay(attempts)));
                    }
                }
                return false;
            };

            const MAX_PARALLEL = 3;
            
            for (const item of uploadableFiles) {
                // Check if cancelled
                const currentFileState = files.find(f => f.id === item.id);
                if (!currentFileState || currentFileState.cancelled) continue;
                
                const file = item.file as File;
                const fileId = generateUUID();
                const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

                if (totalChunks > 0) {
                    const ok0 = await uploadChunk(file, fileId, 0, totalChunks);
                    if (!ok0) throw new Error('cancelled');
                    uploadedBytes += Math.min(CHUNK_SIZE, file.size);
                    setProgress(Math.min(Math.round((uploadedBytes * 100) / totalUploadSize), 99));
                    setFiles(prev => prev.map(f =>
                        f.id === item.id
                            ? { ...f, uploadProgress: Math.min(Math.round((1 / totalChunks) * 100), 99) }
                            : f
                    ));
                }
                for (let batchStart = 1; batchStart < totalChunks; batchStart += MAX_PARALLEL) {
                    const batchEnd = Math.min(batchStart + MAX_PARALLEL, totalChunks);
                    const promises = [];
                    for (let chunkIndex = batchStart; chunkIndex < batchEnd; chunkIndex++) {
                        promises.push(uploadChunk(file, fileId, chunkIndex, totalChunks));
                    }
                    const results = await Promise.all(promises);
                    if (results.includes(false)) {
                        throw new Error('cancelled');
                    }
                    uploadedBytes += (batchEnd - batchStart) * CHUNK_SIZE;
                    setProgress(Math.min(Math.round((uploadedBytes * 100) / totalUploadSize), 99));
                    
                    setFiles(prev => prev.map(f => 
                        f.id === item.id 
                            ? { ...f, uploadProgress: Math.min(Math.round(((batchEnd) / totalChunks) * 100), 99) }
                            : f
                    ));
                }
                
                const fileState = files.find(f => f.id === item.id);
                if (!fileState?.cancelled) {
                    uploadedFilesMeta.push({ fileName: file.name, originalName: item.path, fileId: fileId, size: file.size, mimeType: file.type });
                }
            }

            setProgress(99);
            setFinalizing(true);
            
            if (uploadedFilesMeta.length === 0) {
                setFiles([]);
                notify('Upload cancelled', 'info');
                return;
            }
            
            await axios.post(`${API_URL}/public/reverse/${id}/finalize`, { files: uploadedFilesMeta });
            setFinalizing(false);
            setSuccess(true);

        } catch (e: any) {
            if (e.name === 'AbortError' || e.message?.includes('cancel')) {
                setFiles(prev => prev.map(f => ({ ...f, cancelled: false, uploadProgress: 0 })));
                notify('Upload cancelled', 'info');
                return;
            }
            const msg = e.response?.data?.error || e.message || 'Error during upload';
            notify(msg, "error");
        } finally {
            delete (window as any).__uploadAbortController;
            delete (window as any).__uploading;
            setUploading(false);
            setFinalizing(false);
            setProgress(0);
            setFiles(prev => prev.map(f => ({ ...f, cancelled: false, uploadProgress: 0 })));
        }
    };

    // Error UI renderen
    if (error) return (
        <div className="min-h-screen bg-app flex items-center justify-center p-4">
            <div className="bg-neutral-900 p-8 rounded-2xl border border-neutral-800 max-w-md w-full text-center anim-scale">
                <div className="w-16 h-16 bg-neutral-800 rounded-full flex items-center justify-center mx-auto mb-4">
                    <XCircle className="w-8 h-8 text-red-500" />
                </div>
                <h2 className="heading-panel mb-2">Unavailable</h2>
                <p className="text-neutral-400">{error}</p>
                <a href="/" className="mt-6 inline-block text-primary-300 hover:text-white transition text-sm font-medium">Go to home</a>
            </div>
        </div>
    );

    if (!info) return <div className="min-h-screen bg-app flex items-center justify-start pt-24 md:pt-32 text-white">Loading...</div>;
    if (success) return (
        <div className="min-h-screen bg-app flex items-center justify-start pt-24 md:pt-32 p-4 flex-col">
            <div className="bg-neutral-900 p-8 rounded-2xl border border-neutral-800 text-center max-w-md w-full anim-scale mb-8">
                <Check className="w-16 h-16 text-green-500 mx-auto mb-4" />
                <h1 className="heading-section">Thanks!</h1>
                <p className="text-neutral-400 mt-2">Your files have been sent successfully.</p>

                {/* Toon custom bericht indien aanwezig */}
                {info && info.thankYouMessage && (
                    <div className="mt-6 bg-black/50 p-4 rounded-xl border border-neutral-800 text-primary-200 italic">
                        "{info.thankYouMessage}"
                    </div>
                )}
            </div>
            <Footer />
        </div>
    );

    return (
        <div className="min-h-screen bg-app flex items-center justify-start pt-24 md:pt-32 p-4 flex-col">
            <GlobalStyles />
            <div className="bg-neutral-900 p-6 md:p-8 rounded-2xl border border-neutral-800 max-w-lg w-full anim-slide shadow-2xl mb-8">
                <div className="text-center mb-8">
                    <div className="w-16 h-16 bg-primary/20 rounded-2xl flex items-center justify-center mx-auto mb-4"><Upload className="w-8 h-8 text-primary-400" /></div>
                    <h1 className="heading-section">{info.name}</h1>
                    <p className="text-neutral-400">Upload files to this folder.</p>
                </div>
                {!unlocked ? (
                    <form
                        onSubmit={(e) => { e.preventDefault(); verify(); }}
                        className="space-y-4 anim-fade"
                    >
                        <input
                            className="input-field text-center"
                            type="password"
                            placeholder="Password required"
                            value={password}
                            onChange={e => setPassword(e.target.value)}
                            autoFocus // Handig: cursor staat er direct in
                        />
                        <button
                            type="submit"
                            className="w-full bg-gradient-brand hover:brightness-110 text-white p-3 rounded-lg font-bold transition-all btn-press"
                        >
                            Unlock
                        </button>
                    </form>
                ) : (
                    <div className="space-y-6 anim-fade">

                        {/* @ts-ignore */}
                        <input className="hidden" webkitdirectory="" mozdirectory="" type="file" ref={folderInputRef} onChange={(e) => {
                            if (e.target.files) {
                                const newFiles = Array.from(e.target.files as FileList).map((f: any) => ({
                                    file: f, path: f.webkitRelativePath || f.name, name: f.name, id: generateUUID(), isDirectory: false, size: f.size
                                }));
                                setFiles(prev => sortFiles(synthesizeDirectoryItems([...prev, ...newFiles])));
                                e.target.value = '';
                            }
                        }} />

                        <div
                            className="isolate group relative flex flex-col items-center justify-center overflow-hidden rounded-2xl bg-neutral-900 p-8 md:p-10 min-h-[250px] md:min-h-[300px] outline-none focus-visible:outline-none [transform:translateZ(0)] [backface-visibility:hidden]"
                            onDragOver={e => e.preventDefault()}
                            onDrop={handleDrop}
                        >
                            <div className="pointer-events-none absolute inset-0 z-0 rounded-2xl bg-primary-400/[0.06] opacity-0 transition-opacity duration-300 ease-out group-hover:opacity-100" aria-hidden />
                            <div className="pointer-events-none absolute inset-0 z-[1] rounded-2xl border-2 border-dashed border-neutral-800" aria-hidden />
                            <div className="pointer-events-none absolute inset-0 z-[2] rounded-2xl border-2 border-dashed border-primary-400 opacity-0 transition-opacity duration-300 ease-out group-hover:opacity-100" aria-hidden />
                            <div className="absolute inset-0 z-[3] cursor-pointer" onClick={() => fileInputRef.current?.click()} />

                            <div className="relative z-10 text-center pointer-events-none mb-4">
                                <div className="w-16 h-16 bg-gradient-brand-tr rounded-full flex items-center justify-center mx-auto mb-4 shadow-xl transition-transform duration-300 group-hover:scale-[1.03]">
                                    <CloudUpload className="text-white w-8 h-8" />
                                </div>
                                <h3 className="heading-panel mb-2">Drag & Drop files</h3>
                                <p className="text-neutral-400 text-sm max-w-xs mx-auto mb-6">or click to browse from your computer</p>
                            </div>

                            <div className="relative z-20 flex gap-3 mt-0 pb-6 pointer-events-auto">
                                <button onClick={(e) => { e.stopPropagation(); fileInputRef.current?.click(); }} className="text-xs bg-neutral-800 hover:bg-neutral-700 text-white px-3 py-2 rounded-lg transition border border-neutral-700 cursor-pointer hover:border-primary-400">Select Files</button>
                                <button onClick={(e) => { e.stopPropagation(); onPickFolder(); }} className="text-xs bg-neutral-800 hover:bg-neutral-700 text-white px-3 py-2 rounded-lg transition border border-neutral-700 flex items-center gap-2 cursor-pointer hover:border-primary-400"><FolderIcon className="w-3 h-3" /> Select Folder</button>
                            </div>
                            {info.maxSize && (
                                <div className="mt-0 px-3 py-1 rounded-full bg-neutral-800 border border-neutral-700 text-xs text-neutral-400 font-medium group-hover:border-primary-400/30 group-hover:text-primary-200 mb-4 md:mb-0">
                                    Max size: {formatBytes(info.maxSize)}
                                </div>
                            )}
                        </div>

                        {/* @ts-ignore */}
                        <input ref={fileInputRef} type="file" multiple className="hidden" onChange={e => {
                            if (e.target.files) {
                                const newFiles = Array.from(e.target.files as FileList).map((f: any) => ({
                                    file: f, path: f.webkitRelativePath || f.name, name: f.name, id: generateUUID(), isDirectory: false, size: f.size
                                }));
                                setFiles(prev => sortFiles(synthesizeDirectoryItems([...prev, ...newFiles])));
                                e.target.value = '';
                            }
                        }} />

                        {files.length > 0 && (
                            <div className="mt-2 bg-neutral-900 rounded-2xl border border-neutral-800 overflow-hidden shadow-xl" style={{ "--indent-step": "24px" } as React.CSSProperties}>
                                <style>{`@media (max-width: 768px) { [style*="--indent-step"] { --indent-step: 12px !important; } }`}</style>
                                <div className="max-h-[300px] overflow-y-auto">
                                    {files.filter(f => !f.cancelled || uploading).map((item) => {
                                        const segments = item.path.split('/');
                                        const depth = Math.max(0, segments.length - 1);
                                        // Using calc with var for responsive indent
                                        return (
                                            <div key={item.id} className={`flex justify-between items-center px-3 py-2 md:px-4 md:py-3 border-b border-neutral-800 last:border-0 hover:bg-neutral-800/50 transition gap-2 ${item.isDirectory ? 'bg-neutral-800/30' : ''}`}>
                                                <div
                                                    className="flex items-center gap-2 md:gap-4 overflow-hidden flex-1 min-w-0 cursor-pointer"
                                                    style={{ paddingLeft: `calc(${depth} * var(--indent-step, 12px))` }}
                                                    onClick={() => !item.isDirectory && item.file && preview(item.file, item.name)}
                                                >
                                                    <div className="bg-black p-2 rounded-lg flex-shrink-0 relative">
                                                        {item.isDirectory ? <FolderIcon className="w-4 h-4 text-primary-300" /> : <div className="uppercase text-xs font-bold text-primary-300">{item.name.split('.').pop()}</div>}
                                                        {depth > 0 && <div className="absolute -left-3 top-1/2 -translate-y-1/2 w-2 h-[1px] bg-neutral-600"></div>}
                                                    </div>
                                                    <div className="min-w-0 flex-1">
                                                        <p className={`text-white font-medium truncate text-sm md:text-base ${item.isDirectory ? 'text-primary-200' : ''}`}>{item.name}</p>
                                                        {!item.isDirectory && <p className="text-neutral-500 text-xs">{formatBytes(item.size)}</p>}
                                                    </div>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    {!item.isDirectory && (
                                                        <button
                                                            onClick={(e) => { e.stopPropagation(); item.file && preview(item.file, item.name); }}
                                                            className="text-neutral-500 hover:text-white p-2 transition flex-shrink-0 hidden md:block"
                                                            title="Preview"
                                                        >
                                                            <Eye className="w-4 h-4 md:w-5 md:h-5" />
                                                        </button>
                                                    )}
                                                    <button onClick={(e) => {
                                                        e.stopPropagation();
                                                        setFiles(prev => prev.filter(x => x.id !== item.id && !x.path.startsWith(item.path + '/')));
                                                    }} className="text-neutral-500 hover:text-red-400 p-2 transition flex-shrink-0"><X className="w-4 h-4 md:w-5 md:h-5" /></button>
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>
                        )}

                        {uploading && (
                            <div className="w-full">
                                <div className="flex justify-between items-end mb-2">
                                    <div className="text-left text-[10px] font-bold text-white uppercase tracking-wider">
                                        {finalizing ? 'Finalizing & Scanning...' : 'Uploading...'}
                                    </div>
                                    <div className="text-right text-[10px] text-neutral-500 font-bold tabular-nums">
                                        {progress}%
                                    </div>
                                </div>
                                <div className="w-full bg-neutral-800 rounded-full h-2.5 overflow-hidden border border-neutral-700 p-0.5">
                                    <div 
                                        className={`h-full rounded-full transition-all duration-300 relative ${finalizing ? 'bg-primary-500 w-full animate-pulse' : 'bg-green-500'}`} 
                                        style={{ width: finalizing ? '100%' : `${progress}%` }}
                                    >
                                        {finalizing && <div className="absolute inset-0 animate-scan rounded-full" />}
                                    </div>
                                </div>
                                {finalizing && (
                                    <p className="text-[10px] text-neutral-500 mt-1.5 text-center">Server is assembling files and checking for viruses. Please wait.</p>
                                )}
                            </div>
                        )}

                        <button onClick={handleUpload} disabled={uploading || files.length === 0} className="w-full bg-green-600 hover:bg-green-700 text-white p-3 rounded-lg font-bold disabled:bg-neutral-800 transition btn-press shadow-lg">
                            {finalizing ? "Processing..." : uploading ? `Uploading (${progress}%)...` : `Send ${files.length} files`}
                        </button>
                    </div>
                )}
            </div>
            <Footer />
        </div>
    );
};
