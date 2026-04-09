import React, { useState, useEffect, useRef, useCallback } from 'react';
import { AnimatePresence, motion } from 'framer-motion';

import { useParams } from 'react-router-dom';
import {
    Download, Upload, File as FileIcon, Folder as FolderIcon, X, Check, Share2, Settings,
    LogOut, User, Shield,
    Trash2, Send, AlertTriangle, Loader2, Info, HelpCircle,
    XCircle, FileQuestion, CloudUpload, Eye,
    Plus, AlertCircle, ArrowRight, ChevronDown, Edit,
    Mail, Type, HardDrive, Calendar, MessageSquare, Globe,
    Sparkles, FileArchive, Contact, Lock as LockIcon
} from 'lucide-react';
import axios from 'axios';
import DOMPurify from 'dompurify';
import { useEscapeKey } from '../hooks/useEscapeKey';
import {
    startRegistration,
    startAuthentication
} from '@simplewebauthn/browser';
import { API_URL } from '../api/constants';
import {
    SHARES_LIST_CHANGED_EVENT,
    dispatchSharesListChanged,
    ACTIVE_UPLOAD_SHARE_EVENT,
    dispatchActiveUploadShare,
    dispatchConfigChanged,
    saveUploadState,
    loadUploadState,
    clearUploadState,
    formatBytes,
    UNITS,
    getUnitLabel,
    getFutureDate,
    computeChunkHash,
    getBackoffDelay,
    generateUUID,
    isValidHttpUrl,
    sortFiles,
    synthesizeDirectoryItems,
    traverseFileTree,
    processHandle,
} from '../lib';
import type { UploadItem, FileSystemHandle, FileSystemFileHandle, FileSystemDirectoryHandle } from '../types/upload';
import { useAppConfig } from '../context/AppConfigContext';
import { useUI } from '../context/UIContext';
import { GlobalStyles } from '../components/layout/GlobalStyles';
import { Footer } from '../components/layout/Footer';
import { ModalPortal } from '../components/ui/ModalPortal';
import { CopyButton } from '../components/ui/CopyButton';
import { Checkbox } from '../components/ui/Checkbox';
import { ExtensionSelector } from '../components/ui/ExtensionSelector';
import { Tooltip } from '../components/ui/Tooltip';


export type UploadViewProps = {
    active: boolean;
    onUploadSurfaceChange?: (s: { showSuccess: boolean }) => void;
    registerReset?: React.MutableRefObject<(() => void) | null>;
};

export function UploadView({ active, onUploadSurfaceChange, registerReset }: UploadViewProps) {
    const [files, setFiles] = useState<UploadItem[]>([]);
    const [uploading, setUploading] = useState(false);
    const [uploadProgress, setUploadProgress] = useState(0);
    const [result, setResult] = useState<any>(null);
    const [showSettings, setShowSettings] = useState(false);
    const [options, setOpts] = useState({
        name: '', password: '', recipients: '', message: '', customSlug: '',
        expirationVal: 1, expirationUnit: 'Weeks',
        maxDownloads: undefined as number | undefined
    });
    const [idLength, setIdLength] = useState(12);
    const [contacts, setContacts] = useState<any[]>([]);
    const fileInputRef = useRef<HTMLInputElement>(null);
    const folderInputRef = useRef<HTMLInputElement>(null); // Nieue Ref voor mappen
    /** Houdt altijd de laatste files/options bij voor async upload + sessionStorage (geen stale closure). */
    const filesRef = useRef<UploadItem[]>(files);
    const optionsRef = useRef(options);
    const hasSeenSuccessWhileUploadTabActiveRef = useRef(false);
    const pendingResetOnNextUploadFocusRef = useRef(false);
    const prevActiveRef = useRef(active);
    const { notify, preview, isConfirming, isPreviewing } = useUI();

    // Must not rely on useEffect: if the user switches tabs before effects run, hasSeen would stay false
    // and leaving the Upload tab would never arm pendingReset (Docker / fast navigation).
    if (active && result) {
        hasSeenSuccessWhileUploadTabActiveRef.current = true;
    }
    const { config: appCfg } = useAppConfig();

    useEffect(() => { filesRef.current = files; }, [files]);
    useEffect(() => { optionsRef.current = options; }, [options]);

    useEscapeKey(() => setShowSettings(false), showSettings && !isConfirming && !isPreviewing);
    const [locale, setLocale] = useState('en-GB');
    const [maxLimitLabel, setMaxLimitLabel] = useState('');
    const uploadDefaultsFromConfigApplied = useRef(false);

    useEffect(() => {
        const cfg = appCfg;
        if (!cfg || typeof cfg !== 'object' || Object.keys(cfg).length === 0) return;
        if (cfg.appLocale) setLocale(cfg.appLocale as string);
        if (cfg.shareIdLength) {
            const sl = parseInt(String(cfg.shareIdLength), 10);
            if (!Number.isNaN(sl)) {
                setIdLength(sl);
                generateId(sl);
            }
        }
        if (!uploadDefaultsFromConfigApplied.current) {
            uploadDefaultsFromConfigApplied.current = true;
            setOpts(prev => ({
                ...prev,
                expirationVal: (cfg.defaultExpirationVal as number) ?? 1,
                expirationUnit: (cfg.defaultExpirationUnit as string) || 'Weeks'
            }));
        }
        const maxVal = (cfg.maxSizeVal as number) ?? 10;
        const maxUnit = (cfg.maxSizeUnit as string) || 'GB';
        setMaxLimitLabel(`${maxVal} ${maxUnit}`);
    }, [appCfg]);

    useEffect(() => {
        const loadData = async () => {
            try {
                const res = await fetch(`${API_URL}/contacts`, { credentials: 'include' });
                if (res.ok) {
                    const data = await res.json();
                    if (Array.isArray(data)) setContacts(data);
                }
            } catch (e) { console.error(e); }
        };
        loadData();

        // Restore from sessionStorage (page refresh). File/Blob objecten zijn niet te serialiseren — geen file-lijst herstellen.
        const saved = loadUploadState();
        if (saved) {
            if (saved.options) setOpts(saved.options);
            if (saved.result && !saved.uploading) setResult(saved.result);
            // Na refresh bestaat er geen lopende JS-upload meer; voorkom valse "uploading" in storage/UI.
            if (saved.uploading) {
                clearUploadState();
                const { uploading: _u, files: _f, progress: _p, ...kept } = saved;
                saveUploadState({ ...kept, uploading: false });
            }
        }
    }, []);

    const generateId = async (len: number) => {
        try {
            const res = await fetch(`${API_URL}/utils/generate-id?length=${len}`, { credentials: 'include' });
            const data = await res.json();
            if (data.id) setOpts(prev => ({ ...prev, customSlug: data.id }));
        } catch (e) { console.error(e); }
    };

    const handleDrop = async (e: any) => {
        e.preventDefault();

        const items = e.dataTransfer.items;
        if (items) {
            const promises = [];
            for (let i = 0; i < items.length; i++) {
                const item = items[i].webkitGetAsEntry ? items[i].webkitGetAsEntry() : null;
                if (item) {
                    promises.push(traverseFileTree(item));
                } else if (items[i].kind === 'file') {
                    // Fallback
                    const f = items[i].getAsFile();
                    if (f) promises.push(Promise.resolve([{
                        file: f,
                        path: f.name,
                        name: f.name,
                        id: generateUUID(),
                        isDirectory: false,
                        size: f.size
                    }]));
                }
            }
            const results = await Promise.all(promises);
            let flatFiles = results.flat();

            // Consolidate and Sort
            setFiles(prev => {
                const updated = sortFiles(synthesizeDirectoryItems([...prev, ...flatFiles]));
                if (!uploading) saveUploadState({ files: updated, options: optionsRef.current, uploading: false });
                return updated;
            });
        } else if (e.target.files) {
            // Fallback
            const newFiles = Array.from(e.target.files as FileList).map((f: any) => ({
                file: f,
                path: f.webkitRelativePath || f.name,
                name: f.name,
                id: generateUUID(),
                isDirectory: false,
                size: f.size
            }));
            setFiles(prev => {
                const updated = sortFiles(synthesizeDirectoryItems([...prev, ...newFiles]));
                if (!uploading) saveUploadState({ files: updated, options: optionsRef.current, uploading: false });
                return updated;
            });
        }

        // Reset inputs
        if (e.target.value) e.target.value = '';
    };

    const handleFileSelect = (e: any) => {
        if (e.target.files) {
            const newFiles = Array.from(e.target.files as FileList).map((f: any) => ({
                file: f,
                path: f.webkitRelativePath || f.name,
                name: f.name,
                id: generateUUID(),
                isDirectory: false,
                size: f.size
            }));

            setFiles(prev => {
                const updated = sortFiles(synthesizeDirectoryItems([...prev, ...newFiles]));
                if (!uploading) saveUploadState({ files: updated, options: optionsRef.current, uploading: false });
                return updated;
            });
            e.target.value = '';
        }
    };

    // --- On Pick Folder: Native API with Fallback ---
    const onPickFolder = async () => {
        try {
            // @ts-ignore: API might not be in standard definitions yet
            if (window.showDirectoryPicker) {
                // @ts-ignore
                const dirHandle = await window.showDirectoryPicker();
                const items = await processHandle(dirHandle);
                setFiles(prev => {
                    const updated = sortFiles(synthesizeDirectoryItems([...prev, ...items]));
                    if (!uploading) saveUploadState({ files: updated, options: optionsRef.current, uploading: false });
                    return updated;
                });
            } else {
                // Fallback for Safari/Firefox
                folderInputRef.current?.click();
            }
        } catch (err: any) {
            // AbortError means user cancelled, ignore.
            if (err.name !== 'AbortError') {
                console.error('Folder pick failed, trying fallback...', err);
                folderInputRef.current?.click();
            }
        }
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
        setShowSettings(false);
        setUploadProgress(0);
        (window as any).__uploading = true;

        let currentShareId: string | null = null;
        /** Voorkomt dat finally sessionStorage opnieuw vult na clearUploadState (cancel / lege upload / success). */
        let storageHandled = false;

        const optsNow = optionsRef.current;
        saveUploadState({ files: filesRef.current, options: optsNow, uploading: true, progress: 0 });

        try {
            const configRes = await fetch(`${API_URL}/config`, { credentials: 'include' });
            const config = await configRes.json();

            const k = 1024;
            const sizeMap: any = { 'KB': k, 'MB': k * k, 'GB': k * k * k, 'TB': k * k * k * k };
            const maxBytes = (config.maxSizeVal || 10) * (sizeMap[config.maxSizeUnit] || sizeMap['MB']);

            const uploadableFiles = filesRef.current.filter(f => !f.isDirectory && f.file && !f.cancelled);
            const totalUploadSize = uploadableFiles.reduce((acc, item) => acc + item.size, 0);

            if (uploadableFiles.length === 0) {
                notify('No files to upload', 'error');
                return;
            }

            if (totalUploadSize > maxBytes) {
                throw new Error(`Total size (${formatBytes(totalUploadSize)}) exceeds the limit of ${config.maxSizeVal} ${config.maxSizeUnit}.`);
            }

            const chunkSizeVal = config.chunkSizeVal || 20;
            const chunkSizeUnit = config.chunkSizeUnit || 'MB';
            const CHUNK_SIZE = chunkSizeVal * (sizeMap[chunkSizeUnit] || sizeMap['MB']);

            const initPayload = { ...optsNow, totalUploadBytes: totalUploadSize };
            const initRes = await axios.post(`${API_URL}/shares/init`, initPayload);

            if (!initRes.data.success) throw new Error('Initialization failed');

            const shareId = initRes.data.shareId;
            currentShareId = shareId;
            dispatchActiveUploadShare(shareId);

            const uploadedFilesMeta: { fileName: string; originalName: string; fileId: string; size: number; mimeType: string }[] = [];
            let uploadedBytes = 0;
            const totalBytes = Math.max(totalUploadSize, 1);

            const abortController = new AbortController();
            (window as any).__uploadAbortController = abortController;

            const MAX_PARALLEL_CHUNKS = 3;

            const uploadChunk = async (file: File, fileId: string, chunkIndex: number, totalChunks: number): Promise<boolean> => {
                const start = chunkIndex * CHUNK_SIZE;
                const end = Math.min(start + CHUNK_SIZE, file.size);
                const chunk = file.slice(start, end);
                const chunkHash = await computeChunkHash(chunk);

                const fd = new FormData();
                fd.append('chunk', chunk);
                fd.append('chunkIndex', chunkIndex.toString());
                fd.append('totalChunks', totalChunks.toString());
                fd.append('fileName', file.name);
                fd.append('fileId', fileId);
                fd.append('totalFileSize', String(file.size));
                fd.append('chunkHash', chunkHash);

                let attempts = 0;
                const maxAttempts = 10;

                while (attempts < maxAttempts) {
                    try {
                        await axios.post(`${API_URL}/shares/${shareId}/chunk`, fd, {
                            headers: { 'X-Chunk-Size': CHUNK_SIZE.toString() },
                            signal: abortController.signal
                        });
                        return true;
                    } catch (err: any) {
                        if (err.name === 'AbortError' || err.message?.includes('cancel')) {
                            return false;
                        }
                        attempts++;
                        if (err.response?.status === 400 || err.response?.status === 413) {
                            throw err;
                        }
                        console.warn(`Chunk ${chunkIndex} failed, retrying (${attempts}/${maxAttempts})...`);
                        if (attempts >= maxAttempts) throw new Error(`Upload failed after ${maxAttempts} attempts.`);
                        await new Promise(res => setTimeout(res, getBackoffDelay(attempts)));
                    }
                }
                return false;
            };

            for (const item of uploadableFiles) {
                const currentFileState = filesRef.current.find(f => f.id === item.id);
                if (!currentFileState || currentFileState.cancelled) {
                    continue;
                }

                const file = item.file as File;
                const fileId = generateUUID();
                const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));

                // Chunk 0 eerst: server vereist bestaand .part voordat latere chunks (parallel) mogen.
                if (totalChunks > 0) {
                    const ok0 = await uploadChunk(file, fileId, 0, totalChunks);
                    if (!ok0) throw new Error('cancelled');
                    uploadedBytes += Math.min(CHUNK_SIZE, file.size);
                }
                for (let batchStart = 1; batchStart < totalChunks; batchStart += MAX_PARALLEL_CHUNKS) {
                    const batchEnd = Math.min(batchStart + MAX_PARALLEL_CHUNKS, totalChunks);
                    const batchPromises: Promise<boolean>[] = [];

                    for (let chunkIndex = batchStart; chunkIndex < batchEnd; chunkIndex++) {
                        batchPromises.push(uploadChunk(file, fileId, chunkIndex, totalChunks));
                    }

                    const results = await Promise.all(batchPromises);

                    if (results.includes(false)) {
                        throw new Error('cancelled');
                    }

                    uploadedBytes += (batchEnd - batchStart) * CHUNK_SIZE;
                    const progress = Math.min(Math.round((uploadedBytes * 100) / totalBytes), 99);
                    setUploadProgress(progress);

                    setFiles(prev => {
                        const updated = prev.map(f =>
                            f.id === item.id
                                ? { ...f, uploadProgress: Math.min(Math.round((batchEnd / totalChunks) * 100), 99) }
                                : f
                        );
                        saveUploadState({
                            files: updated,
                            options: optionsRef.current,
                            uploading: true,
                            progress: Math.min(Math.round((uploadedBytes * 100) / totalBytes), 99)
                        });
                        return updated;
                    });
                }

                const fileState = filesRef.current.find(f => f.id === item.id);
                if (!fileState?.cancelled) {
                    uploadedFilesMeta.push({
                        fileName: file.name,
                        originalName: item.path,
                        fileId: fileId,
                        size: file.size,
                        mimeType: file.type
                    });
                }
            }

            setUploadProgress(99);

            if (uploadedFilesMeta.length === 0) {
                setFiles([]);
                clearUploadState();
                storageHandled = true;
                notify('Upload cancelled', 'info');
                try { await axios.delete(`${API_URL}/shares/${shareId}`); } catch { /* noop */ }
                dispatchSharesListChanged();
                return;
            }

            const finalRes = await axios.post(`${API_URL}/shares/${shareId}/finalize`, {
                files: uploadedFilesMeta
            });

            if (finalRes.data.success) {
                setResult(finalRes.data);
                storageHandled = true;
                saveUploadState({ files: [], options: optionsRef.current, uploading: false, result: finalRes.data });
                notify("Successfully uploaded!", "success");
                dispatchSharesListChanged();
                setTimeout(() => {
                    clearUploadState();
                    setFiles([]);
                }, 2000);
            }

        } catch (e: any) {
            if (e.name === 'AbortError' || e.message?.includes('cancelled')) {
                if (currentShareId) {
                    try { await axios.delete(`${API_URL}/shares/${currentShareId}`); } catch { /* noop */ }
                }
                try {
                    const res = await fetch(`${API_URL}/utils/generate-id?length=12`, { credentials: 'include' });
                    const data = await res.json();
                    if (data.id) setOpts(prev => ({ ...prev, customSlug: data.id }));
                } catch { /* noop */ }
                setFiles(prev => prev.map(f => ({ ...f, cancelled: false, uploadProgress: 0 })));
                notify("Upload cancelled", "info");
                clearUploadState();
                storageHandled = true;
                dispatchSharesListChanged();
                return;
            }

            if (currentShareId) {
                try {
                    await axios.delete(`${API_URL}/shares/${currentShareId}`);
                } catch (cleanupErr) { console.error("Cleanup failed", cleanupErr); }
                dispatchSharesListChanged();
            }

            const msg = e.response?.data?.error || e.message || 'Upload failed';
            notify(msg, "error");
        } finally {
            dispatchActiveUploadShare(null);
            delete (window as any).__uploadAbortController;
            delete (window as any).__uploading;
            setUploading(false);
            setUploadProgress(0);
            setFiles(prev => {
                const next = prev.map(f => ({ ...f, cancelled: false, uploadProgress: 0 }));
                if (!storageHandled) {
                    saveUploadState({
                        files: next,
                        options: optionsRef.current,
                        uploading: false,
                        progress: 0
                    });
                }
                return next;
            });
        }
    };

    const [qrCode, setQrCode] = useState<string | null>(null);

    const reset = useCallback(() => {
        pendingResetOnNextUploadFocusRef.current = false;
        hasSeenSuccessWhileUploadTabActiveRef.current = false;
        setResult(null);
        setQrCode(null);
        clearUploadState();
        setOpts({
            name: '', password: '', recipients: '', message: '', customSlug: '',
            expirationVal: 1, expirationUnit: 'Weeks', maxDownloads: undefined
        });
        generateId(idLength);
    }, [idLength]);

    useEffect(() => {
        onUploadSurfaceChange?.({ showSuccess: !!result });
    }, [result, onUploadSurfaceChange]);

    useEffect(() => {
        if (registerReset) {
            registerReset.current = () => reset();
            return () => { registerReset.current = null; };
        }
    }, [registerReset, reset]);

    useEffect(() => {
        const prev = prevActiveRef.current;
        if (prev && !active) {
            if (result && hasSeenSuccessWhileUploadTabActiveRef.current) {
                pendingResetOnNextUploadFocusRef.current = true;
            }
        }
        if (!prev && active) {
            if (pendingResetOnNextUploadFocusRef.current) {
                pendingResetOnNextUploadFocusRef.current = false;
                hasSeenSuccessWhileUploadTabActiveRef.current = false;
                reset();
            }
        }
        prevActiveRef.current = active;
    }, [active, result, reset]);

    useEffect(() => {
        if (result?.shareUrl) {
            fetch(`${API_URL}/utils/qr?url=${encodeURIComponent(result.shareUrl)}`)
                .then(r => r.json())
                .then(d => setQrCode(d.qr))
                .catch(console.error);
        }
    }, [result]);

    if (result) return (
        <div className="bg-neutral-900 p-4 md:p-8 rounded-2xl border border-neutral-800 text-center max-w-xl mx-auto mt-10 shadow-2xl anim-scale">
            <div className="w-16 h-16 md:w-20 md:h-20 bg-primary/20 rounded-full flex items-center justify-center mx-auto mb-4 md:mb-6"><Check className="text-primary-400 w-8 h-8 md:w-10 md:h-10" /></div>
            <h2 className={`text-2xl md:text-3xl font-bold text-white ${result.recipientsNotified === true ? 'mb-2' : 'mb-6'}`}>Files Shared!</h2>
            {result.recipientsNotified === true && (
                <p className="text-neutral-400 mb-6">The recipients have been notified.</p>
            )}

            <div className="bg-black/50 p-4 rounded-xl mb-6 border border-neutral-800">
                <div className="flex items-center gap-3 mb-4">
                    <CopyButton text={result.shareUrl} className="flex-1 bg-transparent text-white px-2 outline-none font-mono text-sm justify-center break-all whitespace-normal text-center" />
                </div>
                {/* QR Code Sectie - Klikbaar om te kopiëren */}
                {qrCode && (
                    <div className="flex flex-col items-center justify-center pt-6 border-t border-neutral-800 mt-4">
                        <div
                            className="bg-white p-3 rounded-xl mb-3 cursor-pointer shadow-lg transition-transform duration-200 ease-out hover:scale-105 active:scale-95"
                            onClick={async () => {
                                try {
                                    const res = await fetch(qrCode);
                                    const blob = await res.blob();
                                    await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
                                    const el = document.getElementById('qr-hint');
                                    if (el) { el.innerText = "Copied!"; setTimeout(() => el.innerText = "Click to copy QR", 2000); }
                                } catch (e) {
                                    console.error('Copy failed', e);
                                }
                            }}
                        >
                            {qrCode && (qrCode.startsWith('data:image/') || qrCode.startsWith('https://')) ?
                                <img src={qrCode} alt="QR Code" className="w-32 h-32" />
                                : null
                            }
                        </div>
                        <p id="qr-hint" className="text-xs text-neutral-500 font-medium transition-colors">Click to copy QR</p>
                    </div>
                )}
            </div>
            <button onClick={reset} className="text-neutral-400 hover:text-white underline transition">Create new share</button>
        </div>
    );

    return (
        <div className="relative">
            {!uploading && (
            <div
                className="isolate group relative flex flex-col items-center justify-center overflow-hidden rounded-2xl bg-neutral-900 md:p-10 min-h-[250px] md:min-h-[300px] outline-none focus-visible:outline-none [transform:translateZ(0)] [backface-visibility:hidden]"
                onDragOver={e => e.preventDefault()}
                onDrop={handleDrop}
            >
                {/* Rand: géén transition op border-color (geeft wit tussenframes) — paarse rand als aparte laag met opacity-tween */}
                <div className="pointer-events-none absolute inset-0 z-0 rounded-2xl bg-primary-400/[0.06] opacity-0 transition-opacity duration-300 ease-out group-hover:opacity-100" aria-hidden />
                <div className="pointer-events-none absolute inset-0 z-[1] rounded-2xl border-2 border-dashed border-neutral-800" aria-hidden />
                <div className="pointer-events-none absolute inset-0 z-[2] rounded-2xl border-2 border-dashed border-primary-400 opacity-0 transition-opacity duration-300 ease-out group-hover:opacity-100" aria-hidden />
                {/* 1. Invisible Click Overlay for File Upload - Acts as background click */}
                <div
                    className="absolute inset-0 z-[3] cursor-pointer"
                    onClick={() => fileInputRef.current?.click()}
                />

                {/* 2. Hidden Inputs */}
                <input ref={fileInputRef} type="file" multiple className="hidden" onChange={handleFileSelect} />
                {/* @ts-ignore: Directory attribute is standard but TS might complain without proper types */}
                <input ref={folderInputRef} type="file" multiple webkitdirectory="" directory="" className="hidden" onChange={handleFileSelect} />

                {/* 3. Content - Pointer events none on text/icon so clicks fall through to overlay */}
                <div className="relative z-10 pointer-events-none flex flex-col items-center p-6">
                    <div className="bg-black p-3 md:p-4 rounded-full mb-3 md:mb-4 transition-transform duration-300 group-hover:scale-[1.03]"><Upload className="w-8 h-8 md:w-10 md:h-10 text-primary-400" /></div>
                    <h2 className="text-xl font-bold tracking-tight text-white md:text-2xl mb-2">Upload files or folders</h2>
                    <p className="text-sm md:text-base text-neutral-400 text-center max-w-sm">Drag files & folders here, or click to browse files.</p>
                </div>

                {/* 4. Buttons - High Z-Index to catch their own clicks */}
                <div className="relative z-20 flex gap-3 mt-0 pb-6 pointer-events-auto">
                    <button onClick={(e) => { e.stopPropagation(); fileInputRef.current?.click(); }} className="text-xs bg-neutral-800 hover:bg-neutral-700 text-white px-3 py-2 rounded-lg transition border border-neutral-700 cursor-pointer hover:border-primary-400">Select Files</button>
                    <button onClick={(e) => { e.stopPropagation(); onPickFolder(); }} className="text-xs bg-neutral-800 hover:bg-neutral-700 text-white px-3 py-2 rounded-lg transition border border-neutral-700 flex items-center gap-2 cursor-pointer hover:border-primary-400"><FolderIcon className="w-3 h-3" /> Select Folder</button>
                </div>
                {maxLimitLabel && (
                    <div className="mt-0 px-3 py-1 rounded-full bg-neutral-800 border border-neutral-700 text-xs text-neutral-400 font-medium group-hover:border-primary-400/30 group-hover:text-primary-200 mb-4 md:mb-0">
                        Max size: {maxLimitLabel}
                    </div>
                )}
            </div>
            )}

            {files.length > 0 && (
                <div className="mt-2 anim-slide bg-neutral-900 rounded-2xl border border-neutral-800 overflow-hidden shadow-xl" style={{ "--indent-step": "24px" } as React.CSSProperties}>
                    <style>{`@media (max-width: 768px) { .anim-slide { --indent-step: 12px !important; } }`}</style>
                    <div className="max-h-[300px] overflow-y-auto">
                        {files.filter(f => !f.cancelled || uploading).map((item) => {
                            // Calculate depth for indentation
                            // Example path: Folder/Sub/file.txt (depth 2)
                            // Example folder: Folder/Sub (depth 1)
                            const segments = item.path.split('/');
                            // If it is a folder, it doesn't have a filename at the end, so segments length matches depth closer?
                            // Actually, just using split length - 1 works well if paths are consistent.
                            const depth = Math.max(0, segments.length - 1);
                            // Responsive indentation using CSS variable defined in parent or fallback
                            // We use style with calc for responsive indent

                            return (
                                <div key={item.id} className={`flex justify-between items-center px-3 py-2 md:px-4 md:py-3 border-b border-neutral-800 last:border-0 hover:bg-neutral-800/50 transition gap-2 ${item.isDirectory ? 'bg-neutral-800/30' : ''}`}>
                                    <div
                                        className="flex items-center gap-2 md:gap-4 overflow-hidden flex-1 min-w-0 cursor-pointer"
                                        style={{ paddingLeft: `calc(${depth} * var(--indent-step, 12px))` }}
                                        onClick={() => !item.isDirectory && item.file && preview(item.file, item.name)}
                                    >
                                        <div className="bg-black p-2 rounded-lg flex-shrink-0 relative">
                                            {item.uploadProgress !== undefined && item.uploadProgress > 0 ? (
                                                <div className="relative w-8 h-8">
                                                    <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                                                        <circle cx="18" cy="18" r="16" fill="none" stroke="#374151" strokeWidth="3"/>
                                                        <circle cx="18" cy="18" r="16" fill="none" stroke="#14b8a6" strokeWidth="3" 
                                                            strokeDasharray="100" strokeLinecap="round" style={{strokeDashoffset: 100 - item.uploadProgress}}/>
                                                    </svg>
                                                </div>
                                            ) : item.isDirectory ? (
                                                <FolderIcon className="w-4 h-4 text-primary-300" />
                                            ) : (
                                                <div className="uppercase text-xs font-bold text-primary-300">{item.name.split('.').pop()}</div>
                                            )}
                                            {depth > 0 && <div className="absolute -left-3 top-1/2 -translate-y-1/2 w-2 h-[1px] bg-neutral-600"></div>}
                                        </div>
                                        <div className="min-w-0 flex-1">
                                            <p className={`text-white font-medium truncate text-sm md:text-base ${item.isDirectory ? 'text-primary-200' : ''}`}>{item.name}</p>
                                            {!item.isDirectory && (
                                                <p className="text-neutral-500 text-xs flex gap-2">
                                                    <span>{formatBytes(item.size)}</span>
                                                </p>
                                            )}
                                        </div>
                                    </div>
                                    <button
                                        onClick={(e) => { e.stopPropagation(); item.file && preview(item.file, item.name); }}
                                        className="text-neutral-500 hover:text-white p-2 transition flex-shrink-0 hidden md:block"
                                        title="Preview"
                                    >
                                        <Eye className="w-4 h-4 md:w-5 md:h-5" />
                                    </button>
                                    <button onClick={(e) => {
                                        e.stopPropagation();
                                        if (uploading) {
                                            // Mark as cancelled during upload
                                            setFiles(prev => prev.map(f => 
                                                (f.id === item.id || f.path.startsWith(item.path + '/'))
                                                    ? { ...f, cancelled: true }
                                                    : f
                                            ));
                                            // Abort the upload
                                            const abortCtrl = (window as any).__uploadAbortController;
                                            if (abortCtrl) {
                                                abortCtrl.abort();
                                            }
                                        } else {
                                            setFiles(prev => {
                                                const next = prev.filter(x => x.id !== item.id && !x.path.startsWith(item.path + '/'));
                                                saveUploadState({ files: next, options: optionsRef.current, uploading: false });
                                                return next;
                                            });
                                        }
                                    }} className="text-neutral-500 hover:text-red-400 p-2 transition flex-shrink-0">
                                        {item.cancelled ? <XCircle className="w-4 h-4 md:w-5 md:h-5 text-red-500" /> : <X className="w-4 h-4 md:w-5 md:h-5" />}
                                    </button>
                                </div>
                            )
                        })}
                    </div>

                    {/* PROGRESS BAR */}
                    {uploading && (
                        <div className="px-4 py-3 bg-black border-t border-neutral-800">
                            <div className="flex justify-between text-xs text-neutral-400 mb-1">
                                <span>Uploading...</span>
                                <span>{uploadProgress}%</span>
                            </div>
                            <div className="w-full bg-neutral-800 rounded-full h-2 overflow-hidden">
                                <div className="bg-gradient-to-r from-primary to-primary-300 h-2 rounded-full transition-all duration-300" style={{ width: `${uploadProgress}%` }}></div>
                            </div>
                        </div>
                    )}

                    <div className="p-4 bg-neutral-900/90 border-t border-neutral-800 flex justify-end">
                        <button onClick={() => setShowSettings(true)} disabled={uploading} className="bg-gradient-brand hover:brightness-90 text-white px-8 py-3 rounded-xl font-bold shadow-lg shadow-primary-950/25 transition-all btn-press flex items-center gap-2 text-lg">
                            {uploading ? <Loader2 className="w-5 h-5 animate-spin" /> : <ArrowRight className="w-5 h-5" />}
                            {uploading ? 'In progress...' : 'Share'}
                        </button>
                    </div>
                </div>
            )}

            <AnimatePresence>
                {showSettings && (
                    <ModalPortal>
                        <motion.div
                            key="settings-modal"
                            initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            animate={{ opacity: 1, backdropFilter: "blur(4px)" }}
                            exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            className="fixed inset-0 bg-black/80 z-[9999] flex items-center justify-center p-4"
                            onClick={() => setShowSettings(false)}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.95, opacity: 0 }}
                                className="bg-neutral-900 w-full max-w-2xl rounded-2xl border border-neutral-700 shadow-2xl p-4 md:p-8 space-y-2 md:space-y-2 max-h-[90vh] overflow-y-auto"
                                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                            >
                                <h3 className="heading-section flex gap-2 items-center"><Settings className="text-primary-400" /> Share Settings</h3>

                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div>
                                        <label className="label-form-compact">Name</label>
                                        <input className="input-field" value={options.name} onChange={e => setOpts({ ...options, name: e.target.value })} placeholder="Optional" />
                                    </div>

                                    {/* ID GENERATOR UI */}
                                    <div>
                                        <label className="text-xs font-bold text-neutral-500 uppercase mb-1 flex justify-between">
                                            <span>Unique Link ID</span>
                                            <span className="text-primary-300">{idLength} characters</span>
                                        </label>
                                        <div className="flex gap-2 mb-2">
                                            <input className="input-field font-mono text-center tracking-wider" value={options.customSlug} onChange={e => setOpts({ ...options, customSlug: e.target.value })} />
                                            <button onClick={() => generateId(idLength)} className="bg-neutral-800 hover:bg-neutral-700 p-3 rounded-lg text-white transition" title="Generate new ID">
                                                <Loader2 className="w-5 h-5" />
                                            </button>
                                        </div>
                                        <input
                                            type="range"
                                            min="8"
                                            max="32"
                                            value={idLength}
                                            onChange={(e) => {
                                                const len = parseInt(e.target.value);
                                                setIdLength(len);
                                                generateId(len);
                                            }}
                                            className="w-full accent-primary h-2 bg-neutral-800 rounded-lg appearance-none cursor-pointer"
                                        />
                                    </div>
                                </div>

                                <div><label className="label-form-compact">Message</label><textarea className="input-field" rows={2} value={options.message} onChange={e => setOpts({ ...options, message: e.target.value })} /></div>

                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div><label className="label-form-compact">Password</label><input className="input-field" type="password" placeholder="Optional" value={options.password} onChange={e => setOpts({ ...options, password: e.target.value })} /></div>
                                    <div>
                                        <label className="label-form-compact">Expires after</label>
                                        <div className="flex gap-2">
                                            <input
                                                type="number" min="0"
                                                className="input-field w-20 text-center"
                                                value={options.expirationVal === '' ? '' : options.expirationVal}
                                                onChange={e => {
                                                    const val = e.target.value;
                                                    setOpts({ ...options, expirationVal: val === '' ? '' : parseInt(val) })
                                                }}
                                                onBlur={() => {
                                                    if (options.expirationVal === '') setOpts({ ...options, expirationVal: 0 });
                                                }}
                                            />
                                            <div className="relative flex-1">
                                                <select
                                                    className="input-field appearance-none pr-10"
                                                    value={options.expirationUnit}
                                                    onChange={e => setOpts({ ...options, expirationUnit: e.target.value })}
                                                >
                                                    {UNITS.map(u => (
                                                        <option key={u} value={u}>
                                                            {getUnitLabel(options.expirationVal, u)}
                                                        </option>
                                                    ))}
                                                </select>
                                                <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500 pointer-events-none" />
                                            </div>
                                        </div>
                                        <div className="text-[10px] text-neutral-500 mt-1.5 flex items-center gap-1.5">
                                            <Info className="w-3 h-3" />
                                            {options.expirationVal > 0
                                                ? <span>Expires on: <span className="text-primary-300">{getFutureDate(options.expirationVal, options.expirationUnit, locale)}</span></span>
                                                : <span>Link <span className="text-green-500">always remains valid</span></span>
                                            }
                                        </div>
                                    </div>

                                    <div>
                                        <label className="label-form-compact">Max Downloads (Optional)</label>
                                        <input
                                            type="number"
                                            min="0"
                                            placeholder="Unlimited"
                                            className="input-field"
                                            value={options.maxDownloads || ''}
                                            onChange={e => setOpts({ ...options, maxDownloads: e.target.value ? parseInt(e.target.value) : undefined })}
                                        />
                                        <p className="text-[10px] text-neutral-500 mt-1">Leave empty for unlimited</p>
                                    </div>
                                </div>

                                <div>
                                    <label className="label-form-compact flex items-center gap-2">
                                        Recipients
                                        <Tooltip content="Use commas to separate multiple email addresses.">
                                            <HelpCircle className="w-3.5 h-3.5 text-neutral-500 cursor-help" />
                                        </Tooltip>
                                    </label>
                                    <input className="input-field" placeholder="dan@example.com..." value={options.recipients} onChange={e => setOpts({ ...options, recipients: e.target.value })} list="contacts" />
                                    <datalist id="contacts">{contacts.map(c => <option key={c.id} value={c.email} />)}</datalist>
                                </div>

                                <div className="flex justify-end gap-3 pt-4 border-t border-neutral-800">
                                    <button onClick={() => setShowSettings(false)} className="text-neutral-400 hover:text-white px-4 py-2 transition">Cancel</button>
                                    <button onClick={handleUpload} disabled={uploading} className="bg-gradient-brand hover:brightness-90 px-8 py-3 rounded-lg text-white font-bold transition btn-press shadow-lg shadow-primary-950/25">{uploading ? 'In progress...' : 'Send'}</button>
                                </div>
                            </motion.div>
                        </motion.div>
                    </ModalPortal>
                )}
            </AnimatePresence>
        </div>
    );
};

