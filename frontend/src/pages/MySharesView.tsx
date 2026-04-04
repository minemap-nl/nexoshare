import React, { useState, useEffect, useRef, useCallback } from 'react';
import { AnimatePresence, motion } from 'framer-motion';

import { useParams } from 'react-router-dom';
import {
    Download, Upload, File as FileIcon, Folder as FolderIcon, X, Check, Share2, Settings,
    LogOut, User, Shield,
    Trash2, Send, AlertTriangle, Loader2, Info,
    XCircle, FileQuestion, CloudUpload, Eye,
    Copy, Plus, AlertCircle, ArrowRight, ChevronDown, Edit,
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


export function MySharesView({ active }: { active: boolean }) {
    const [shares, setShares] = useState<any[]>([]);
    const [editing, setEditing] = useState<any>(null);
    const [activeUploadShareId, setActiveUploadShareId] = useState<string | null>(null);
    const [newFiles, setNewFiles] = useState<File[]>([]);
    const [editProgress, setEditProgress] = useState(0);
    const [isSaving, setIsSaving] = useState(false);
    const [resending, setResending] = useState<any>(null);
    const fileInputRef = useRef<HTMLInputElement>(null);
    const { notify, confirm, preview, isConfirming, isPreviewing } = useUI();
    const { config: msCfg } = useAppConfig();

    // Esc keys
    useEscapeKey(() => setEditing(null), !!editing && !isConfirming && !isPreviewing);
    useEscapeKey(() => setResending(null), !!resending && !isConfirming && !isPreviewing);

    const load = useCallback(async () => {
        try {
            const res = await fetch(`${API_URL}/shares`, { credentials: 'include' });
            if (res.ok) {
                const data = await res.json();
                // Voorkom crash: update alleen als het een array is
                if (Array.isArray(data)) {
                    setShares(data);
                } else {
                    setShares([]); // Veilige fallback
                }
            }
        } catch (e) {
            console.error("Error loading shares:", e);
        }
    }, []);

    // Tab blijft gemount maar hidden: ververs lijst telkens als je naar My Shares gaat (nieuwe shares, edits elders).
    useEffect(() => {
        if (!active) return;
        load();
    }, [active, load]);

    useEffect(() => {
        const onSharesChanged = () => { void load(); };
        window.addEventListener(SHARES_LIST_CHANGED_EVENT, onSharesChanged);
        return () => window.removeEventListener(SHARES_LIST_CHANGED_EVENT, onSharesChanged);
    }, [load]);

    useEffect(() => {
        const onActiveUpload = (ev: Event) => {
            const d = (ev as CustomEvent<{ shareId: string | null }>).detail;
            setActiveUploadShareId(d?.shareId ?? null);
        };
        window.addEventListener(ACTIVE_UPLOAD_SHARE_EVENT, onActiveUpload);
        return () => window.removeEventListener(ACTIVE_UPLOAD_SHARE_EVENT, onActiveUpload);
    }, []);

    const deleteShare = async (id: string) => {
        confirm("Are you sure you want to delete this share? This cannot be undone.", async () => {
            await fetch(`${API_URL}/shares/${id}`, { method: 'DELETE', credentials: 'include' });
            setShares(prev => prev.filter(s => s.id !== id));
            notify("Share deleted", "success");
        });
    };

    const deleteFile = async (shareId: string, fileId: string | number) => {
        confirm("Do you want to delete this file?", async () => {
            const res = await fetch(`${API_URL}/shares/${shareId}/files/${fileId}`, { method: 'DELETE', credentials: 'include' });
            const data = await res.json(); // Lees antwoord van server

            if (res.ok) {
                if (data.shareDeleted) {
                    // Als de server zegt dat de share weg is:
                    setEditing(null); // Sluit modal
                    notify("Share deleted because it was empty", "info");
                } else {
                    // Normale afhandeling: update lijst in modal
                    if (editing) {
                        const updatedShare = { ...editing };
                        updatedShare.files = updatedShare.files.filter((f: any) => f.id !== fileId);
                        setEditing(updatedShare);
                    }
                    notify("File deleted", "success");
                }
                load(); // Ververs de hoofdlijst
            } else {
                notify("Error while deleting", "error");
            }
        });
    };

    const deleteFolder = async (shareId: string, path: string) => {
        confirm("Are you sure you want to delete this folder and all its contents?", async () => {
            const res = await fetch(`${API_URL}/shares/${shareId}/folder?path=${encodeURIComponent(path)}`, {
                method: 'DELETE',
                credentials: 'include'
            });
            const data = await res.json();

            if (res.ok) {
                if (data.shareDeleted) {
                    setEditing(null);
                    notify("Share deleted because it was empty", "info");
                } else {
                    if (editing) {
                        // We moeten herladen vanuit de server omdat we niet precies weten welke IDs zijn verwijderd (enkel prefix)
                        // Alternatief kan zijn: filter alle files die starten met 'path/'
                        const updatedShare = { ...editing };
                        updatedShare.files = updatedShare.files.filter((f: any) => !f.original_name.startsWith(path + '/'));
                        setEditing(updatedShare);
                    }
                    notify("Folder deleted", "success");
                }
                load();
            } else {
                notify(data.error || "Error while deleting folder", "error");
            }
        });
    };

    const [stagedFiles, setStagedFiles] = useState<any[]>([]); // { tempId, originalName, size, mimeType }
    const [isStaging, setIsStaging] = useState(false);

    // Als we een edit openen, reset staged
    useEffect(() => {
        if (editing) {
            setStagedFiles([]);
        }
    }, [editing?.id]);

    const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
        if (!e.target.files || e.target.files.length === 0) return;
        setIsStaging(true);
        setEditProgress(0);

        const files = Array.from(e.target.files);
        // We gebruiken de bestaande chunked upload logica, maar naar de 'stage' endpoint

        try {
            const cfg = msCfg;
            const k = 1024;
            const map: any = { 'KB': k, 'MB': k * k };
            const CHUNK_SIZE = ((cfg?.chunkSizeVal as number) || 20) * (map[(cfg?.chunkSizeUnit as string) || 'MB'] || k * k);

            const uploadedFilesMeta = [];
            let totalBytes = files.reduce((acc, f) => acc + f.size, 0);
            let uploadedBytes = 0;

            // Abort controller
            const abortController = new AbortController();
            (window as any).__uploadAbortController = abortController;

            const uploadChunk = async (file: File, fileId: string, chunkIndex: number, totalChunks: number): Promise<boolean> => {
                const start = chunkIndex * CHUNK_SIZE;
                const end = Math.min(start + CHUNK_SIZE, file.size);
                const chunk = file.slice(start, end);
                
                const chunkHash = await computeChunkHash(chunk);
                
                const chunkFd = new FormData();
                chunkFd.append('chunk', chunk);
                chunkFd.append('chunkIndex', chunkIndex.toString());
                chunkFd.append('totalChunks', totalChunks.toString());
                chunkFd.append('fileName', file.name);
                chunkFd.append('fileId', fileId);
                chunkFd.append('chunkHash', chunkHash);

                let attempts = 0;
                const maxAttempts = 10;
                while (attempts < maxAttempts) {
                    try {
                        await axios.post(`${API_URL}/shares/${editing.id}/chunk`, chunkFd, {
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
            
            for (const file of files) {
                const fileId = generateUUID();
                const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

                if (totalChunks > 0) {
                    const ok0 = await uploadChunk(file, fileId, 0, totalChunks);
                    if (!ok0) throw new Error('cancelled');
                    uploadedBytes += Math.min(CHUNK_SIZE, file.size);
                    setEditProgress(Math.min(Math.round((uploadedBytes * 100) / totalBytes), 99));
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
                    setEditProgress(Math.min(Math.round((uploadedBytes * 100) / totalBytes), 99));
                }

                uploadedFilesMeta.push({
                    fileName: file.name,
                    fileId: fileId,
                    size: file.size,
                    mimeType: file.type
                });
            }

            // Call STAGE endpoint
            const res = await axios.post(`${API_URL}/shares/${editing.id}/stage`, {
                files: uploadedFilesMeta
            });

            if (res.data.success) {
                setStagedFiles(prev => [...prev, ...res.data.stagedFiles]);
                notify("Files scanned & ready to save", "success");
            }

        } catch (e: any) {
            console.error(e);
            notify(e.response?.data?.error || e.message || 'Scan failed', "error");
        } finally {
            setIsStaging(false);
            setEditProgress(0);
            if (fileInputRef.current) fileInputRef.current.value = '';
        }
    };

    const saveEdit = async () => {
        setIsSaving(true);
        try {
            const fd = new FormData();
            fd.append('name', editing.name);

            if (editing.removePassword) {
                fd.append('password', '');
                fd.append('remove_password', 'true');
            } else if (editing.password) {
                fd.append('password', editing.password);
            }

            if (editing.newSlug) fd.append('customSlug', editing.newSlug);

            if (editing.newExpirationVal !== undefined && editing.newExpirationVal !== null && !isNaN(editing.newExpirationVal)) {
                fd.append('expirationVal', editing.newExpirationVal.toString());
                fd.append('expirationUnit', editing.newExpirationUnit || 'Days');
            }

            // Add Staged Files
            if (stagedFiles.length > 0) {
                fd.append('staged_files', JSON.stringify(stagedFiles));
            }

            // Update metadata
            const res = await fetch(`${API_URL}/shares/${editing.id}`, {
                method: 'PUT',
                credentials: 'include',
                body: fd
            });

            const json = await res.json();
            if (!res.ok) throw new Error(json.error || 'Metadata update failed');

            setEditing(null);
            setStagedFiles([]);
            load();
            notify("Changes saved", "success");

        } catch (e: any) {
            console.error(e);
            notify(e.message || 'Update failed', "error");
        } finally {
            setIsSaving(false);
        }
    };

    const submitResend = async () => {
        await fetch(`${API_URL}/shares/${resending.id}/resend`, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ recipients: resending.recipients, message: resending.message }) });
        setResending(null);
        notify("Email resent!", "success");
    };

    return (
        <div className="space-y-6 anim-slide">
            <h2 className="heading-section mb-6">My Shares</h2>

            {shares.length === 0 && (
                <div className="bg-neutral-900/50 rounded-2xl border-2 border-dashed border-neutral-800 p-10 flex flex-col items-center justify-center text-neutral-500">
                    <FileQuestion className="w-12 h-12 mb-4 opacity-50" />
                    <p className="text-lg font-medium">You haven't shared any files yet.</p>
                    <p className="text-sm">Upload your first file to get started!</p>
                </div>
            )}

            <div className="grid gap-4">
                {shares.map(s => (
                    <div key={s.id} className="bg-neutral-900 rounded-xl border border-neutral-800 p-4 md:p-6 flex flex-col md:flex-row justify-between items-start gap-4 hover:border-neutral-600 transition duration-300">
                        <div className="flex-1 min-w-0">
                            <h3 className="text-lg font-bold tracking-tight text-white md:text-xl flex items-center gap-2 flex-wrap">{s.name} {s.protected && <LockIcon className="w-4 h-4 text-yellow-500" />}</h3>
                            <div className="text-neutral-400 text-xs md:text-sm mt-1 flex gap-2 md:gap-3 flex-wrap">
                                <span>{s.files?.length || 0} files</span>
                                <span>•</span>
                                <span>{formatBytes(s.total_size)}</span>
                                <span className="hidden sm:inline">•</span>
                                <span>Expires on: {s.expires_at ? new Date(s.expires_at).toLocaleDateString() : 'Never'}</span>
                                <span className="hidden sm:inline">•</span>
                                <span className={`flex items-center gap-1 ${s.max_downloads && s.download_count >= s.max_downloads ? 'text-red-500 font-bold' : ''}`}>
                                    <Download className="w-3 h-3" />
                                    {s.download_count || 0}
                                    {s.max_downloads ? ` / ${s.max_downloads}` : ''}
                                </span>
                            </div>
                            <div className="mt-3"><CopyButton text={s.url} className="text-primary-300 hover:text-primary-200 text-sm bg-primary/10 px-2 py-1 rounded w-fit break-all text-left whitespace-normal" /></div>
                        </div>
                        <div className="flex gap-2 flex-shrink-0 self-start">
                            <button
                                onClick={() => setEditing(s)}
                                className="p-2 hover:bg-neutral-800 rounded text-neutral-400 hover:text-white transition"
                                title="Edit"
                            >
                                <Edit className="w-5 h-5" />
                            </button>
                            <button
                                onClick={() => setResending(s)}
                                className="p-2 hover:bg-neutral-800 rounded text-neutral-400 hover:text-white transition"
                                title="Resend email"
                            >
                                <Mail className="w-5 h-5" />
                            </button>
                            <button
                                onClick={() => deleteShare(s.id)}
                                className="p-2 hover:bg-red-500/10 rounded text-red-500 transition"
                                title="Delete"
                            >
                                <Trash2 className="w-5 h-5" />
                            </button>
                        </div>
                    </div>
                ))}
            </div>

            <AnimatePresence>
                {editing && (
                    <ModalPortal>
                        <motion.div
                            key="edit-modal"
                            initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            animate={{ opacity: 1, backdropFilter: "blur(8px)" }}
                            exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            transition={{ duration: 0.2 }}
                            className="fixed inset-0 bg-black/80 z-[9999] flex items-center justify-center p-4 text-left"
                            onClick={() => !isSaving && setEditing(null)}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0, y: 20 }}
                                animate={{ scale: 1, opacity: 1, y: 0 }}
                                exit={{ scale: 0.95, opacity: 0, y: 20 }}
                                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                                className="bg-neutral-900 w-full max-w-2xl rounded-2xl border border-neutral-700 shadow-2xl p-4 md:p-8 space-y-4 md:space-y-6 max-h-[90vh] overflow-y-auto"
                            >
                                <h3 className="heading-section flex gap-2 items-center"><Edit className="text-primary-400" /> Edit Share</h3>

                                {/* Naam & Link */}
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div><label className="label-form-compact">Name</label><input className="input-field" value={editing.name} onChange={e => setEditing({ ...editing, name: e.target.value })} /></div>
                                    <div>
                                        <label className="label-form-compact">Link / ID</label>
                                        <input
                                            className={`input-field ${editing.id === activeUploadShareId ? '!border-neutral-600 opacity-60 cursor-not-allowed' : ''}`}
                                            defaultValue={editing.id}
                                            disabled={editing.id === activeUploadShareId}
                                            onChange={e => setEditing({ ...editing, newSlug: e.target.value })}
                                        />
                                        {editing.id === activeUploadShareId && (
                                            <p className="text-[11px] text-amber-500/90 mt-1.5">Link cannot be changed while a file upload to this share is still running (from the Upload tab). Other fields can still be edited.</p>
                                        )}
                                    </div>
                                </div>

                                {/* Password & Expiration */}
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div>
                                        <label className="label-form-compact">Password</label>
                                        <div className="relative">
                                            <input
                                                className="input-field pr-10"
                                                type="password"
                                                autoComplete="current-password"
                                                placeholder={editing.protected ? "Password set (type to change)" : "Leave blank for no change"}
                                                onChange={e => setEditing({ ...editing, password: e.target.value, removePassword: false })}
                                            />
                                            {editing.protected && !editing.removePassword && (
                                                <button
                                                    type="button"
                                                    onClick={() => setEditing({ ...editing, protected: false, removePassword: true, password: '' })}
                                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-neutral-400 hover:text-red-500 transition-colors p-1 rounded-md hover:bg-neutral-800"
                                                    title="Delete password"
                                                >
                                                    <X className="w-5 h-5" />
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                    <div>
                                        <label className="label-form-compact">New Expiry Time</label>
                                        <div className="flex gap-2">
                                            <input
                                                type="number" min="0" placeholder="-"
                                                className="input-field w-20 text-center"
                                                value={editing.newExpirationVal ?? ''}
                                                onChange={e => {
                                                    const val = e.target.value;
                                                    setEditing({
                                                        ...editing,
                                                        // Als leeg, maak 0. Anders parseInt.
                                                        newExpirationVal: val === '' ? 0 : parseInt(val),
                                                        newExpirationUnit: editing.newExpirationUnit || 'Days'
                                                    });
                                                }}
                                            />
                                            <div className="relative flex-1">
                                                <select
                                                    className="input-field appearance-none pr-10"
                                                    value={editing.newExpirationUnit || 'Days'}
                                                    onChange={e => setEditing({ ...editing, newExpirationUnit: e.target.value })}
                                                >
                                                    {UNITS.map(u => (
                                                        <option key={u} value={u}>
                                                            {getUnitLabel(editing.newExpirationVal || 1, u)}
                                                        </option>
                                                    ))}
                                                </select>
                                                <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500 pointer-events-none" />
                                            </div>
                                        </div>
                                        {editing.newExpirationVal !== undefined && !isNaN(editing.newExpirationVal) && (
                                            <p className="text-[10px] text-neutral-500 mt-1">
                                                New date: <span className="text-primary-300">{getFutureDate(editing.newExpirationVal, editing.newExpirationUnit || 'Days')}</span>
                                            </p>
                                        )}
                                    </div>
                                </div>

                                {/* Bestanden */}
                                <div>
                                    <label className="label-form-compact">Files</label>

                                    {/* Hierarchical File Tree */}
                                    {(() => {
                                        const dbItems: UploadItem[] = (editing.files || []).map((f: any) => ({
                                            file: null,
                                            path: f.original_name,
                                            name: f.original_name.split('/').pop() || f.original_name,
                                            id: f.id,
                                            isDirectory: false,
                                            size: f.size
                                        }));
                                        const stagedItems: UploadItem[] = stagedFiles.map(f => ({
                                            file: null, // It's on server now
                                            path: f.originalName,
                                            name: f.originalName,
                                            id: f.tempId, // Use tempId for identification
                                            isDirectory: false,
                                            size: f.size,
                                            isStaged: true // Vlaggetje om te weten dat hij staged is
                                        }));

                                        // Sort and synthesize tree
                                        const combined = sortFiles(synthesizeDirectoryItems([...dbItems, ...stagedItems]));

                                        return (
                                            <div className="bg-neutral-800/50 rounded-lg border border-neutral-700 overflow-hidden max-h-[300px] overflow-y-auto" style={{ "--indent-step": "24px" } as React.CSSProperties}>
                                                <style>{`@media (max-width: 768px) { [style*="--indent-step"] { --indent-step: 12px !important; } }`}</style>
                                                {combined.length === 0 ? (
                                                    <p className="text-center text-neutral-500 py-8">No files in this share.</p>
                                                ) : (
                                                    combined.map((item: any) => {
                                                        const segments = item.path.split('/');
                                                        const depth = Math.max(0, segments.length - 1);

                                                        return (
                                                            <div key={item.id} className={`flex justify-between items-center px-3 py-2 border-b border-neutral-700 last:border-0 hover:bg-neutral-700/50 transition gap-2 ${item.isDirectory ? 'bg-neutral-700/30' : ''}`}>
                                                                <div
                                                                    className="flex items-center gap-2 md:gap-4 overflow-hidden flex-1 cursor-pointer"
                                                                    style={{ paddingLeft: `calc(${depth} * var(--indent-step, 12px))` }}
                                                                    onClick={() => {
                                                                        if (item.isDirectory) return;
                                                                        if (item.isStaged) {
                                                                            preview(`${API_URL}/shares/preview-stage/${item.id}`, item.name);
                                                                        } else {
                                                                            preview(`${API_URL}/shares/${editing.id}/files/${item.id}`, item.name);
                                                                        }
                                                                    }}
                                                                >
                                                                    <div className="bg-black p-2 rounded-lg text-primary-300 font-bold text-xs uppercase text-center shrink-0 flex items-center justify-center min-w-[2.5rem]">
                                                                        {item.isDirectory ? <FolderIcon className="w-4 h-4" /> : item.name.split('.').pop()}
                                                                        {depth > 0 && <div className="absolute -left-3 top-1/2 -translate-y-1/2 w-2 h-[1px] bg-neutral-600"></div>}
                                                                    </div>
                                                                    <div className="min-w-0">
                                                                        <p className={`font-medium truncate ${item.isDirectory ? 'text-primary-200' : 'text-neutral-200'}`}>
                                                                            {item.name} {item.isStaged && <span className="text-[10px] bg-green-900/50 text-green-400 px-1.5 py-0.5 rounded ml-2 border border-green-800">New</span>}
                                                                        </p>
                                                                        {!item.isDirectory && <p className="text-xs text-neutral-500">{formatBytes(item.size)}</p>}
                                                                    </div>
                                                                </div>

                                                                <div className="flex items-center gap-1">
                                                                    {!(item.isStaged && item.isDirectory) && (
                                                                        <button
                                                                            onClick={(e) => {
                                                                                e.stopPropagation();
                                                                                if (item.isDirectory) {
                                                                                    deleteFolder(editing.id, item.path);
                                                                                } else if (item.isStaged) {
                                                                                    setStagedFiles(prev => prev.filter(p => p.tempId !== item.id));
                                                                                } else {
                                                                                    deleteFile(editing.id, item.id);
                                                                                }
                                                                            }}
                                                                            className="p-2 text-neutral-500 hover:text-red-400 hover:bg-red-500/10 rounded transition"
                                                                        >
                                                                            <X className="w-4 h-4" />
                                                                        </button>
                                                                    )}
                                                                </div>
                                                            </div>
                                                        );
                                                    })
                                                )}
                                            </div>
                                        );
                                    })()}

                                    {isStaging && (
                                        <div className="mt-2">
                                            <div className="flex justify-between text-xs text-neutral-400 mb-1">
                                                <span>Scanning & Staging files...</span>
                                                <span>{editProgress}%</span>
                                            </div>
                                            <div className="w-full bg-neutral-800 rounded-full h-1.5">
                                                <div className="bg-green-500 h-1.5 rounded-full transition-all duration-300" style={{ width: `${editProgress}%` }}></div>
                                            </div>
                                        </div>
                                    )}

                                    <div className="mt-4 flex gap-2">
                                        <button onClick={() => fileInputRef.current?.click()} className="bg-neutral-800 hover:bg-neutral-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition border border-neutral-700 flex items-center gap-2">
                                            <Plus className="w-4 h-4" /> Add Files
                                        </button>

                                        <input
                                            ref={fileInputRef}
                                            type="file"
                                            multiple
                                            className="hidden"
                                            onChange={handleFileSelect}
                                        />
                                    </div>
                                </div>

                                {/* Progress Bar (Alleen zichtbaar tijdens Save) */}
                                {isSaving && (
                                    <div className="mt-4">
                                        <div className="flex justify-between text-xs text-neutral-400 mb-1">
                                            <span>{newFiles.length > 0 ? 'Uploading files...' : 'Save...'}</span>
                                            <span>{editProgress}%</span>
                                        </div>
                                        <div className="w-full bg-neutral-800 rounded-full h-2 overflow-hidden">
                                            <div
                                                className="bg-gradient-to-r from-primary to-primary-300 h-2 rounded-full transition-all duration-300"
                                                style={{ width: `${newFiles.length > 0 ? editProgress : 100}%` }}
                                            ></div>
                                        </div>
                                    </div>
                                )}

                                {/* Actieknoppen */}
                                <div className="flex justify-end gap-3 pt-4 border-t border-neutral-700 mt-4">
                                    <button onClick={() => { setEditing(null); setNewFiles([]) }} disabled={isSaving} className="text-neutral-400 hover:text-white px-4 py-2 transition">Cancel</button>
                                    <button onClick={saveEdit} disabled={isSaving} className="bg-gradient-brand hover:brightness-90 px-6 py-2 rounded-lg text-white font-bold transition btn-press flex items-center gap-2">
                                        {isSaving && <Loader2 className="w-4 h-4 animate-spin" />}
                                        Save
                                    </button>
                                </div>

                            </motion.div>
                        </motion.div>
                    </ModalPortal>
                )}
            </AnimatePresence>

            <AnimatePresence>
                {resending && (
                    <ModalPortal>
                        <motion.div
                            key="resend-modal"
                            initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            animate={{ opacity: 1, backdropFilter: "blur(4px)" }}
                            exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            className="fixed inset-0 bg-black/80 z-[9999] flex items-center justify-center p-4"
                            onClick={() => setResending(null)}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.95, opacity: 0 }}
                                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                                className="bg-neutral-900 w-full max-w-lg rounded-2xl border border-neutral-700 p-4 md:p-8 shadow-2xl"
                            >
                                <h3 className="heading-panel mb-6 flex gap-2 items-center"><Mail className="text-primary-400" /> Resend mail</h3>
                                <div className="space-y-4">
                                    <div><label className="label-form-compact">Recipients</label><input className="input-field" value={resending.recipients || ''} onChange={e => setResending({ ...resending, recipients: e.target.value })} /></div>
                                    <div><label className="label-form-compact">Message</label><textarea className="input-field" rows={4} value={resending.message || ''} onChange={e => setResending({ ...resending, message: e.target.value })} /></div>
                                </div>
                                <div className="flex justify-end gap-3 mt-6 border-t border-neutral-700 pt-4">
                                    <button onClick={() => setResending(null)} className="text-neutral-400 hover:text-white px-4 py-2 transition">Cancel</button>
                                    <button onClick={submitResend} className="bg-gradient-brand hover:brightness-90 px-6 py-2 rounded-lg text-white font-bold transition btn-press flex items-center gap-2"><Send className="w-4 h-4" /> Send</button>
                                </div>
                            </motion.div>
                        </motion.div>
                    </ModalPortal>
                )}
            </AnimatePresence>
        </div>
    );
};

