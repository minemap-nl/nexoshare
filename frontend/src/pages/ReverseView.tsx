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


export function ReverseView({ active }: { active: boolean }) {
    const [shares, setShares] = useState<any[]>([]);
    const [createMode, setCreateMode] = useState(false);
    const [viewFiles, setViewFiles] = useState<any>(null);
    const [uploadedFiles, setUploadedFiles] = useState<any[]>([]);
    // Update state met expirationVal en expirationUnit (Default: 1 Week)
    const [newShare, setNewShare] = useState({
        name: '',
        maxSizeVal: 1, // Standaard 1
        maxSizeUnit: 'GB', // Standaard GB
        expirationVal: 1,
        expirationUnit: 'Weeks',
        password: '',
        notify: true,
        sendEmailTo: '',
        thankYouMessage: '',
        customSlug: ''
    });
    const [idLength, setIdLength] = useState(12);
    const [copiedId, setCopiedId] = useState<string | null>(null);
    const { notify, confirm, preview, isConfirming, isPreviewing } = useUI();
    const { config: revCfg } = useAppConfig();

    // Esc keys
    useEscapeKey(() => setCreateMode(false), createMode && !isConfirming && !isPreviewing);
    useEscapeKey(() => setViewFiles(null), !!viewFiles && !isConfirming && !isPreviewing);

    useEffect(() => {
        const cfg = revCfg;
        if (!cfg || typeof cfg !== 'object' || Object.keys(cfg).length === 0) return;
        if (cfg.shareIdLength) {
            const sl = parseInt(String(cfg.shareIdLength), 10);
            if (!Number.isNaN(sl)) {
                setIdLength(sl);
                generateId(sl);
                return;
            }
        }
        generateId(12);
    }, [revCfg]);

    const loadReverse = useCallback(async () => {
        try {
            const res = await fetch(`${API_URL}/reverse`, { credentials: 'include' });
            if (res.ok) {
                const data = await res.json();
                if (Array.isArray(data)) setShares(data);
            }
        } catch (e) { console.error(e); }
    }, []);

    useEffect(() => {
        if (!active) return;
        loadReverse();
    }, [active, loadReverse]);

    const generateId = async (len: number) => {
        try {
            const res = await fetch(`${API_URL}/utils/generate-id?length=${len}`, { credentials: 'include' });
            const data = await res.json();
            if (data.id) setNewShare(prev => ({ ...prev, customSlug: data.id }));
        } catch (e) { console.error(e); }
    };

    const create = async () => {
        // Bereken bytes op basis van gekozen unit
        const multiplier = newShare.maxSizeUnit === 'GB' ? 1024 * 1024 * 1024 : 1024 * 1024;
        const sizeInBytes = (newShare.maxSizeVal || 0) * multiplier;

        const res = await fetch(`${API_URL}/reverse`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ...newShare,
                maxSize: sizeInBytes // Verstuur als bytes
            })
        });

        if (res.ok) {
            setCreateMode(false);
            // Reset formulier
            setNewShare({
                name: '', maxSizeVal: 1, maxSizeUnit: 'GB', expirationVal: 1,
                expirationUnit: 'Weeks', password: '', notify: true,
                sendEmailTo: '', thankYouMessage: '', customSlug: ''
            });
            loadReverse();
            notify("Reverse share created", "success");
        } else {
            const data = await res.json();
            notify(data.error || "Creation failed", "error");
        }
    };
    const deleteReverse = async (id: string) => { confirm("Delete?", async () => { await fetch(`${API_URL}/reverse/${id}`, { method: 'DELETE', credentials: 'include' }); loadReverse(); notify("Deleted", "success"); }); };
    const openFiles = async (id: string) => {
        const res = await fetch(`${API_URL}/reverse/${id}/files`, { credentials: 'include' });
        const json = await res.json();
        setUploadedFiles(json);


        // We reuse the viewFiles state logic, but we might need a separate state for the tree items if 'viewFiles' is just the ID string.
        // The original code used 'viewFiles' as the ID string. We'll stick to that and calculate the tree on render or use a useEffect/memo if needed.
        // For simplicity/perf, let's add a local var or state. Since this is inside MySharesView functional component, we can add a state for it at the top level or reuse 'uploadedFiles' if we typed it loosely. 
        // Better: let's add a state 'viewFilesTree' at the top level of MySharesView.
        setViewFiles(id);
    };

    const handleCopy = (id: string, url: string) => {
        navigator.clipboard.writeText(url);
        setCopiedId(id);
        setTimeout(() => setCopiedId(null), 2000);
    };

    if (viewFiles) {
        // Compute tree on the fly (or memoize if slow)
        const mapped: UploadItem[] = (uploadedFiles || []).map((f: any) => ({
            file: null,
            path: f.original_name,
            name: f.original_name.split('/').pop() || f.original_name,
            id: f.id,
            isDirectory: false,
            size: f.size
        }));
        const treeItems = sortFiles(synthesizeDirectoryItems(mapped));

        return (
            <div className="bg-neutral-900 rounded-xl border border-neutral-800 p-6 anim-scale">
                <div className="flex justify-between items-center mb-6"><h3 className="heading-panel flex gap-2"><Download className="text-primary-400" /> Received Files</h3><button onClick={() => setViewFiles(null)} className="text-neutral-400 hover:text-white transition">Back</button></div>
                {uploadedFiles.length === 0 ? <p className="text-neutral-500">Nothing uploaded yet.</p> : (
                    <div className="max-h-[500px] overflow-y-auto bg-black/30 rounded-lg border border-neutral-800" style={{ "--indent-step": "24px" } as React.CSSProperties}>
                        <style>{`@media (max-width: 768px) { [style*="--indent-step"] { --indent-step: 12px !important; } }`}</style>
                        {treeItems.map(item => {
                            const segments = item.path.split('/');
                            const depth = Math.max(0, segments.length - 1);

                            return (
                                <div key={item.id} className={`flex justify-between items-center px-3 py-2 last:border-0 hover:bg-neutral-800/50 transition gap-2 ${item.isDirectory ? 'bg-neutral-800/30' : ''}`}>
                                    <div className="flex items-center gap-2 md:gap-4 overflow-hidden flex-1 min-w-0" style={{ paddingLeft: `calc(${depth} * var(--indent-step, 12px))` }}>
                                        <div className="bg-black p-2 rounded-lg flex-shrink-0 relative">
                                            {item.isDirectory ? <FolderIcon className="w-4 h-4 text-primary-300" /> : <div className="uppercase text-xs font-bold text-primary-300 min-w-[2.5rem] w-auto text-center">{item.name.split('.').pop()}</div>}
                                            {depth > 0 && <div className="absolute -left-3 top-1/2 -translate-y-1/2 w-2 h-[1px] bg-neutral-600"></div>}
                                        </div>
                                        <div className="min-w-0 flex-1">
                                            <p className={`text-neutral-200 font-medium truncate text-sm md:text-base ${item.isDirectory ? 'text-primary-200' : ''}`}>{item.name}</p>
                                            {!item.isDirectory && <p className="text-neutral-500 text-xs">{formatBytes(item.size)}</p>}
                                        </div>
                                    </div>
                                    {!item.isDirectory && (
                                        <>
                                            <button onClick={() => preview(`${API_URL}/reverse/files/${item.id}/download`, item.name)} className="text-neutral-500 hover:text-white transition p-2 rounded hover:bg-neutral-800 flex-shrink-0" title="Preview"><Eye className="w-4 h-4" /></button>
                                            <a href={`${API_URL}/reverse/files/${encodeURIComponent(item.id)}/download`} className="text-primary-300 hover:text-white transition p-2 rounded hover:bg-neutral-800 flex-shrink-0"><Download className="w-4 h-4" /></a>
                                        </>
                                    )}
                                </div>
                            );
                        })}
                        <div className="p-4 border-t border-neutral-800 sticky bottom-0 bg-neutral-900/95 backdrop-blur">
                            <a href={`${API_URL}/reverse/${viewFiles}/download`} className="block w-full text-center bg-green-600 hover:bg-green-700 text-white px-4 py-3 rounded-lg font-bold transition btn-press shadow-lg shadow-green-900/20">Download everything (.zip)</a>
                        </div>
                    </div>
                )}
            </div>
        );
    }

    return (
        <div className="space-y-6 anim-slide">
            <div className="flex justify-between items-center"><h2 className="heading-section">Reverse Shares</h2><button onClick={() => setCreateMode(true)} className="bg-gradient-brand hover:brightness-90 text-white px-4 py-2 rounded-lg font-bold flex items-center gap-2 transition btn-press"><Plus className="w-4 h-4" /> New link</button></div>
            <AnimatePresence>
                {createMode && (
                    <motion.div
                        key="create-panel"
                        initial={{ opacity: 0, height: 0, marginBottom: 0 }}
                        animate={{ opacity: 1, height: 'auto', marginBottom: 24 }}
                        exit={{ opacity: 0, height: 0, marginBottom: 0 }}
                        className="overflow-hidden"
                    >
                        <div className="bg-neutral-900 p-4 md:p-6 rounded-xl border border-neutral-800 space-y-4">
                            <h3 className="font-bold text-white">Create new link</h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

                                {/* Naam Veld */}
                                <div className="relative group">
                                    <Type className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-neutral-500 group-focus-within:text-primary-300 transition" />
                                    <input
                                        className="input-field input-field--icon"
                                        placeholder="Name of the share (e.g. Project X)"
                                        value={newShare.name}
                                        onChange={e => setNewShare({ ...newShare, name: e.target.value })}
                                    />
                                </div>

                                {/* Password Veld */}
                                <div className="relative group">
                                    <LockIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-neutral-500 group-focus-within:text-primary-300 transition" />
                                    <input
                                        type="password"
                                        className="input-field input-field--icon"
                                        placeholder="Password (Optional)"
                                        value={newShare.password}
                                        onChange={e => setNewShare({ ...newShare, password: e.target.value })}
                                    />
                                </div>

                                {/* Max Grootte met Eenheid Selectie */}
                                <div>
                                    <div className="flex gap-2 relative group">
                                        <div className="relative flex-1">
                                            <HardDrive className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-neutral-500 group-focus-within:text-primary-300 transition" />
                                            <input
                                                type="number"
                                                min="1"
                                                className="input-field input-field--icon"
                                                placeholder="Max Upload"
                                                value={newShare.maxSizeVal}
                                                onChange={e => {
                                                    const val = e.target.value;
                                                    setNewShare({ ...newShare, maxSizeVal: val === '' ? 0 : parseInt(val) })
                                                }}
                                            />
                                        </div>
                                        {/* Aangepaste breedte: w-20 ipv w-28 */}
                                        <div className="relative w-20">
                                            <select
                                                className="select-field px-2 pl-3 font-medium"
                                                value={newShare.maxSizeUnit}
                                                onChange={e => setNewShare({ ...newShare, maxSizeUnit: e.target.value })}
                                            >
                                                <option value="MB">MB</option>
                                                <option value="GB">GB</option>
                                            </select>
                                            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-neutral-500 pointer-events-none" />
                                        </div>
                                    </div>
                                </div>

                                {/* Expiratie Controls met Datum Preview */}
                                <div>
                                    <div className="flex gap-2 relative group">
                                        <div className="relative flex-1">
                                            <Calendar className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-neutral-500 group-focus-within:text-primary-300 transition" />
                                            <input
                                                type="number"
                                                min="0"
                                                className="input-field input-field--icon"
                                                placeholder="0 = Never"
                                                value={newShare.expirationVal}
                                                onChange={e => {
                                                    const val = e.target.value;
                                                    setNewShare({ ...newShare, expirationVal: val === '' ? 0 : parseInt(val) })
                                                }}
                                            />
                                        </div>
                                        <div className="relative w-32">
                                            <select
                                                className="select-field"
                                                value={newShare.expirationUnit}
                                                onChange={e => setNewShare({ ...newShare, expirationUnit: e.target.value })}
                                            >
                                                {UNITS.map(u => (
                                                    <option key={u} value={u}>{getUnitLabel(newShare.expirationVal || 0, u)}</option>
                                                ))}
                                            </select>
                                            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500 pointer-events-none" />
                                        </div>
                                    </div>
                                    {/* Datum Preview Tekst */}
                                    <p className="text-xs text-neutral-500 mt-1.5 ml-1 flex items-center gap-1.5">
                                        <Info className="w-3 h-3" />
                                        {!newShare.expirationVal || newShare.expirationVal === 0
                                            ? "Never expires (Optional)"
                                            : <span>Expires on: <span className="text-primary-300">{getFutureDate(newShare.expirationVal, newShare.expirationUnit)}</span></span>
                                        }
                                    </p>
                                </div>

                                {/* Email Veld & ID Generator Split */}
                                <div className="md:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-4">
                                    {/* Linkerkant: Email */}
                                    <div className="relative group">
                                        <label className="label-form-compact ml-1">Recipient (Email)</label>
                                        <div className="relative">
                                            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-neutral-500 group-focus-within:text-primary-300 transition" />
                                            <input
                                                className="input-field input-field--icon"
                                                placeholder="dan@example.com (Optional)"
                                                value={newShare.sendEmailTo}
                                                onChange={e => setNewShare({ ...newShare, sendEmailTo: e.target.value })}
                                            />
                                        </div>
                                    </div>

                                    {/* Rechterkant: Custom ID */}
                                    <div>
                                        <label className="text-xs font-bold text-neutral-500 uppercase mb-1 flex justify-between ml-1">
                                            <span>Link ID</span>
                                            <span className="text-primary-300">{idLength} characters</span>
                                        </label>
                                        <div className="flex gap-2 mb-2">
                                            <input
                                                className="input-field py-2 font-mono text-center tracking-wider"
                                                value={newShare.customSlug}
                                                onChange={e => setNewShare({ ...newShare, customSlug: e.target.value })}
                                            />
                                            <button onClick={() => generateId(idLength)} className="bg-neutral-800 hover:bg-neutral-700 p-2 rounded-lg text-white transition flex-shrink-0" title="Generate new ID">
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

                                {/* Bedankt Bericht */}
                                <div className="md:col-span-2 relative group">
                                    <MessageSquare className="absolute left-3 top-3 w-5 h-5 text-neutral-500 group-focus-within:text-primary-300 transition" />
                                    <input
                                        className="input-field input-field--icon"
                                        placeholder="Custom Thank You Message (e.g. Thanks for the files!)"
                                        value={newShare.thankYouMessage}
                                        onChange={e => setNewShare({ ...newShare, thankYouMessage: e.target.value })}
                                    />
                                    <p className="text-xs text-neutral-500 mt-1.5 ml-1">This message is what the uploader sees after successful submission.</p>
                                </div>

                                <div className="md:col-span-2 mt-2">
                                    <Checkbox
                                        checked={newShare.notify}
                                        onChange={(e) => setNewShare({ ...newShare, notify: e.target.checked })}
                                        label="Send me an email notification for every upload"
                                    />
                                </div>
                            </div>
                            <div className="flex justify-end gap-2"><button onClick={() => setCreateMode(false)} className="text-neutral-400 px-4 hover:text-white transition">Cancel</button><button onClick={create} className="bg-green-600 hover:bg-green-700 text-white px-6 py-2 rounded font-bold transition btn-press shadow-lg shadow-green-900/20">Create</button></div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            {shares.length === 0 && !createMode && (
                <div className="bg-neutral-900/50 rounded-2xl border-2 border-dashed border-neutral-800 p-10 flex flex-col items-center justify-center text-neutral-500">
                    <FileQuestion className="w-12 h-12 mb-4 opacity-50" /><p className="text-lg font-medium">You don't have any reverse shares yet.</p><p className="text-sm">Create a link to receive files.</p>
                </div>
            )}

            <div className="grid gap-4">
                {shares.map(s => (
                    <div key={s.id} className="bg-neutral-900 p-4 md:p-6 rounded-xl border border-neutral-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 hover:border-neutral-600 transition duration-300">
                        <div>
                            <h4 className="font-bold text-white flex items-center gap-2">{s.name} {s.protected && <LockIcon className="w-3 h-3 text-yellow-500" />}</h4>
                            <div className="flex gap-4 text-sm text-neutral-400 mt-1 flex-wrap">
                                <CopyButton text={s.url} className="bg-primary/10 text-primary-300 px-2 rounded font-mono break-all text-left whitespace-normal" />
                                <span>{s.file_count || 0} receive files</span>

                                {/* Datum weergave */}
                                <span className="hidden sm:inline">•</span>
                                <span>Expires on: {s.expires_at ? new Date(s.expires_at).toLocaleDateString() : 'Never'}</span>
                            </div>
                        </div>
                        <div className="flex gap-2">
                            <button
                                onClick={() => handleCopy(s.id, s.url)}
                                className={`p-2 rounded transition-all duration-300 ${copiedId === s.id
                                    ? 'bg-green-600 text-white scale-110'
                                    : 'bg-neutral-700 hover:bg-neutral-600 text-white'
                                    }`}
                                title="Copy link"
                            >
                                {copiedId === s.id ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                            </button>
                            <button onClick={() => openFiles(s.id)} className="p-2 bg-primary hover:bg-primary-700 rounded text-white transition" title="View files"><Eye className="w-4 h-4" /></button>
                            <button onClick={() => deleteReverse(s.id)} className="p-2 bg-red-500/10 text-red-500 hover:bg-red-500/20 rounded transition"><Trash2 className="w-4 h-4" /></button>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

