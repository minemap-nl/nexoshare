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

/** Demo: informative banner + frozen, greyed panel (no focus, edit, or text selection). */
function DemoServerLockedChrome({
    show,
    children,
    unlockTop,
}: {
    show: boolean;
    children: React.ReactNode;
    /** Shown between banner and frozen panel (e.g. copyable SSO callback). */
    unlockTop?: React.ReactNode;
}) {
    if (!show) return <>{children}</>;
    return (
        <div>
            <div className="mb-4 flex items-center gap-2 rounded-md border border-cyan-900/45 bg-slate-900/85 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-neutral-400">
                <LockIcon className="h-3.5 w-3.5 shrink-0 text-cyan-500/90" aria-hidden />
                Locked by the server — these values are enforced remotely; you cannot change or select them here.
            </div>
            {unlockTop}
            <div
                className="demo-server-locked rounded-xl border border-neutral-600/50 bg-neutral-950/50 p-3 opacity-[0.58] shadow-inner ring-1 ring-black/40 saturate-75 md:p-5 [&_button]:pointer-events-none [&_input]:cursor-not-allowed [&_label]:cursor-default [&_select]:cursor-not-allowed"
                {...({ inert: true } as React.HTMLAttributes<HTMLDivElement>)}
            >
                {children}
            </div>
        </div>
    );
}

export function ConfigTabs({ user, onRestartSetup }: { user: any, onRestartSetup: () => void }) {
    const [config, setConfig] = useState<any>({});
    const [activeTab, setActiveTab] = useState('general');
    const [users, setUsers] = useState<any[]>([]);
    const [contacts, setContacts] = useState<any[]>([]);
    const [newUser, setNewUser] = useState({ email: '', name: '', password: '', is_admin: false });
    const [editUser, setEditUser] = useState<any>(null);
    const { notify, confirm, isConfirming, isPreviewing } = useUI();

    useEscapeKey(() => setEditUser(null), !!editUser && !isConfirming && !isPreviewing);

    // Validatie State voor Users Tab
    const [pwdValid, setPwdValid] = useState({ length: false, upper: false, lower: false, number: false });
    const [isPwdFocused, setIsPwdFocused] = useState(false);

    // We checken zowel newUser (aanmaken) als editUser (bewerken)
    useEffect(() => {
        // Welk Password zijn we aan het typen?
        const p = editUser ? (editUser.password || '') : newUser.password;

        setPwdValid({
            length: p.length >= 8,
            upper: /[A-Z]/.test(p),
            lower: /[a-z]/.test(p),
            number: /[0-9]/.test(p)
        });
    }, [newUser.password, editUser]);

    useEffect(() => {
        fetch(`${API_URL}/config`, { credentials: 'include' })
            .then(r => r.json())
            .then(data => {
                data.smtpPass = '';
                data.oidcSecret = '';

                setConfig(data);
            });
        fetchUsers();
        fetchContacts();
    }, []);

    const fetchUsers = async () => {
        try {
            const res = await fetch(`${API_URL}/users`, { credentials: 'include' });
            if (res.ok) {
                const data = await res.json();
                if (Array.isArray(data)) setUsers(data);
            }
        } catch (e) { console.error(e); }
    };

    const fetchContacts = async () => {
        try {
            const res = await fetch(`${API_URL}/contacts`, { credentials: 'include' });
            if (res.ok) {
                const data = await res.json();
                if (Array.isArray(data)) setContacts(data);
            }
        } catch (e) { console.error(e); }
    };
    const save = async () => {
        const res = await fetch(`${API_URL}/config`, { method: 'PUT', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(config) });
        if (res.ok) {
            notify('Settings saved', 'success');
            dispatchConfigChanged();
        } else {
            notify('Saving failed', 'error');
        }
    };
    const testEmail = async () => {
        const targetEmail = user.email;
        if (!targetEmail) return;

        notify(`Test connection to ${targetEmail}...`, 'info'); // Feedback dat hij bezig is

        try {
            const res = await fetch(`${API_URL}/config/test-email`, {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ...config,
                    testEmail: targetEmail
                })
            });

            if (res.ok) {
                // HIER IS DE AANPASSING:
                notify(`Test email successfully sent to ${targetEmail}`, 'success');
            } else {
                const data = await res.json();
                notify(`Error sending to ${targetEmail}: ${data.error || 'Unknown error'}`, 'error');
            }
        } catch (e: any) {
            notify(`Network error while testing to ${targetEmail}`, 'error');
        }
    };
    const createUser = async () => { const res = await fetch(`${API_URL}/users`, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newUser) }); if (res.ok) { setNewUser({ email: '', name: '', password: '', is_admin: false }); fetchUsers(); notify('User added', 'success'); } };
    const deleteUser = async (id: number) => { confirm('Delete user?', async () => { await fetch(`${API_URL}/users/${id}`, { method: 'DELETE', credentials: 'include' }); fetchUsers(); notify('Deleted', 'success'); }); };
    const deleteContact = async (id: number) => { confirm('Delete contact?', async () => { await fetch(`${API_URL}/contacts/${id}`, { method: 'DELETE', credentials: 'include' }); fetchContacts(); notify('Deleted', 'success'); }); };
    const reset2FA = async (id: number) => {
        confirm('Reset 2FA for this user?', async () => {
            const res = await fetch(`${API_URL}/users/${id}/2fa/reset`, {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' }
            });
            if (res.ok) {
                notify('2FA reset', 'success');
            } else {
                notify('2FA reset failed', 'error');
            }
        });
    };

    const updateUser = async () => {
        const res = await fetch(`${API_URL}/users/${editUser.id}`, { method: 'PUT', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(editUser) });
        if (res.ok) { setEditUser(null); fetchUsers(); notify('User updated', 'success'); }
        else notify('Update failed', 'error');
    };

    // Gebruikt nu de juiste URL en veldnamen voor de backend
    const handleBrandingUpload = async (file: File, field: 'logoUrl' | 'faviconUrl') => {
        // Client-side validatie (dubbele check)
        if (file.size > 5 * 1024 * 1024) {
            notify('File is too large (max 5MB)', 'error');
            return;
        }

        const fd = new FormData();
        // De backend verwacht de key 'logo' of 'favicon', niet 'file'
        const backendField = field === 'logoUrl' ? 'logo' : 'favicon';
        fd.append(backendField, file);

        try {
            notify('Uploading...', 'info');
            // Juiste API route gebruiken (/config/branding i.p.v. /config/upload-branding)
            const res = await fetch(`${API_URL}/config/branding`, {
                method: 'POST',
                credentials: 'include',
                body: fd
            });

            if (res.ok) {
                const data = await res.json();

                // Update de config direct met de nieuwe URL
                setConfig((prev: any) => ({
                    ...prev,
                    [field]: field === 'logoUrl' ? data.logoUrl : data.faviconUrl
                }));

                dispatchConfigChanged();
                notify('Image uploaded! Click "Save" to confirm.', 'success');
            } else {
                const err = await res.json();
                notify(err.error || 'Upload failed', 'error');
            }
        } catch (error) {
            console.error(error);
            notify('Upload error', 'error');
        }
    };

    const tabClass = (id: string) => `flex-1 text-center px-4 md:px-6 py-4 font-bold border-b-2 transition duration-300 whitespace-nowrap text-sm md:text-base ${activeTab === id ? 'border-primary-400 text-white bg-neutral-900' : 'border-transparent text-neutral-400 hover:text-white hover:bg-neutral-900'}`;

    const isDemo = !!config.demoMode;

    return (
        <div className="bg-neutral-900 rounded-xl border border-neutral-800 overflow-hidden max-w-4xl mx-auto shadow-xl anim-slide">
            <div className="flex border-b border-neutral-800 bg-black/50 overflow-x-auto scrollbar-hide">
                <button onClick={() => setActiveTab('general')} className={tabClass('general')}>General</button>
                <button onClick={() => setActiveTab('system')} className={tabClass('system')}>System</button>
                <button onClick={() => setActiveTab('security')} className={tabClass('security')}>Security</button>
                <button onClick={() => setActiveTab('smtp')} className={tabClass('smtp')}>SMTP</button>
                <button onClick={() => setActiveTab('sso')} className={tabClass('sso')}>SSO</button>
                <button onClick={() => setActiveTab('users')} className={tabClass('users')}>Users</button>
            </div>
            <div className="p-4 md:p-8">
                {isDemo && (
                    <div className="mb-6 rounded-lg border border-cyan-800/40 bg-slate-900/80 px-4 py-3 text-sm text-neutral-300">
                        Demo mode: branding uploads, new users, user edits, test email, and some security toggles are disabled on the server. Values shown may differ from what is stored.
                    </div>
                )}
                {activeTab === 'general' && (
                    <DemoServerLockedChrome show={isDemo}>
                    <div className="space-y-6 anim-fade">
                        <div className="flex justify-between items-center mb-6">
                            <h3 className="heading-panel flex gap-2"><Globe className="w-6 h-6 text-neutral-400" /> Branding & Domain</h3>
                            {!isDemo && (
                                <button onClick={onRestartSetup} className="text-neutral-400 hover:text-white text-xs md:text-sm flex items-center gap-2 border border-neutral-700 px-3 py-1.5 rounded-lg hover:bg-neutral-800 transition">
                                    <Sparkles className="w-4 h-4 text-primary-300" /> Restart setup
                                </button>
                            )}
                        </div>
                        <div><label className="label-form">Application Name</label><input className="input-field" value={config.appName || ''} onChange={e => setConfig({ ...config, appName: e.target.value })} /></div>
                        <div>
                            <label className="label-form">Logo</label>
                            <div className="flex gap-2">
                                <input className="input-field" placeholder="https://..." value={config.logoUrl || ''} onChange={e => setConfig({ ...config, logoUrl: e.target.value })} />
                                <label className={`bg-neutral-800 border border-neutral-700 text-white p-3 rounded-lg flex items-center justify-center min-w-[3rem] ${isDemo ? 'opacity-40 cursor-not-allowed pointer-events-none' : 'hover:bg-neutral-700 cursor-pointer transition'}`} title={isDemo ? 'Disabled in demo' : 'Upload Logo'}>
                                    <Upload className="w-5 h-5" />
                                    <input type="file" accept="image/*" className="hidden" disabled={isDemo} onChange={(e) => {
                                        if (e.target.files && e.target.files[0]) {
                                            handleBrandingUpload(e.target.files[0], 'logoUrl');
                                        }
                                    }} />
                                </label>
                            </div>
                            {/* De src checkt nu of het begint met http, zo niet plakt hij er niets voor (relatief) */}
                            {config.logoUrl && <img src={config.logoUrl} alt="Logo Preview" className="mt-2 h-10 object-contain bg-neutral-800/50 p-1 rounded" />}
                        </div>

                        <div>
                            <label className="label-form">Favicon</label>
                            <div className="flex gap-2">
                                <input className="input-field" placeholder="https://..." value={config.faviconUrl || ''} onChange={e => setConfig({ ...config, faviconUrl: e.target.value })} />
                                <label className={`bg-neutral-800 border border-neutral-700 text-white p-3 rounded-lg flex items-center justify-center min-w-[3rem] ${isDemo ? 'opacity-40 cursor-not-allowed pointer-events-none' : 'hover:bg-neutral-700 cursor-pointer transition'}`} title={isDemo ? 'Disabled in demo' : 'Upload Favicon'}>
                                    <Upload className="w-5 h-5" />
                                    <input type="file" accept="image/x-icon,image/png,image/svg+xml" className="hidden" disabled={isDemo} onChange={(e) => {
                                        if (e.target.files && e.target.files[0]) {
                                            handleBrandingUpload(e.target.files[0], 'faviconUrl');
                                        }
                                    }} />
                                </label>
                            </div>
                            {config.faviconUrl && <img src={config.faviconUrl} alt="Favicon Preview" className="mt-2 w-8 h-8 object-contain bg-neutral-800/50 p-1 rounded" />}
                        </div>
                        <div><label className="label-form">App URL</label><input className="input-field" placeholder="https://share.domain.nl" value={config.appUrl || ''} onChange={e => setConfig({ ...config, appUrl: e.target.value })} /></div>

                        <h3 className="heading-panel mt-8 mb-6 flex gap-2"><Shield className="w-6 h-6 text-neutral-400" /> Security & Session</h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label className="label-form">Session duration</label>
                                <input
                                    type="number"
                                    className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white"
                                    value={config.sessionVal ?? ''}
                                    onChange={e => setConfig({ ...config, sessionVal: e.target.value === '' ? '' : parseInt(e.target.value) })}
                                    onBlur={() => { if (config.sessionVal === '') setConfig({ ...config, sessionVal: 7 }) }}
                                    placeholder="7"
                                />
                            </div>
                            <div>
                                <label className="label-form">Unit</label>
                                <div className="relative">
                                    <select
                                        className="input-field appearance-none pr-10"
                                        value={config.sessionUnit || 'Days'}
                                        onChange={e => setConfig({ ...config, sessionUnit: e.target.value })}
                                    >
                                        <option>Minutes</option>
                                        <option>Hours</option>
                                        <option>Days</option>
                                        <option>Weeks</option>
                                    </select>
                                    <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500 pointer-events-none" />
                                </div>
                            </div>
                        </div>
                        <Checkbox
                            checked={config.secureCookies || false}
                            onChange={(e) => setConfig({ ...config, secureCookies: e.target.checked })}
                            label="Secure Cookies (Require HTTPS)"
                        />

                        <h3 className="heading-panel mt-8 mb-6 flex gap-2 border-t border-neutral-800 pt-6"><Shield className="w-6 h-6 text-neutral-400" /> 2FA & Authentication</h3>
                        <div className="space-y-3">
                            <Checkbox
                                checked={config.require2FA || false}
                                onChange={(e) => setConfig({ ...config, require2FA: e.target.checked })}
                                label="Make 2FA Mandatory for all users"
                            />
                            <Checkbox
                                checked={config.allowPasskeys !== false}
                                onChange={e => setConfig({ ...config, allowPasskeys: e.target.checked })}
                                label="Allow Passkeys"
                            />
                            <Checkbox
                                checked={config.allowPasswordReset !== false}
                                onChange={e => setConfig({ ...config, allowPasswordReset: e.target.checked })}
                                label="Allow Password Reset (requires SMTP)"
                            />
                        </div>

                        <button onClick={save} className="bg-gradient-brand hover:brightness-90 text-white px-6 py-2 rounded-lg font-bold mt-4 transition btn-press">Save</button>
                    </div>
                    </DemoServerLockedChrome>
                )}

                {activeTab === 'system' && (
                    <DemoServerLockedChrome show={isDemo}>
                    <div className="space-y-6 anim-fade">
                        <h3 className="heading-panel mb-6 flex gap-2"><HardDrive className="w-6 h-6 text-neutral-400" /> Storage & Uploads</h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label className="label-form">Max Size</label>
                                <input
                                    type="number"
                                    className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white"
                                    value={config.maxSizeVal ?? ''}
                                    onChange={e => setConfig({ ...config, maxSizeVal: e.target.value === '' ? '' : parseInt(e.target.value) })}
                                    onBlur={() => { if (config.maxSizeVal === '') setConfig({ ...config, maxSizeVal: 10 }) }}
                                    placeholder="10"
                                />
                            </div>
                            <div>
                                <label className="label-form">Unit</label>
                                <div className="relative">
                                    <select
                                        className="input-field appearance-none pr-10"
                                        value={config.maxSizeUnit || 'GB'}
                                        onChange={e => setConfig({ ...config, maxSizeUnit: e.target.value })}
                                    >
                                        <option>MB</option>
                                        <option>GB</option>
                                        <option>TB</option>
                                    </select>
                                    <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500 pointer-events-none" />
                                </div>
                            </div>
                        </div>
                        {isDemo && typeof config.demoMaxFileMb === 'number' && (
                            <p className="text-xs text-cyan-400/90">
                                Demo: max share size and ClamAV scan limit are both enforced at {config.demoMaxFileMb} MB — nothing larger is accepted.
                            </p>
                        )}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label className="label-form">
                                    Chunk Size (Upload)
                                    <span className="ml-2 text-xs text-neutral-500 font-normal">(Recommended: 10-25 MB for Cloudflare)</span>
                                </label>
                                <input
                                    type="number"
                                    className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white"
                                    value={config.chunkSizeVal ?? ''}
                                    onChange={e => setConfig({ ...config, chunkSizeVal: e.target.value === '' ? '' : parseInt(e.target.value) })}
                                    onBlur={() => { if (config.chunkSizeVal === '') setConfig({ ...config, chunkSizeVal: 20 }) }}
                                    placeholder="20"
                                />
                                <p className="text-xs text-neutral-500 mt-1">
                                    Smaller chunks (10-25MB) are more resilient to network issues and Cloudflare tunnel timeouts.
                                </p>
                            </div>
                            <div>
                                <label className="label-form">Unit</label>
                                <div className="relative">
                                    <select
                                        className="input-field appearance-none pr-10"
                                        value={config.chunkSizeUnit || 'MB'}
                                        onChange={e => setConfig({ ...config, chunkSizeUnit: e.target.value })}
                                    >
                                        <option>KB</option>
                                        <option>MB</option>
                                    </select>
                                    <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500 pointer-events-none" />
                                </div>
                            </div>
                        </div>
                        <div>
                            <label className="label-form">Default Share ID Length</label>
                            <input
                                type="number"
                                min="8"
                                className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white"
                                value={config.shareIdLength ?? ''}
                                onChange={e => setConfig({ ...config, shareIdLength: e.target.value === '' ? '' : parseInt(e.target.value) })}
                                onBlur={() => { if (config.shareIdLength === '' || (config.shareIdLength as number) < 8) setConfig({ ...config, shareIdLength: 12 }) }} // Default 12 (en minimaal 8)
                                placeholder="12"
                            />
                            <p className="text-neutral-500 text-xs mt-1">Minimum 8 for safety.</p>
                        </div>
                        <h4 className="text-white font-bold text-lg mt-6 mb-4 flex gap-2 border-t border-neutral-800 pt-6">Expiration Times Policy</h4>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                            {/* Standaard Vervaltijd */}
                            <div>
                                <label className="label-form">Standard Expiry Time</label>
                                <div className="flex gap-3">
                                    <input
                                        type="number" min="0"
                                        className="input-field w-24"
                                        value={config.defaultExpirationVal ?? ''}
                                        onChange={e => setConfig({ ...config, defaultExpirationVal: e.target.value === '' ? '' : parseInt(e.target.value) })}
                                        onBlur={() => { if (config.defaultExpirationVal === '') setConfig({ ...config, defaultExpirationVal: 1 }) }}
                                        placeholder="1"
                                    />
                                    <div className="relative flex-1">
                                        <select
                                            className="input-field appearance-none pr-10"
                                            value={config.defaultExpirationUnit || 'Weeks'}
                                            onChange={e => setConfig({ ...config, defaultExpirationUnit: e.target.value })}
                                        >
                                            {UNITS.map(u => (
                                                <option key={u} value={u}>{getUnitLabel(config.defaultExpirationVal || 1, u)}</option>
                                            ))}
                                        </select>
                                        <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500 pointer-events-none" />
                                    </div>
                                </div>
                            </div>

                            {/* Maximale Vervaltijd */}
                            <div>
                                <label className="label-form">Maximum Expiration Time</label>
                                <div className="flex gap-3">
                                    <input
                                        type="number" min="0"
                                        className="input-field w-24"
                                        value={config.maxExpirationVal ?? ''}
                                        onChange={e => setConfig({ ...config, maxExpirationVal: e.target.value === '' ? '' : parseInt(e.target.value) })}
                                        onBlur={() => { if (config.maxExpirationVal === '') setConfig({ ...config, maxExpirationVal: 0 }) }}
                                        placeholder="0"
                                    />
                                    <div className="relative flex-1">
                                        <select
                                            className="input-field appearance-none pr-10"
                                            value={config.maxExpirationUnit || 'Months'}
                                            onChange={e => setConfig({ ...config, maxExpirationUnit: e.target.value })}
                                        >
                                            {UNITS.map(u => (
                                                <option key={u} value={u}>{getUnitLabel(config.maxExpirationVal || 0, u)}</option>
                                            ))}
                                        </select>
                                        <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500 pointer-events-none" />
                                    </div>
                                </div>
                            </div>
                        </div>

                        <h3 className="heading-panel mt-8 mb-6 flex gap-2"><FileArchive className="w-6 h-6 text-neutral-400" /> Compression (Zip)</h3>
                        <div><label className="label-form">Compression Level (0-9)</label><input type="range" min="0" max="9" className="w-full accent-primary" value={config.zipLevel || 5} onChange={e => setConfig({ ...config, zipLevel: parseInt(e.target.value) })} /><div className="text-white text-center font-bold mt-2">{config.zipLevel || 5}</div></div>
                        <div className="pt-2">
                            <Checkbox
                                checked={config.zipNoMedia || false}
                                onChange={e => setConfig({ ...config, zipNoMedia: e.target.checked })}
                                label="No compression for media"
                            />
                        </div>
                        <button onClick={save} className="bg-gradient-brand hover:brightness-90 text-white px-6 py-2 rounded-lg font-bold mt-4 transition btn-press">Save</button>
                    </div>
                    </DemoServerLockedChrome>
                )}

                {activeTab === 'security' && (
                    <DemoServerLockedChrome show={isDemo}>
                    <div className="space-y-6 anim-fade">
                        <h3 className="heading-panel mb-6 flex gap-2"><Shield className="w-6 h-6 text-neutral-400" /> Security Policies</h3>

                        <div className="space-y-4 bg-red-500/5 p-4 rounded-xl border border-red-500/20 mb-8">
                            <div className="flex items-start gap-3">
                                <Checkbox
                                    checked={!!(config.clamavMustScan || isDemo)}
                                    onChange={e => setConfig({ ...config, clamavMustScan: e.target.checked })}
                                    className="mt-1"
                                />
                                <div>
                                    <span className="text-white font-bold block cursor-pointer" onClick={() => setConfig({ ...config, clamavMustScan: !config.clamavMustScan })}>Enforce Virus Scan</span>
                                    <p className="text-neutral-400 text-sm mt-1">
                                        If checked, uploads will be <strong>rejected</strong> if the ClamAV scanner is unreachable.
                                        <br />
                                        <span className="text-xs text-neutral-500">Default (off): Uploads will continue, but will not be scanned if ClamAV is offline.</span>
                                    </p>
                                    {isDemo && (
                                        <p className="text-xs text-cyan-400/90 mt-2">
                                            Demo: enforced on the server — uploads are rejected if ClamAV is offline or if scanning fails.
                                        </p>
                                    )}
                                </div>
                            </div>

                            {/* Max Virus Scan File Size */}
                            <div className="border-t border-red-500/20 pt-4 mt-4">
                                <label className="block text-white font-bold mb-2">Max Virus Scan File Size</label>
                                <p className="text-neutral-400 text-sm mb-3">
                                    Files larger than this limit will skip virus scanning (or be rejected if "Enforce Virus Scan" is enabled).
                                </p>
                                <div className="flex gap-2 items-center">
                                    <input
                                        type="number"
                                        min="1"
                                        className="input-field w-24 p-2 py-2 text-center"
                                        value={config.maxScanSizeVal || 25}
                                        onChange={e => setConfig({ ...config, maxScanSizeVal: parseInt(e.target.value) || 25 })}
                                    />
                                    <select
                                        className="select-field w-auto min-w-[3.5rem] py-2 pl-2 pr-7 text-sm"
                                        value={config.maxScanSizeUnit || 'MB'}
                                        onChange={e => setConfig({ ...config, maxScanSizeUnit: e.target.value })}
                                    >
                                        <option value="KB">KB</option>
                                        <option value="MB">MB</option>
                                        <option value="GB">GB</option>
                                        <option value="TB">TB</option>
                                    </select>
                                    <span className="text-neutral-500 text-sm ml-2">(ClamAV default: 25 MB)</span>
                                </div>

                                {/* Warning when value exceeds default */}
                                {(() => {
                                    const val = config.maxScanSizeVal || 25;
                                    const unit = config.maxScanSizeUnit || 'MB';
                                    const multipliers: any = { 'KB': 1 / 1024, 'MB': 1, 'GB': 1024, 'TB': 1024 * 1024 };
                                    const inMB = val * (multipliers[unit] || 1);
                                    if (inMB > 25) {
                                        return (
                                            <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                                                <p className="text-yellow-400 text-sm font-bold flex items-center gap-2">
                                                    <AlertTriangle className="w-4 h-4" /> ClamAV Configuration Required
                                                </p>
                                                <p className="text-yellow-200/80 text-xs mt-2">
                                                    You've set a limit higher than ClamAV's default (25 MB). Update your ClamAV config:
                                                </p>

                                                <p className="text-neutral-400 text-xs mt-3 font-bold">Option 1: clamd.conf</p>
                                                <pre className="mt-1 bg-black p-2 rounded text-xs text-green-400 font-mono overflow-x-auto">
                                                    {`StreamMaxLength ${Math.ceil(inMB)}M
MaxScanSize ${Math.ceil(inMB)}M
MaxFileSize ${Math.ceil(inMB)}M`}
                                                </pre>

                                                <p className="text-neutral-400 text-xs mt-3 font-bold">Option 2: Docker Compose (environmental variables for the ClamAV container)</p>
                                                <pre className="mt-1 bg-black p-2 rounded text-xs text-blue-400 font-mono overflow-x-auto">
                                                    {`environment:
  - CLAMD_CONF_StreamMaxLength=${Math.ceil(inMB)}M
  - CLAMD_CONF_MaxScanSize=${Math.ceil(inMB)}M
  - CLAMD_CONF_MaxFileSize=${Math.ceil(inMB)}M`}
                                                </pre>

                                                <p className="text-neutral-500 text-xs mt-2">Then restart ClamAV for changes to take effect.</p>
                                            </div>
                                        );
                                    }
                                    return null;
                                })()}
                            </div>
                        </div>

                        <div className="border-t border-neutral-800 pt-6">
                            <h3 className="heading-panel mb-6 flex gap-2"><FileIcon className="w-6 h-6 text-neutral-400" /> File Type Restrictions</h3>
                            <p className="text-neutral-400 text-sm mb-6">Specify which file extensions should be blocked. <br />Files with these extensions will be rejected immediately upon upload.</p>

                            <ExtensionSelector
                                label="Authenticated User Uploads"
                                blocked={config.blockedExtensionsUser || []}
                                onChange={(list) => setConfig({ ...config, blockedExtensionsUser: list })}
                            />

                            <ExtensionSelector
                                label="Guest / Reverse Share Uploads"
                                blocked={config.blockedExtensionsGuest || []}
                                onChange={(list) => setConfig({ ...config, blockedExtensionsGuest: list })}
                            />
                        </div>

                        <button onClick={save} className="bg-gradient-brand hover:brightness-90 text-white px-6 py-2 rounded-lg font-bold mt-4 transition btn-press">Save</button>
                    </div>
                    </DemoServerLockedChrome>
                )}

                {activeTab === 'smtp' && (
                    <DemoServerLockedChrome show={isDemo}>
                    <div className="space-y-6 anim-fade">
                        <h3 className="heading-panel mb-6 flex gap-2"><Mail className="w-6 h-6 text-neutral-400" /> Email Configuration</h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div className="md:col-span-2"><label className="label-form">Host</label><input className="input-field" value={config.smtpHost || ''} onChange={e => setConfig({ ...config, smtpHost: e.target.value })} placeholder="smtp.office365.com" /></div>

                            <div><label className="label-form">Port</label><input type="number" className="input-field" value={config.smtpPort || ''} onChange={e => setConfig({ ...config, smtpPort: parseInt(e.target.value) })} placeholder="465" /></div>

                            {/* Afzender Adres */}
                            <div><label className="label-form">Sender (From)</label><input className="input-field" value={config.smtpFrom || ''} onChange={e => setConfig({ ...config, smtpFrom: e.target.value })} placeholder="noreply@domain.nl" /></div>

                            <div><label className="label-form">Username</label><input className="input-field" value={config.smtpUser || ''} onChange={e => setConfig({ ...config, smtpUser: e.target.value })} placeholder="email@domain.nl" /></div>

                            <div>
                                <label className="label-form">Password</label>
                                <input
                                    className="input-field"
                                    type="password"
                                    placeholder="Leave blank for no change"
                                    value={config.smtpPass || ''}
                                    onChange={e => setConfig({ ...config, smtpPass: e.target.value })}
                                />
                            </div>
                        </div>

                        <div className="flex flex-col gap-4 pt-2 border-t border-neutral-800 mt-4">
                            <Checkbox
                                checked={config.smtpSecure || false}
                                onChange={e => setConfig({ ...config, smtpSecure: e.target.checked })}
                                label="Use SSL (Often port 465)"
                            />
                            <Checkbox
                                checked={config.smtpStartTls !== false}
                                onChange={e => setConfig({ ...config, smtpStartTls: e.target.checked })}
                                label="Use STARTTLS (Often port 587)"
                            />
                            <div className="flex items-start gap-3">
                                <Checkbox
                                    checked={config.smtpAllowLocal || false}
                                    onChange={e => setConfig({ ...config, smtpAllowLocal: e.target.checked })}
                                    className="mt-1"
                                />
                                <div>
                                    <span className="text-white font-medium block cursor-pointer" onClick={() => setConfig({ ...config, smtpAllowLocal: !config.smtpAllowLocal })}>Allow Local/Private IP addresses</span>
                                    <span className="text-neutral-500 text-xs">Only enable this if your SMTP server is on the same network (e.g. 192.168.x.x or localhost).</span>
                                </div>
                            </div>
                        </div>

                        <div className="flex gap-3 mt-6 items-center">
                            <button onClick={save} className="bg-gradient-brand hover:brightness-90 text-white px-6 py-2 rounded-lg font-bold transition btn-press shadow-lg shadow-primary-950/25">Save</button>
                            {!isDemo && (
                                <button onClick={testEmail} className="bg-neutral-800 hover:bg-neutral-700 text-white px-6 py-2 rounded-lg font-bold border border-neutral-700 transition btn-press flex items-center gap-2"><Send className="w-4 h-4" /> Test Connection</button>
                            )}
                        </div>

                        {/* Contactenlijst blijft hieronder ongewijzigd... */}
                        <div className="border-t border-neutral-700 pt-6 mt-6">
                            <h4 className="text-white font-bold mb-4 flex items-center gap-2"><Contact className="w-5 h-5" /> Saved Contacts</h4>
                            <div className="bg-black rounded-lg p-4 max-h-60 overflow-y-auto space-y-2 border border-neutral-700">
                                {contacts.map(c => (
                                    <div key={c.id} className="flex justify-between items-center bg-neutral-900 p-3 rounded-lg border border-neutral-700 hover:border-neutral-500 transition">
                                        <span className="text-neutral-300">{c.email}</span>
                                        <button onClick={() => deleteContact(c.id)} className="text-red-400 hover:text-red-300 transition"><X className="w-4 h-4" /></button>
                                    </div>
                                ))}
                                {contacts.length === 0 && <span className="text-neutral-500 text-sm">No contacts saved yet.</span>}
                            </div>
                        </div>
                    </div>
                    </DemoServerLockedChrome>
                )}

                {activeTab === 'sso' && (
                    <DemoServerLockedChrome
                        show={isDemo}
                        unlockTop={
                            isDemo ? (
                                <div className="mb-4 select-text rounded-lg border border-neutral-700 bg-neutral-800/50 p-4 text-sm text-neutral-300">
                                    <span className="font-medium text-white">Callback URL</span>
                                    <code className="mt-2 block break-all rounded border border-neutral-700 bg-black/50 px-2 py-1.5 font-mono text-xs text-primary-300">
                                        {window.location.origin}/api/auth/callback
                                    </code>
                                </div>
                            ) : undefined
                        }
                    >
                    <div className="space-y-6 anim-fade">
                        <h3 className="heading-panel mb-6 flex gap-2"><Shield className="w-6 h-6 text-neutral-400" /> SSO (OIDC)</h3>
                        {!isDemo && (
                        <div className="bg-neutral-800/50 border border-neutral-700 p-4 rounded-lg text-neutral-300 text-sm mb-6">Callback URL: <code className="select-text bg-black/50 px-2 py-1 rounded border border-neutral-700 text-primary-300 break-all inline-block">{window.location.origin}/api/auth/callback</code></div>
                        )}

                        <div><label className="label-form">Issuer URL</label><input className="input-field" value={config.oidcIssuer || ''} onChange={e => setConfig({ ...config, oidcIssuer: e.target.value })} /></div>
                        <div><label className="label-form">Client ID</label><input className="input-field" value={config.oidcClientId || ''} onChange={e => setConfig({ ...config, oidcClientId: e.target.value })} /></div>
                        <div>
                            <label className="label-form">Client Secret</label>
                            <input
                                className="input-field"
                                type="password"
                                placeholder="Leave blank for no change"
                                value={config.oidcSecret || ''}
                                onChange={e => setConfig({ ...config, oidcSecret: e.target.value })}
                            />
                        </div>

                        <div><label className="label-form">SSO Logout URL (Optional)</label><input className="input-field" placeholder="E.g. https://auth.provider.com/logout?returnTo=..." value={config.ssoLogoutUrl || ''} onChange={e => setConfig({ ...config, ssoLogoutUrl: e.target.value })} /></div>

                        <div className="space-y-3 pt-2">
                            <Checkbox
                                checked={config.ssoEnabled || false}
                                onChange={e => setConfig({ ...config, ssoEnabled: e.target.checked })}
                                label="Enable SSO"
                            />
                            <Checkbox
                                checked={config.ssoAutoRedirect || false}
                                onChange={e => setConfig({ ...config, ssoAutoRedirect: e.target.checked })}
                                label="Auto-Redirect to SSO (Skip login)"
                            />
                        </div>

                        <button onClick={save} className="bg-gradient-brand hover:brightness-90 text-white px-6 py-2 rounded-lg font-bold mt-4 transition btn-press">Save settings</button>
                    </div>
                    </DemoServerLockedChrome>
                )}

                {activeTab === 'users' && (
                    <DemoServerLockedChrome show={isDemo}>
                    <div className="anim-fade">
                        <h3 className="heading-panel mb-6 flex gap-2"><User className="w-6 h-6 text-neutral-400" /> User management</h3>
                        {!isDemo && (
                        <div className="bg-black/50 p-6 rounded-xl mb-6 border border-neutral-700">
                            <h4 className="text-white text-sm font-bold mb-4 uppercase text-neutral-500">Add new user</h4>
                            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                                <input placeholder="Name" className="input-field !bg-neutral-900" value={newUser.name} onChange={e => setNewUser({ ...newUser, name: e.target.value })} />
                                <input placeholder="Email" className="input-field !bg-neutral-900" value={newUser.email} onChange={e => setNewUser({ ...newUser, email: e.target.value })} />

                                {/* Password Veld met Focus events */}
                                <input
                                    placeholder="Password"
                                    type="password"
                                    className="input-field !bg-neutral-900"
                                    value={newUser.password}
                                    onChange={e => setNewUser({ ...newUser, password: e.target.value })}
                                    onFocus={() => setIsPwdFocused(true)} // Laat zien
                                    onBlur={() => setIsPwdFocused(false)} // Verberg
                                />

                                <div className="flex gap-2">
                                    <div className="bg-neutral-900 px-3 rounded-lg border border-neutral-700 flex-1 flex items-center justify-center">
                                        <Checkbox
                                            checked={newUser.is_admin}
                                            onChange={e => setNewUser({ ...newUser, is_admin: e.target.checked })}
                                            label={<span className="text-sm">Admin</span>}
                                        />
                                    </div>
                                    <button onClick={createUser} className="bg-green-600 hover:bg-green-700 text-white p-3 rounded-lg transition btn-press"><Plus className="w-5 h-5" /></button>
                                </div>
                            </div>

                            {/* Validatie Box (Zichtbaar zodra er tekst is, of als er focus is) */}
                            <div className={`overflow-hidden transition-all duration-300 ${(isPwdFocused || newUser.password.length > 0) ? 'max-h-20 opacity-100 mt-3' : 'max-h-0 opacity-0'}`}>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs bg-neutral-900/50 p-3 rounded-lg border border-neutral-800">
                                    <div className={`flex items-center gap-1.5 ${pwdValid.length ? 'text-green-500' : 'text-neutral-500'}`}>
                                        {pwdValid.length ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} 8+ characters
                                    </div>
                                    <div className={`flex items-center gap-1.5 ${pwdValid.upper ? 'text-green-500' : 'text-neutral-500'}`}>
                                        {pwdValid.upper ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Upper case
                                    </div>
                                    <div className={`flex items-center gap-1.5 ${pwdValid.lower ? 'text-green-500' : 'text-neutral-500'}`}>
                                        {pwdValid.lower ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Lower case
                                    </div>
                                    <div className={`flex items-center gap-1.5 ${pwdValid.number ? 'text-green-500' : 'text-neutral-500'}`}>
                                        {pwdValid.number ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Number
                                    </div>
                                </div>
                            </div>
                        </div>
                        )}
                        <div className="space-y-3 mb-6">
                            {users.map(u => (
                                <div key={u.id} className="flex justify-between items-center bg-neutral-900 p-4 rounded-xl border border-neutral-700 hover:border-neutral-600 transition">
                                    <div className="flex items-center gap-4">
                                        <div className="w-10 h-10 bg-gradient-to-br from-primary to-neutral-700 rounded-full flex items-center justify-center font-bold text-white">{u.name.charAt(0)}</div>
                                        <div>
                                            <div className="font-bold text-white flex items-center gap-2">{u.name} {u.is_admin && <span className="text-[10px] bg-primary text-white px-2 py-0.5 rounded-full uppercase tracking-wider">Admin</span>}</div>
                                            <div className="text-sm text-neutral-500">{u.email}</div>
                                        </div>
                                    </div>
                                    {!isDemo && (
                                    <div className="flex gap-2">
                                        <button onClick={() => setEditUser(u)} className="text-neutral-400 hover:bg-neutral-800 p-2 rounded-lg transition" title="Edit"><Edit className="w-5 h-5" /></button>
                                        <button onClick={() => reset2FA(u.id)} className="text-neutral-400 hover:bg-primary/10 hover:text-primary-400 p-2 rounded-lg transition btn-press" title="Reset 2FA"><Shield className="w-5 h-5" /></button>
                                        <button onClick={() => deleteUser(u.id)} className="text-neutral-500 hover:bg-red-500/10 hover:text-red-500 p-2 rounded-lg transition btn-press" title="Delete"><Trash2 className="w-5 h-5" /></button>
                                    </div>
                                    )}
                                </div>
                            ))}
                        </div>
                        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-4 md:p-6 text-sm text-yellow-200/80">
                            <h4 className="text-yellow-500 font-bold mb-2 flex items-center gap-2">
                                <Info className="w-4 h-4" /> Password Requirements
                            </h4>
                            <ul className="list-disc list-inside space-y-1 ml-1">
                                <li>At least <strong>8 characters</strong> long</li>
                                <li>At least 1 <strong>upper case</strong> (A-Z)</li>
                                <li>At least 1 <strong>lower case</strong> (a-z)</li>
                                <li>At least 1 <strong>number</strong> (0-9)</li>
                            </ul>
                            <p className="mt-3 text-xs opacity-70">
                                Weak passwords will be rejected.
                            </p>
                        </div>
                    </div>
                    </DemoServerLockedChrome>
                )}
            </div>

            <AnimatePresence>
                {editUser && (
                    <ModalPortal>
                        <motion.div
                            key="edit-user-modal"
                            initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            animate={{ opacity: 1, backdropFilter: "blur(4px)" }}
                            exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            className="fixed inset-0 bg-black/80 z-[9999] flex items-center justify-center p-4"
                            onClick={() => setEditUser(null)}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.95, opacity: 0 }}
                                className="bg-neutral-900 w-full max-w-lg rounded-2xl border border-neutral-700 p-4 md:p-8 shadow-2xl"
                                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                            >
                                <h3 className="heading-panel mb-6">Edit User</h3>
                                <div className="space-y-4">
                                    <div><label className="label-form-compact">Name</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white" value={editUser.name} onChange={e => setEditUser({ ...editUser, name: e.target.value })} /></div>
                                    <div><label className="label-form-compact">Email</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white" value={editUser.email} onChange={e => setEditUser({ ...editUser, email: e.target.value })} /></div>
                                    <div><label className="label-form-compact">Password (Leave blank for no change)</label><input className="w-full bg-black border border-neutral-700 rounded-lg p-3 text-white" type="password" placeholder="New Password" onChange={e => setEditUser({ ...editUser, password: e.target.value })}
                                    />
                                        {/* Validatie Box voor Edit User */}
                                        {editUser.password && editUser.password.length > 0 && (
                                            <div className="mt-2 grid grid-cols-2 gap-2 text-xs mb-3 p-3 bg-neutral-900/50 rounded-lg border border-neutral-800">
                                                <div className={`flex items-center gap-1.5 ${pwdValid.length ? 'text-green-500' : 'text-neutral-500'}`}>
                                                    {pwdValid.length ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} 8+ characters
                                                </div>
                                                <div className={`flex items-center gap-1.5 ${pwdValid.upper ? 'text-green-500' : 'text-neutral-500'}`}>
                                                    {pwdValid.upper ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Upper case
                                                </div>
                                                <div className={`flex items-center gap-1.5 ${pwdValid.lower ? 'text-green-500' : 'text-neutral-500'}`}>
                                                    {pwdValid.lower ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Lower case
                                                </div>
                                                <div className={`flex items-center gap-1.5 ${pwdValid.number ? 'text-green-500' : 'text-neutral-500'}`}>
                                                    {pwdValid.number ? <Check className="w-3 h-3" /> : <div className="w-3 h-3 rounded-full border border-neutral-600" />} Number
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                    <Checkbox
                                        checked={editUser.is_admin}
                                        onChange={e => setEditUser({ ...editUser, is_admin: e.target.checked })}
                                        label="Admin privileges"
                                    />
                                </div>
                                <div className="flex justify-end gap-3 mt-6 border-t border-neutral-700 pt-4">
                                    <button onClick={() => setEditUser(null)} className="text-neutral-400 hover:text-white px-4 py-2 transition">Cancel</button>
                                    <button onClick={updateUser} className="bg-gradient-brand hover:brightness-90 px-6 py-2 rounded-lg text-white font-bold transition btn-press">Save</button>
                                </div>
                            </motion.div>
                        </motion.div>
                    </ModalPortal>
                )}
            </AnimatePresence>
        </div>
    );
};
