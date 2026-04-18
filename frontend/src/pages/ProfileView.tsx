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

/** Demo: grey + inert only for General (form fields). Other tabs hide actions and stay visually normal. */
function DemoProfileGeneralLock({ locked, children }: { locked: boolean; children: React.ReactNode }) {
    if (!locked) return <>{children}</>;
    return (
        <div
            className="demo-server-locked rounded-xl border border-neutral-600/50 bg-neutral-950/50 p-3 opacity-[0.58] shadow-inner ring-1 ring-black/40 saturate-75 md:p-5 [&_button]:pointer-events-none [&_input]:cursor-not-allowed [&_label]:cursor-default [&_select]:cursor-not-allowed"
            {...({ inert: true } as React.HTMLAttributes<HTMLDivElement>)}
        >
            {children}
        </div>
    );
}

export function ProfileView({ user, config, forcedSetup = false, onComplete }: { user: any, config: any, forcedSetup?: boolean, onComplete?: () => void }) {
    const [form, setForm] = useState({ name: user.name, email: user.email, password: '' });

    // Hulpfunctie: Haal hostname uit config.appUrl (bijv. "mijnshare.nl" of "localhost")
    const getDomain = (url: string) => {
        try {
            if (!url) return window.location.hostname;
            return new URL(url).hostname;
        } catch (e) {
            return window.location.hostname;
        }
    };
    const [tab, setTab] = useState<'general' | '2fa' | 'passkeys' | 'danger'>(forcedSetup ? '2fa' : 'general');

    // Validatie State voor Profiel
    const [pwdValid, setPwdValid] = useState({ length: false, upper: false, lower: false, number: false });

    // Update validatie bij typen (form.password gebruiken)
    useEffect(() => {
        const p = form.password;
        setPwdValid({
            length: p.length >= 8,
            upper: /[A-Z]/.test(p),
            lower: /[a-z]/.test(p),
            number: /[0-9]/.test(p)
        });
    }, [form.password]);

    // 2FA States
    const [twoFactorEnabled, setTwoFactorEnabled] = useState(false);
    const [twoFactorSecret, setTwoFactorSecret] = useState('');
    const [twoFactorQR, setTwoFactorQR] = useState('');
    const [twoFactorCode, setTwoFactorCode] = useState('');
    const [twoFactorBackupCodes, setTwoFactorBackupCodes] = useState<string[]>([]);
    const [backupCodesRemaining, setBackupCodesRemaining] = useState(0);
    const [show2FASetup, setShow2FASetup] = useState(false);
    useEffect(() => {
        if (forcedSetup && !twoFactorEnabled) {
            // We roepen de setup functie aan om QR codes te genereren
            handleSetup2FA();
        }
    }, [forcedSetup, twoFactorEnabled]);
    const [show2FADisable, setShow2FADisable] = useState(false);
    const [disable2FAPassword, setDisable2FAPassword] = useState('');

    // Passkey States
    const [passkeys, setPasskeys] = useState<any[]>([]);
    const [passkeyName, setPasskeyName] = useState('');
    const [showPasskeyAdd, setShowPasskeyAdd] = useState(false);

    // Delete Account States
    const [showDeleteAccount, setShowDeleteAccount] = useState(false);
    const [deletePassword, setDeletePassword] = useState('');

    /** Programmatic backup download via a persistent hidden anchor (avoids per-click DOM injection patterns). */
    const backupDownloadRef = useRef<HTMLAnchorElement>(null);

    const { notify, confirm, isConfirming, isPreviewing } = useUI();
    const isDemo = !!config?.demoMode;

    // Esc keys
    useEscapeKey(() => { setShow2FASetup(false); setTwoFactorSecret(''); setTwoFactorQR(''); }, show2FASetup && !isConfirming && !isPreviewing);
    useEscapeKey(() => setShow2FADisable(false), show2FADisable && !isConfirming && !isPreviewing);
    useEscapeKey(() => setShowPasskeyAdd(false), showPasskeyAdd && !isConfirming && !isPreviewing);
    useEscapeKey(() => setShowDeleteAccount(false), showDeleteAccount && !isConfirming && !isPreviewing);

    useEffect(() => {
        fetch2FAStatus();
        fetchPasskeys();
    }, []);

    const fetch2FAStatus = async () => {
        const res = await fetch(`${API_URL}/auth/2fa/status`, {
            credentials: 'include'
        });
        if (res.ok) {
            const data = await res.json();
            setTwoFactorEnabled(data.enabled);
            setBackupCodesRemaining(data.backupCodesRemaining);
        }
    };

    const fetchPasskeys = async () => {
        const res = await fetch(`${API_URL}/passkeys`, {
            credentials: 'include'
        });
        if (res.ok) {
            const data = await res.json();
            setPasskeys(data);
        }
    };

    const save = async () => {
        if (isDemo) {
            notify('Profile changes are disabled in demo mode.', 'error');
            return;
        }
        if (form.password && form.password.length > 0) {
            if (form.password.length < 8) {
                notify('Password needs to contain at least 8 characters', 'error');
                return;
            }
            if (!/[a-z]/.test(form.password) || !/[A-Z]/.test(form.password) || !/[0-9]/.test(form.password)) {
                notify('Password must contain at least 1 lowercase letter, 1 uppercase letter and 1 number', 'error');
                return;
            }
        }

        const res = await fetch(`${API_URL}/users/profile`, {
            method: 'PUT',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(form)
        });

        if (res.ok) {
            notify('Profile saved', 'success');
        } else {
            const data = await res.json();
            notify(data.error || 'Save failed', 'error');
        }
    };

    const handleSetup2FA = async () => {
        const res = await fetch(`${API_URL}/auth/2fa/setup`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await res.json();
        if (res.ok) {
            setTwoFactorSecret(data.secret);
            setTwoFactorQR(data.qrCode);
            setShow2FASetup(true);
        } else {
            notify(data.error || '2FA Setup failed', 'error');
        }
    };

    const handleEnable2FA = async (e: any) => {
        e.preventDefault();
        const res = await fetch(`${API_URL}/auth/2fa/enable`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secret: twoFactorSecret, code: twoFactorCode })
        });
        const data = await res.json();
        if (res.ok) {
            setTwoFactorBackupCodes(data.backupCodes);
            setTwoFactorEnabled(true);
            setTwoFactorCode('');
            notify('2FA successfully enabled!', 'success');
            await fetch2FAStatus();
        } else {
            notify(data.error || '2FA activation failed', 'error');
        }
    };

    const handleDisable2FA = async (e: any) => {
        e.preventDefault();
        const res = await fetch(`${API_URL}/auth/2fa/disable`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: disable2FAPassword })
        });
        if (res.ok) {
            setTwoFactorEnabled(false);
            setShow2FADisable(false);
            setDisable2FAPassword('');
            setTwoFactorSecret('');
            setTwoFactorQR('');
            setTwoFactorBackupCodes([]);
            notify('2FA disabled', 'success');
            await fetch2FAStatus();
        } else {
            const data = await res.json();
            notify(data.error || 'Failed to disable 2FA', 'error');
        }
    };

    const handleRegisterPasskey = async () => {
        if (!passkeyName.trim()) {
            notify('Give your passkey a name', 'error');
            return;
        }

        try {
            const rpDomain = getDomain(config?.appUrl);

            // 1. Opties ophalen
            const optionsRes = await fetch(`${API_URL}/passkeys/register/options`, {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: passkeyName, domain: rpDomain })
            });

            if (!optionsRes.ok) throw new Error('Could not retrieve passkey options');

            const options = await optionsRes.json();

            // 2. Start Registratie - Library handelt base64url automatisch af
            let credential;
            try {
                // Moderne syntax (v9+)
                credential = await startRegistration(options);
            } catch (syntaxError) {
                console.warn("New syntax didn't work, try legacy...", syntaxError);
                // Legacy fallback
                credential = await startRegistration(options);
            }

            // 3. Verificatie naar server sturen
            const verifyRes = await fetch(`${API_URL}/passkeys/register/verify`, {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    response: credential,
                    name: passkeyName,
                    domain: rpDomain
                })
            });

            const verifyData = await verifyRes.json();
            if (!verifyRes.ok) throw new Error(verifyData.error || 'Passkey verification failed');

            notify('Passkey registered successfully', 'success');
            setPasskeyName('');
            setShowPasskeyAdd(false);
            await fetchPasskeys();

        } catch (err: any) {
            console.error("Passkey Error:", err);
            notify(err.message || 'Passkey registration failed', 'error');
        }
    };

    const handleDeletePasskey = async (id: number) => {
        confirm('Are you sure you want to delete this passkey?', async () => {
            const res = await fetch(`${API_URL}/passkeys/${id}`, {
                method: 'DELETE',
                credentials: 'include'
            });
            if (res.ok) {
                notify('Passkey deleted', 'success');
                await fetchPasskeys();
            } else {
                notify('Passkey deletion failed', 'error');
            }
        });
    };

    const handleDeleteAccount = async (e: any) => {
        e.preventDefault();
        confirm('Are you SURE you want to delete your account? This cannot be undone!', async () => {
            const res = await fetch(`${API_URL}/users/me/delete`, {
                method: 'DELETE',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: deletePassword })
            });
            if (res.ok) {
                notify('Account deleted successfully', 'success');
                setTimeout(() => {
                    localStorage.removeItem('token');
                    localStorage.removeItem('user');
                    window.location.href = '/login';
                }, 1000);
            } else {
                const data = await res.json();
                notify(data.error || 'Deletion failed', 'error');
            }
        });
    };

    const tabClass = (id: string) => `flex-1 text-center px-4 py-4 font-bold transition whitespace-nowrap border-b-2 cursor-pointer ${tab === id ? 'border-primary-400 text-white bg-neutral-800' : 'border-transparent text-neutral-400 hover:text-white hover:bg-neutral-800'}`;

    const handleCopyAllCodes = () => {
        const text = twoFactorBackupCodes.join('\n');
        navigator.clipboard.writeText(text);
        notify('All codes copied to clipboard', 'success');
    };

    const handleDownloadCodes = () => {
        const text = `${config.appName || 'Nexo Share'} Backup Codes\n\nKeep these codes in a safe place.\nIf you no longer have access to your authenticator app, you can use these codes to log in.\n\n${twoFactorBackupCodes.join('\n')}\n\nGenerated on: ${new Date().toLocaleString('en-GB')}`;
        const blob = new Blob([text], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);

        const a = backupDownloadRef.current;
        if (!a) {
            URL.revokeObjectURL(url);
            notify('Download failed', 'error');
            return;
        }

        let rawAppName = (config.appName || 'Nexo Share').replace(/[^a-zA-Z0-9_\-]/g, '').trim();
        let safeAppName = DOMPurify.sanitize(rawAppName);
        if (!safeAppName) safeAppName = 'Nexo-Share';

        a.href = url;
        a.setAttribute('download', `${safeAppName}-backup-codes.txt`);
        a.click();

        setTimeout(() => {
            a.removeAttribute('href');
            a.removeAttribute('download');
            URL.revokeObjectURL(url);
        }, 100);

        notify('Codes downloaded', 'success');
    };

    return (
        <div className="max-w-4xl mx-auto anim-slide">
            <a
                ref={backupDownloadRef}
                className="pointer-events-none fixed left-[-9999px] top-0 opacity-0"
                aria-hidden
                tabIndex={-1}
            />
            <div className="bg-neutral-900 rounded-xl border border-neutral-800 shadow-xl overflow-hidden">
                {/* VERBERG TABS BIJ FORCED SETUP */}
                {!forcedSetup && (
                    <div className="flex border-b border-neutral-800 overflow-x-auto scrollbar-hide">
                        <button onClick={() => setTab('general')} className={tabClass('general')}>General</button>
                        <button onClick={() => setTab('2fa')} className={tabClass('2fa')}>2FA</button>
                        <button onClick={() => setTab('passkeys')} className={tabClass('passkeys')}>Passkeys</button>
                        <button onClick={() => setTab('danger')} className={tabClass('danger')}>Danger Zone</button>
                    </div>
                )}

                <div className="p-4 md:p-8">
                    {isDemo && (
                        <div className="mb-6 space-y-3">
                            <div className="flex items-center gap-2 rounded-md border border-cyan-900/45 bg-slate-900/85 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-neutral-400">
                                <LockIcon className="h-3.5 w-3.5 shrink-0 text-cyan-500/90" aria-hidden />
                                Locked by the server — profile and security settings are enforced remotely; you cannot change or select them here.
                            </div>
                            <div className="rounded-lg border border-cyan-800/40 bg-slate-900/70 px-4 py-3 text-sm text-neutral-300">
                                Demo mode: you cannot change your profile, 2FA, passkeys, or delete your account here.
                            </div>
                        </div>
                    )}
                    {tab === 'general' && (
                        <DemoProfileGeneralLock locked={isDemo}>
                        <div className="space-y-4">
                            <h2 className="heading-section mb-6 flex items-center gap-2"><User className="text-neutral-400" /> My profile</h2>
                            <div><label className="label-form">Name</label><input className="input-field" disabled={isDemo} value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></div>
                            <div><label className="label-form">Email</label><input className="input-field" disabled={isDemo} value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} /></div>
                            {/* Password Sectie */}
                            <div className="pt-4 border-t border-neutral-800 mt-4">
                                <h3 className="text-white font-bold mb-4 flex items-center gap-2">
                                    <LockIcon className="w-4 h-4 text-neutral-400" /> Change Password
                                </h3>

                                <div className="grid gap-4">
                                    {/* 1. Huidig Password (Altijd zichtbaar, bovenaan) */}
                                    <div>
                                        <label className="label-form">Current Password</label>
                                        <input
                                            className="input-field"
                                            type="password"
                                            disabled={isDemo}
                                            placeholder="Your current password (required for changing)"
                                            value={(form as any).currentPassword || ''}
                                            onChange={e => setForm({ ...form, currentPassword: e.target.value } as any)}
                                        />
                                    </div>

                                    {/* 2. Nieuw Password */}
                                    <div>
                                        <label className="label-form">New Password</label>
                                        <input
                                            className="input-field"
                                            type="password"
                                            disabled={isDemo}
                                            placeholder="New password (leave blank if you don't want to change it)"
                                            value={form.password}
                                            onChange={e => setForm({ ...form, password: e.target.value })}
                                        />
                                    </div>
                                </div>

                                {/* Validatie Box (Alleen tonen als er een nieuw Password wordt getypt) */}
                                {form.password.length > 0 && (
                                    <div className="mt-3 grid grid-cols-2 gap-2 text-xs p-3 bg-neutral-900/50 rounded-lg border border-neutral-800 anim-slide">
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
                            <button type="button" onClick={save} disabled={isDemo} className="bg-gradient-brand hover:brightness-90 text-white px-6 py-3 rounded-lg font-bold mt-4 transition btn-press w-full disabled:opacity-40 disabled:pointer-events-none">Save</button>
                        </div>
                        </DemoProfileGeneralLock>
                    )}

                    {tab === '2fa' && (
                        <div className="space-y-6">
                            {isDemo ? (
                                <p className="text-neutral-400">Two-factor authentication cannot be changed in demo mode.</p>
                            ) : (<>
                            <div className="flex items-center justify-between">
                                <div>
                                    <h2 className="heading-section mb-2 flex items-center gap-2"><Shield className="text-neutral-400" /> Two-factor authentication</h2>
                                    <p className="text-neutral-400">Extra security for your account</p>
                                </div>
                                <div className={`px-4 py-2 rounded-lg font-bold ${twoFactorEnabled ? 'bg-green-500/20 text-green-400' : 'bg-neutral-800 text-neutral-400'}`}>
                                    {twoFactorEnabled ? 'Active' : 'Inactive'}
                                </div>
                            </div>

                            {twoFactorEnabled ? (
                                <div className="bg-neutral-800/50 rounded-lg p-6 border border-neutral-700">
                                    <div className="flex items-center justify-between mb-4">
                                        <div>
                                            <p className="text-white font-bold">2FA is enabled</p>
                                            <p className="text-neutral-400 text-sm">Backup codes remaining: {backupCodesRemaining}</p>
                                        </div>
                                        <button onClick={() => setShow2FADisable(true)} className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg font-bold transition btn-press">
                                            Disable
                                        </button>
                                    </div>
                                </div>
                            ) : (
                                <div className="bg-neutral-800/50 rounded-lg p-6 border border-neutral-700">
                                    <p className="text-neutral-300 mb-4">Enable two-factor authentication for extra security of your account.</p>
                                    <button onClick={handleSetup2FA} className="bg-primary hover:bg-primary-700 text-white px-6 py-3 rounded-lg font-bold transition btn-press">
                                        Set up 2FA
                                    </button>
                                </div>
                            )}
                            </>)}
                        </div>
                    )}

                    {tab === 'passkeys' && (
                        <div className="space-y-6">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h2 className="heading-section mb-2 flex items-center gap-2"><Shield className="text-neutral-400" /> Passkeys</h2>
                                    <p className="text-neutral-400">Log in without password</p>
                                </div>
                                {!isDemo && (
                                <button onClick={() => setShowPasskeyAdd(true)} className="bg-primary hover:bg-primary-700 text-white px-4 py-2 rounded-lg font-bold transition btn-press flex items-center gap-2">
                                    <Plus className="w-4 h-4" /> Add Passkey
                                </button>
                                )}
                            </div>

                            {passkeys.length === 0 ? (
                                <div className="bg-neutral-800/50 rounded-lg p-8 border border-neutral-700 text-center">
                                    <Shield className="w-16 h-16 text-neutral-600 mx-auto mb-4" />
                                    <p className="text-neutral-400">No passkeys configured</p>
                                </div>
                            ) : (
                                <div className="space-y-3">
                                    {passkeys.map(pk => (
                                        <div key={pk.id} className="bg-neutral-800/50 rounded-lg p-4 border border-neutral-700 flex items-center justify-between">
                                            <div>
                                                <p className="text-white font-bold">{pk.name}</p>
                                                <p className="text-neutral-400 text-sm">Added: {new Date(pk.created_at).toLocaleDateString(config.appLocale || 'en-GB')}</p>
                                            </div>
                                            {!isDemo && (
                                            <button onClick={() => handleDeletePasskey(pk.id)} className="text-red-400 hover:text-red-300 p-2 rounded-lg hover:bg-red-500/10 transition">
                                                <Trash2 className="w-5 h-5" />
                                            </button>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    )}

                    {tab === 'danger' && (
                        <div className="space-y-6">
                            <h2 className="text-2xl font-bold text-red-500 mb-4 flex items-center gap-2"><AlertCircle /> Danger Zone</h2>
                            {isDemo ? (
                                <p className="text-neutral-400">Account deletion is disabled in demo mode.</p>
                            ) : (
                            <div className="bg-red-500/10 rounded-lg p-6 border border-red-500/30">
                                <h3 className="text-white font-bold mb-2">Delete account</h3>
                                <p className="text-neutral-400 text-sm mb-4">
                                    This will permanently delete your account and all associated data. This action cannot be undone.
                                </p>
                                <button onClick={() => setShowDeleteAccount(true)} className="bg-red-600 hover:bg-red-700 text-white px-6 py-3 rounded-lg font-bold transition btn-press">
                                    Delete account
                                </button>
                            </div>
                            )}
                        </div>
                    )}
                </div>
            </div>

            {/* 2FA Setup Modal */}
            <AnimatePresence>
                {show2FASetup && (
                    <ModalPortal>
                        <motion.div
                            key="2fa-setup-modal"
                            initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            animate={{ opacity: 1, backdropFilter: "blur(4px)" }}
                            exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            className="fixed inset-0 bg-black/80 z-[9999] flex items-center justify-center p-4"
                            onClick={() => { setShow2FASetup(false); setTwoFactorSecret(''); setTwoFactorQR(''); }}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.95, opacity: 0 }}
                                className="bg-neutral-900 p-8 rounded-2xl border border-neutral-800 max-w-md w-full shadow-2xl"
                                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                            >
                                <h2 className="heading-section mb-4">Configure 2FA</h2>

                                {twoFactorBackupCodes.length === 0 ? (
                                    <>
                                        <p className="text-neutral-300 mb-4">Scan this QR code with your authenticator app:</p>

                                        {/* Witte achtergrond voor QR zorgt voor beter contrast */}
                                        <div className="bg-white p-2 rounded-lg mb-4 flex justify-center">
                                            {twoFactorQR && (twoFactorQR.startsWith('data:image/') || twoFactorQR.startsWith('https://')) ?
                                                <img src={twoFactorQR} className="rounded max-h-48" alt="2FA QR Code" />
                                                : null
                                            }
                                        </div>

                                        <div className="bg-black rounded-lg p-3 mb-4 border border-neutral-800">
                                            <p className="text-neutral-400 text-xs mb-1">Or enter manually:</p>
                                            <p className="text-white font-mono text-sm break-all select-all">{twoFactorSecret}</p>
                                        </div>

                                        <form onSubmit={handleEnable2FA}>
                                            <input
                                                type="text"
                                                className="input-field mb-4 text-center text-2xl tracking-widest"
                                                placeholder="000000"
                                                value={twoFactorCode}
                                                onChange={e => setTwoFactorCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                                maxLength={6}
                                                required
                                            />
                                            <div className="flex gap-3">
                                                <button type="button" onClick={() => { setShow2FASetup(false); setTwoFactorSecret(''); setTwoFactorQR(''); }} className="flex-1 bg-neutral-800 hover:bg-neutral-700 text-white p-3 rounded-lg font-bold transition btn-press border border-neutral-700">
                                                    Cancel
                                                </button>
                                                <button type="submit" className="flex-1 bg-primary hover:bg-primary-700 text-white p-3 rounded-lg font-bold transition btn-press shadow-[0_0_18px_rgba(20,184,166,0.35)]">
                                                    Activate
                                                </button>
                                            </div>
                                        </form>
                                    </>
                                ) : (
                                    <>
                                        <p className="text-green-400 mb-4 font-bold flex items-center gap-2">✓ 2FA successfully enabled!</p>

                                        <p className="text-neutral-300 text-sm mb-4">
                                            These are your backup codes. Keep them safe! You'll need them if you lose your phone.
                                        </p>

                                        {/* --- KNOPPEN VOOR ALLES --- */}
                                        <div className="flex gap-3 mb-4">
                                            <button
                                                onClick={handleDownloadCodes}
                                                className="flex-1 bg-neutral-800 hover:bg-neutral-700 text-white p-3 rounded-lg font-bold transition btn-press border border-neutral-700 flex items-center justify-center gap-2"
                                            >
                                                <Download className="w-4 h-4" /> Download .txt
                                            </button>
                                            <button
                                                onClick={handleCopyAllCodes}
                                                className="flex-1 bg-neutral-800 hover:bg-neutral-700 text-white p-3 rounded-lg font-bold transition btn-press border border-neutral-700 flex items-center justify-center gap-2"
                                            >
                                                <Copy className="w-4 h-4" /> Copy everything
                                            </button>
                                        </div>

                                        <div className="bg-black rounded-lg p-4 mb-4 space-y-2 max-h-60 overflow-y-auto border border-neutral-800">
                                            {twoFactorBackupCodes.map((code, i) => (
                                                <div key={i} className="flex items-center justify-center bg-neutral-900 p-2 rounded border border-neutral-800">
                                                    <code className="text-white font-mono text-lg tracking-widest">{code}</code>
                                                </div>
                                            ))}
                                        </div>

                                        <button onClick={() => { setShow2FASetup(false); setTwoFactorBackupCodes([]); setTwoFactorSecret(''); setTwoFactorQR(''); if (onComplete) onComplete(); }} className="w-full bg-primary hover:bg-primary-700 text-white p-3 rounded-lg font-bold transition btn-press">
                                            I saved them, Close
                                        </button>
                                    </>
                                )}
                            </motion.div>
                        </motion.div>
                    </ModalPortal>
                )}
            </AnimatePresence>

            {/* 2FA Disable Modal */}
            <AnimatePresence>
                {show2FADisable && (
                    <ModalPortal>
                        <motion.div
                            key="2fa-disable-modal"
                            initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            animate={{ opacity: 1, backdropFilter: "blur(4px)" }}
                            exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50"
                            onClick={() => setShow2FADisable(false)}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.95, opacity: 0 }}
                                className="bg-neutral-900 p-8 rounded-2xl border border-neutral-800 max-w-md w-full"
                                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                            >
                                <h2 className="heading-section mb-4">Disable 2FA</h2>
                                <p className="text-neutral-300 mb-4">Enter your password to disable 2FA:</p>
                                <form onSubmit={handleDisable2FA}>
                                    <input type="password" autoComplete="current-password" className="input-field mb-4" placeholder="Password" value={disable2FAPassword} onChange={e => setDisable2FAPassword(e.target.value)} required />
                                    <div className="flex gap-3">
                                        <button type="button" onClick={() => { setShow2FADisable(false); setDisable2FAPassword(''); }} className="flex-1 bg-neutral-800 hover:bg-neutral-700 text-white p-3 rounded-lg font-bold transition btn-press">
                                            Cancel
                                        </button>
                                        <button type="submit" className="flex-1 bg-red-600 hover:bg-red-700 text-white p-3 rounded-lg font-bold transition btn-press">
                                            Turn off
                                        </button>
                                    </div>
                                </form>
                            </motion.div>
                        </motion.div>
                    </ModalPortal>
                )}
            </AnimatePresence>

            {/* Passkey Add Modal */}
            <AnimatePresence>
                {showPasskeyAdd && (
                    <ModalPortal>
                        <motion.div
                            key="passkey-add-modal"
                            initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            animate={{ opacity: 1, backdropFilter: "blur(4px)" }}
                            exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50"
                            onClick={() => setShowPasskeyAdd(false)}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.95, opacity: 0 }}
                                className="bg-neutral-900 p-8 rounded-2xl border border-neutral-800 max-w-md w-full"
                                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                            >
                                <h2 className="heading-section mb-4">Add Passkey</h2>
                                <p className="text-neutral-300 mb-4">Give your passkey a recognizable name:</p>
                                <input type="text" className="input-field mb-4" placeholder="For example: iPhone, Windows Hello, YubiKey" value={passkeyName} onChange={e => setPasskeyName(e.target.value)} />
                                <div className="flex gap-3">
                                    <button onClick={() => { setShowPasskeyAdd(false); setPasskeyName(''); }} className="flex-1 bg-neutral-800 hover:bg-neutral-700 text-white p-3 rounded-lg font-bold transition btn-press">
                                        Cancel
                                    </button>
                                    <button onClick={handleRegisterPasskey} className="flex-1 bg-primary hover:bg-primary-700 text-white p-3 rounded-lg font-bold transition btn-press">
                                        Register
                                    </button>
                                </div>
                            </motion.div>
                        </motion.div>
                    </ModalPortal>
                )}
            </AnimatePresence>

            {/* Delete Account Modal */}
            {/* Delete Account Modal */}
            <AnimatePresence>
                {showDeleteAccount && (
                    <ModalPortal>
                        <motion.div
                            key="delete-account-modal"
                            initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            animate={{ opacity: 1, backdropFilter: "blur(4px)" }}
                            exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
                            className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50"
                            onClick={() => setShowDeleteAccount(false)}
                        >
                            <motion.div
                                initial={{ scale: 0.95, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.95, opacity: 0 }}
                                className="bg-neutral-900 p-8 rounded-2xl border border-red-500/50 max-w-md w-full"
                                onClick={(e: React.MouseEvent) => e.stopPropagation()}
                            >
                                <h2 className="text-2xl font-bold mb-4 text-red-500 flex items-center gap-2"><AlertCircle /> Delete Account</h2>
                                <p className="text-neutral-300 mb-4">This action <strong>cannot</strong> be undone. All your data will be permanently deleted.</p>
                                <form onSubmit={handleDeleteAccount}>
                                    <label className="label-form">Enter your password to confirm:</label>
                                    <input type="password" autoComplete="current-password" className="input-field mb-4 focus:border-red-500 focus-visible:ring-red-500/35" placeholder="Password" value={deletePassword} onChange={e => setDeletePassword(e.target.value)} required />
                                    <div className="flex gap-3">
                                        <button type="button" onClick={() => { setShowDeleteAccount(false); setDeletePassword(''); }} className="flex-1 bg-neutral-800 hover:bg-neutral-700 text-white p-3 rounded-lg font-bold transition btn-press">
                                            Cancel
                                        </button>
                                        <button type="submit" className="flex-1 bg-red-600 hover:bg-red-700 text-white p-3 rounded-lg font-bold transition btn-press">
                                            Delete permanently
                                        </button>
                                    </div>
                                </form>
                            </motion.div>
                        </motion.div>
                    </ModalPortal>
                )}
            </AnimatePresence>
        </div>
    );
};

