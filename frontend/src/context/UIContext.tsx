import React, { createContext, useCallback, useContext, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { X, Check, AlertTriangle, Info } from 'lucide-react';
import FilePreviewModal from '../components/preview/FilePreviewModal';
import { useEscapeKey } from '../hooks/useEscapeKey';
import type { Toast, ToastType, UIContextType } from '../types/ui';

const UIContext = createContext<UIContextType | null>(null);

export function UIProvider({ children }: { children: React.ReactNode }) {
    const [toasts, setToasts] = useState<Toast[]>([]);
    const [confirmMessage, setConfirmMessage] = useState<string | null>(null);
    const [confirmCallback, setConfirmCallback] = useState<(() => void) | null>(null);

    const [previewFile, setPreviewFile] = useState<File | Blob | string | null>(null);
    const [previewName, setPreviewName] = useState<string>('');
    const [previewType, setPreviewType] = useState<string | undefined>(undefined);

    const notify = (message: string, type: ToastType = 'info') => {
        const id = Date.now();
        setToasts(prev => [...prev, { id, message, type }]);
        setTimeout(() => removeToast(id), 5000);
    };

    const removeToast = (id: number) => setToasts(prev => prev.filter(t => t.id !== id));

    const confirm = (msg: string, onConfirm: () => void) => {
        setConfirmMessage(msg);
        setConfirmCallback(() => onConfirm);
    };

    const handleConfirm = () => {
        if (confirmCallback) confirmCallback();
        setConfirmMessage(null);
        setConfirmCallback(null);
    };

    const preview = useCallback((file: File | Blob | string, name: string, type?: string) => {
        setPreviewFile(file);
        setPreviewName(name);
        setPreviewType(type);
    }, []);

    const closePreview = useCallback(() => {
        setPreviewFile(null);
        setPreviewName('');
        setPreviewType(undefined);
    }, []);

    const cancelConfirm = () => {
        setConfirmMessage(null);
        setConfirmCallback(null);
    };

    useEscapeKey(cancelConfirm, !!confirmMessage);

    return (
        <UIContext.Provider value={{ notify, confirm, preview, isConfirming: !!confirmMessage, isPreviewing: !!previewFile }}>
            {children}
            <div className="fixed bottom-4 right-4 z-[10003] flex flex-col gap-2">
                {toasts.map(toast => (
                    <div key={toast.id} className={`p-4 rounded-xl shadow-lg text-white font-medium flex items-center gap-3 anim-slide ${toast.type === 'error' ? 'bg-red-500' :
                        toast.type === 'success' ? 'bg-green-500' :
                            'bg-neutral-800 border border-neutral-700'
                        }`}>
                        {toast.type === 'error' ? <AlertTriangle className="w-5 h-5" /> :
                            toast.type === 'success' ? <Check className="w-5 h-5" /> :
                                <Info className="w-5 h-5 text-primary-300" />}
                        {toast.message}
                        <button type="button" onClick={() => removeToast(toast.id)} className="ml-2 hover:bg-black/20 p-1 rounded"><X className="w-3 h-3" /></button>
                    </div>
                ))}
            </div>

            <AnimatePresence>
                {confirmMessage && (
                    <motion.div
                        key="confirm-modal"
                        initial={{ opacity: 0, backdropFilter: 'blur(0px)' }}
                        animate={{ opacity: 1, backdropFilter: 'blur(4px)' }}
                        exit={{ opacity: 0, backdropFilter: 'blur(0px)' }}
                        className="fixed inset-0 z-[10002] flex items-center justify-center p-4 bg-black/60"
                        onClick={cancelConfirm}
                    >
                        <motion.div
                            initial={{ scale: 0.95, opacity: 0 }}
                            animate={{ scale: 1, opacity: 1 }}
                            exit={{ scale: 0.95, opacity: 0 }}
                            onClick={(e: React.MouseEvent) => e.stopPropagation()}
                            className="bg-neutral-900 border border-neutral-800 p-6 rounded-2xl shadow-2xl max-w-sm w-full"
                        >
                            <h3 className="heading-panel mb-2">Confirm</h3>
                            <p className="text-neutral-400 mb-6">{confirmMessage}</p>
                            <div className="flex gap-3">
                                <button type="button" onClick={() => setConfirmMessage(null)} className="flex-1 bg-neutral-800 hover:bg-neutral-700 text-white p-2 rounded-lg font-bold transition">Cancel</button>
                                <button type="button" onClick={handleConfirm} className="flex-1 bg-red-600 hover:bg-red-700 text-white p-2 rounded-lg font-bold transition shadow-lg shadow-red-900/20">Confirm</button>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>

            <AnimatePresence>
                {previewFile && (
                    <FilePreviewModal
                        file={previewFile}
                        name={previewName}
                        type={previewType}
                        onClose={closePreview}
                    />
                )}
            </AnimatePresence>
        </UIContext.Provider>
    );
}

export function useUI() {
    const context = useContext(UIContext);
    if (!context) throw new Error('useUI must be used within UIProvider');
    return context;
}
