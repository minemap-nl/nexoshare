export type ToastType = 'success' | 'error' | 'info';

export interface Toast {
    id: number;
    message: string;
    type: ToastType;
}

export interface UIContextType {
    notify: (msg: string, type?: ToastType) => void;
    confirm: (msg: string, onConfirm: () => void) => void;
    preview: (file: File | Blob | string, name: string, type?: string) => void;
    isConfirming: boolean;
    isPreviewing: boolean;
}
