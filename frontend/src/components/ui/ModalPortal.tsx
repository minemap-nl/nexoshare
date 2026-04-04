import { createPortal } from 'react-dom';
import type { ReactNode } from 'react';

export function ModalPortal({ children }: { children: ReactNode }) {
    return createPortal(children, document.body);
}
