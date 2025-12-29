import { useEffect } from 'react';

export const useEscapeKey = (handler: () => void, condition: boolean = true) => {
    useEffect(() => {
        if (!condition) return;

        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.key === 'Escape') {
                e.preventDefault();
                e.stopPropagation();
                handler();
            }
        };

        window.addEventListener('keydown', handleKeyDown, { capture: true });
        return () => window.removeEventListener('keydown', handleKeyDown, { capture: true });
    }, [condition, handler]);
};
