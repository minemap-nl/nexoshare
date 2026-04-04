import { useEffect } from 'react';
import { useUI } from '../context/UIContext';

export function useTokenExpiration(token: string | null, logout: () => void) {
    const { notify } = useUI();

    useEffect(() => {
        if (!token) return;

        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            const exp = payload.exp * 1000;
            const now = Date.now();
            const timeUntilExpiry = exp - now;

            if (timeUntilExpiry <= 0) {
                logout();
                notify('Session expired. Login again.', 'info');
                return;
            }

            const warningTime = Math.max(0, timeUntilExpiry - 60000);
            const timeoutIds: ReturnType<typeof setTimeout>[] = [];
            const warningTimeout = setTimeout(() => {
                notify('Your session is about to expire. Save your work!', 'info');
                timeoutIds.push(
                    setTimeout(() => {
                        logout();
                        notify('Session expired. Login again.', 'info');
                    }, 60000)
                );
            }, warningTime);
            timeoutIds.push(warningTimeout);

            return () => {
                for (const id of timeoutIds) clearTimeout(id);
            };
        } catch (e) {
            console.error('Token parse error:', e);
            logout();
        }
    }, [token, logout, notify]);
}
