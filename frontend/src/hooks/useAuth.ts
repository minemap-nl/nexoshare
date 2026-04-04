import { useCallback, useEffect, useState } from 'react';
import { API_URL } from '../api/constants';

export function useAuth() {
    const [user, setUser] = useState<any>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        try {
            const storedUser = localStorage.getItem('user');

            if (storedUser && storedUser !== 'undefined' && storedUser !== 'null') {
                setUser(JSON.parse(storedUser));
            } else {
                localStorage.removeItem('user');
            }
        } catch (e) {
            console.error('User parse error', e);
            localStorage.removeItem('user');
        }
        setLoading(false);
    }, []);

    const login = useCallback((u: any) => {
        localStorage.setItem('user', JSON.stringify(u));
        setUser(u);
    }, []);

    const logout = useCallback(async () => {
        try {
            await fetch(`${API_URL}/auth/logout`, { method: 'POST', credentials: 'include' });
        } catch (e) {
            console.error('Logout request failed', e);
        }

        localStorage.clear();
        setUser(null);
        window.location.href = '/login';
    }, []);

    return { user, token: null, login, logout, loading };
}
