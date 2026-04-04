import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { API_URL } from '../api/constants';
import { CONFIG_CHANGED_EVENT } from '../lib';

export type AppConfigContextType = {
    config: any;
    refreshConfig: () => Promise<void>;
    loading: boolean;
};

const AppConfigContext = createContext<AppConfigContextType | null>(null);

export function AppConfigProvider({ children }: { children: React.ReactNode }) {
    const [config, setConfig] = useState<any>({});
    const [loading, setLoading] = useState(true);

    const refreshConfig = useCallback(async () => {
        try {
            const r = await fetch(`${API_URL}/config`, { credentials: 'include' });
            if (r.ok) setConfig(await r.json());
        } catch (e) {
            console.error(e);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        void refreshConfig();
    }, [refreshConfig]);

    useEffect(() => {
        const onCfg = () => {
            void refreshConfig();
        };
        window.addEventListener(CONFIG_CHANGED_EVENT, onCfg);
        const onVis = () => {
            if (document.visibilityState === 'visible') void refreshConfig();
        };
        document.addEventListener('visibilitychange', onVis);
        return () => {
            window.removeEventListener(CONFIG_CHANGED_EVENT, onCfg);
            document.removeEventListener('visibilitychange', onVis);
        };
    }, [refreshConfig]);

    useEffect(() => {
        const url = config?.faviconUrl;
        if (!url || typeof url !== 'string') return;
        let link = document.querySelector("link[rel~='icon']") as HTMLLinkElement;
        if (!link) {
            link = document.createElement('link');
            link.rel = 'icon';
            document.getElementsByTagName('head')[0].appendChild(link);
        }
        link.href = url;
    }, [config?.faviconUrl]);

    return (
        <AppConfigContext.Provider value={{ config, refreshConfig, loading }}>
            {children}
        </AppConfigContext.Provider>
    );
}

export function useAppConfig() {
    const ctx = useContext(AppConfigContext);
    if (!ctx) throw new Error('useAppConfig must be used within AppConfigProvider');
    return ctx;
}
