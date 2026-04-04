import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AppConfigProvider } from './context/AppConfigContext';
import { UIProvider } from './context/UIContext';
import { DemoBanner } from './components/layout/DemoBanner';
import { useAuth } from './hooks/useAuth';
import { Dashboard } from './pages/Dashboard';
import { DownloadPage } from './pages/DownloadPage';
import { GuestUploadPage } from './pages/GuestUploadPage';
import { LoginPage } from './pages/LoginPage';
import { PasswordResetPage } from './pages/PasswordResetPage';

function App() {
    const { user, token, login, logout, loading } = useAuth();
    if (loading) return <div className="bg-black min-h-screen" />;

    return (
        <BrowserRouter>
            <AppConfigProvider>
                <UIProvider>
                    <DemoBanner />
                    <Routes>
                        <Route path="/s/:id" element={<DownloadPage />} />
                        <Route path="/r/:id" element={<GuestUploadPage />} />
                        <Route path="/login" element={!user ? <LoginPage onLogin={login} /> : <Navigate to="/" />} />
                        <Route path="/reset-password" element={<PasswordResetPage />} />
                        <Route path="/*" element={user ? <Dashboard token={token} logout={logout} /> : <Navigate to="/login" />} />
                    </Routes>
                </UIProvider>
            </AppConfigProvider>
        </BrowserRouter>
    );
}

export default App;
