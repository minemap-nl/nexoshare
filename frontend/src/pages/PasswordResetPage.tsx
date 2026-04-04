import React, { useState, useEffect } from 'react';
import { Check } from 'lucide-react';
import { API_URL } from '../api/constants';
import { useUI } from '../context/UIContext';
import { GlobalStyles } from '../components/layout/GlobalStyles';


export function PasswordResetPage() {
    const [token, setToken] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [success, setSuccess] = useState(false);
    const { notify } = useUI();

    useEffect(() => {
        const params = new URLSearchParams(window.location.search);
        const t = params.get('token');
        if (t) {
            setToken(t);
            // Verify token
            fetch(`${API_URL}/auth/password-reset/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: t })
            }).then(res => {
                if (!res.ok) {
                    notify('Invalid or expired reset link', 'error');
                }
            });
        } else {
            notify('No reset token found', 'error');
        }
    }, []);

    const handleSubmit = async (e: any) => {
        e.preventDefault();

        if (newPassword !== confirmPassword) {
            notify('Passwords do not match', 'error');
            return;
        }

        if (newPassword.length < 8) {
            notify('Password must be at least 8 characters', 'error');
            return;
        }

        if (!/[a-z]/.test(newPassword) || !/[A-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
            notify('Password must contain at least 1 lowercase letter, 1 uppercase letter and 1 number', 'error');
            return;
        }

        const res = await fetch(`${API_URL}/auth/password-reset/complete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, password: newPassword })
        });

        const data = await res.json();

        if (res.ok) {
            setSuccess(true);
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
        } else {
            notify(data.error || 'Reset failed', 'error');
        }
    };

    if (success) {
        return (
            <div className="min-h-screen bg-app flex items-center justify-center p-4">
                <div className="bg-neutral-900 p-8 rounded-2xl border border-neutral-800 max-w-md w-full text-center">
                    <div className="bg-green-500/20 text-green-400 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                        <Check className="w-8 h-8" />
                    </div>
                    <h2 className="heading-section mb-2">Password reset!</h2>
                    <p className="text-neutral-400">You will be redirected to the login page...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-app flex items-center justify-center p-4">
            <GlobalStyles />
            <form onSubmit={handleSubmit} className="bg-neutral-900 p-8 rounded-2xl border border-neutral-800 max-w-md w-full">
                <h2 className="heading-section mb-6 text-center">Set New Password</h2>
                <div className="space-y-4">
                    <div>
                        <label className="label-form">New Password</label>
                        <input type="password" className="input-field" placeholder="At least 8 characters" value={newPassword} onChange={e => setNewPassword(e.target.value)} required />
                    </div>
                    <div>
                        <label className="label-form">Confirm Password</label>
                        <input type="password" className="input-field" placeholder="Repeat Password" value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} required />
                    </div>
                    <button type="submit" className="w-full bg-primary hover:bg-primary-700 text-white p-3 rounded-lg font-bold transition btn-press">
                        Reset Password
                    </button>
                </div>
            </form>
        </div>
    );
};
