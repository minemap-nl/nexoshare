/**
 * Slices src/App.tsx into src/pages/*.tsx. Run: node scripts/build-pages-from-app.mjs
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const appPath = path.join(__dirname, '../src/App.tsx');
const pagesDir = path.join(__dirname, '../src/pages');
const lines = fs.readFileSync(appPath, 'utf8').split(/\r?\n/);

function slice(start, end) {
    return lines.slice(start - 1, end).join('\n');
}

function constToExport(code, name) {
    const prefix = `const ${name} = `;
    if (!code.startsWith(prefix)) {
        throw new Error(`Expected to start with "${prefix}", got: ${code.slice(0, 80)}`);
    }
    const rest = code.slice(prefix.length);
    const marker = ') => {';
    const idx = rest.indexOf(marker);
    if (idx === -1) throw new Error(`No "${marker}" for ${name}`);
    const sig = rest.slice(0, idx + 1).trim();
    const bodyWithBrace = rest.slice(idx + 5);
    return `export function ${name}${sig} ${bodyWithBrace}`;
}

const HEADER_FULL = `import React, { useState, useEffect, useRef, useCallback } from 'react';
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
`;

const HEADER_DASHBOARD = `import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
    Download, Upload, Share2, Settings,
    LogOut, User,
    Loader2,
} from 'lucide-react';
import { API_URL } from '../api/constants';
import { isValidHttpUrl } from '../lib';
import { useAppConfig } from '../context/AppConfigContext';
import { useUI } from '../context/UIContext';
import { useAuth } from '../hooks/useAuth';
import { useTokenExpiration } from '../hooks/useTokenExpiration';
import { GlobalStyles } from '../components/layout/GlobalStyles';
import { Footer } from '../components/layout/Footer';
import { ProfileView } from './ProfileView';
import { UploadView } from './UploadView';
import { MySharesView } from './MySharesView';
import { ReverseView } from './ReverseView';
import { ConfigTabs } from './ConfigTabs';
import { SetupWizard } from './SetupWizard';
`;

const HEADER_LOGIN = `import React, { useState, useEffect } from 'react';
import { Share2, Shield, Loader2 } from 'lucide-react';
import { startAuthentication } from '@simplewebauthn/browser';
import { API_URL } from '../api/constants';
import { isValidHttpUrl } from '../lib';
import { useAppConfig } from '../context/AppConfigContext';
import { useUI } from '../context/UIContext';
import { GlobalStyles } from '../components/layout/GlobalStyles';
import { Footer } from '../components/layout/Footer';
`;

const HEADER_GUEST = `import React, { useState, useEffect, useRef } from 'react';
import { useParams } from 'react-router-dom';
import {
    Download, File as FileIcon, Folder as FolderIcon, X, Check,
    Loader2, FileQuestion, CloudUpload, Eye, XCircle,
} from 'lucide-react';
import axios from 'axios';
import { API_URL } from '../api/constants';
import {
    computeChunkHash,
    getBackoffDelay,
    generateUUID,
    sortFiles,
    synthesizeDirectoryItems,
    traverseFileTree,
    processHandle,
} from '../lib';
import type { UploadItem } from '../types/upload';
import { useAppConfig } from '../context/AppConfigContext';
import { useUI } from '../context/UIContext';
import { GlobalStyles } from '../components/layout/GlobalStyles';
import { Footer } from '../components/layout/Footer';
`;

const HEADER_PW_RESET = `import React, { useState, useEffect } from 'react';
import { Check } from 'lucide-react';
import { API_URL } from '../api/constants';
import { useUI } from '../context/UIContext';
import { GlobalStyles } from '../components/layout/GlobalStyles';
`;

const HEADER_DOWNLOAD = `import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { Download, FileQuestion, Loader2, Eye, Folder as FolderIcon } from 'lucide-react';
import DOMPurify from 'dompurify';
import { API_URL } from '../api/constants';
import { sortFiles, synthesizeDirectoryItems } from '../lib';
import type { UploadItem } from '../types/upload';
import { useUI } from '../context/UIContext';
import { GlobalStyles } from '../components/layout/GlobalStyles';
import { Footer } from '../components/layout/Footer';
`;

const HEADER_SETUP = `import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Sparkles, Shield, ArrowRight, Check, Loader2 } from 'lucide-react';
import { API_URL } from '../api/constants';
import { useUI } from '../context/UIContext';
import { ModalPortal } from '../components/ui/ModalPortal';
import { Checkbox } from '../components/ui/Checkbox';
`;

const jobs = [
    { name: 'ProfileView', start: 59, end: 745, header: HEADER_FULL },
    { name: 'UploadView', start: 746, end: 1569, header: HEADER_FULL, isUploadView: true },
    { name: 'MySharesView', start: 1570, end: 2206, header: HEADER_FULL },
    { name: 'ReverseView', start: 2207, end: 2597, header: HEADER_FULL },
    { name: 'ConfigTabs', start: 2598, end: 3386, header: HEADER_FULL },
    { name: 'SetupWizard', start: 3389, end: 3628, header: HEADER_SETUP },
    { name: 'Dashboard', start: 3630, end: 3857, header: HEADER_DASHBOARD },
    { name: 'LoginPage', start: 3859, end: 4164, header: HEADER_LOGIN },
    { name: 'GuestUploadPage', start: 4166, end: 4564, header: HEADER_GUEST },
    { name: 'PasswordResetPage', start: 4566, end: 4664, header: HEADER_PW_RESET },
    { name: 'DownloadPage', start: 4666, end: 4844, header: HEADER_DOWNLOAD },
];

for (const job of jobs) {
    let body = slice(job.start, job.end);
    if (job.isUploadView) {
        body = body.replace(/^type UploadViewProps/m, 'export type UploadViewProps');
        const idx = body.indexOf('const UploadView = ');
        if (idx === -1) throw new Error('UploadView slice missing const UploadView');
        const typePart = body.slice(0, idx).trimEnd();
        const compPart = body.slice(idx).trimStart();
        body = `${typePart}\n\n${constToExport(compPart, 'UploadView')}`;
    } else {
        body = constToExport(body, job.name);
    }

    const out = `${job.header}\n\n${body}\n`;
    fs.mkdirSync(pagesDir, { recursive: true });
    fs.writeFileSync(path.join(pagesDir, `${job.name}.tsx`), out, 'utf8');
    console.log('Wrote', job.name);
}
