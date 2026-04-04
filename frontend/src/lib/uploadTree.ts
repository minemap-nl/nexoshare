import type { UploadItem } from '../types/upload';
import { generateUUID } from './uploadCrypto';

export function sortFiles(items: UploadItem[]): UploadItem[] {
    return items.sort((a, b) => a.path.localeCompare(b.path));
}

export function synthesizeDirectoryItems(items: UploadItem[]): UploadItem[] {
    const existingPaths = new Set(items.map(i => i.path));
    const foldersToAdd = new Map<string, UploadItem>();

    items.forEach(item => {
        const parts = item.path.split('/');
        let currentPath = '';
        for (let i = 0; i < parts.length - 1; i++) {
            const part = parts[i];
            currentPath = currentPath ? `${currentPath}/${part}` : part;

            if (!existingPaths.has(currentPath) && !foldersToAdd.has(currentPath)) {
                foldersToAdd.set(currentPath, {
                    file: null,
                    path: currentPath,
                    name: part,
                    id: generateUUID(),
                    isDirectory: true,
                    size: 0,
                });
            }
        }
    });

    return [...foldersToAdd.values(), ...items];
}
