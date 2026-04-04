import type { UploadItem, FileSystemHandle, FileSystemFileHandle, FileSystemDirectoryHandle } from '../types/upload';
import { generateUUID } from './uploadCrypto';

export const traverseFileTree = async (item: any, path = ''): Promise<UploadItem[]> => {
    return new Promise((resolve) => {
        if (item.isFile) {
            item.file((file: File) => {
                const fullPath = path + file.name;
                resolve([{
                    file,
                    path: fullPath,
                    name: file.name,
                    id: generateUUID(),
                    isDirectory: false,
                    size: file.size,
                }]);
            });
        } else if (item.isDirectory) {
            const dirFullPath = path + item.name;
            const dirItem: UploadItem = {
                file: null,
                path: dirFullPath,
                name: item.name,
                id: generateUUID(),
                isDirectory: true,
                size: 0,
            };

            const dirReader = item.createReader();
            const entries: any[] = [];

            const readEntries = () => {
                dirReader.readEntries(async (batch: any[]) => {
                    if (batch.length > 0) {
                        entries.push(...batch);
                        readEntries();
                    } else {
                        const promises = entries.map((entry: any) => traverseFileTree(entry, path + item.name + '/'));
                        const results = await Promise.all(promises);
                        resolve([dirItem, ...results.flat()]);
                    }
                });
            };
            readEntries();
        } else {
            resolve([]);
        }
    });
};

export const processHandle = async (handle: FileSystemHandle, path = ''): Promise<UploadItem[]> => {
    if (handle.kind === 'file') {
        const fileHandle = handle as FileSystemFileHandle;
        const file = await fileHandle.getFile();
        const fullPath = path + file.name;
        return [{
            file,
            path: fullPath,
            name: file.name,
            id: generateUUID(),
            isDirectory: false,
            size: file.size,
        }];
    }
    if (handle.kind === 'directory') {
        const dirHandle = handle as FileSystemDirectoryHandle;
        const dirFullPath = path + handle.name;

        const dirItem: UploadItem = {
            file: null,
            path: dirFullPath,
            name: handle.name,
            id: generateUUID(),
            isDirectory: true,
            size: 0,
        };

        const results: UploadItem[] = [dirItem];

        for await (const entry of dirHandle.values()) {
            const children = await processHandle(entry, path + handle.name + '/');
            results.push(...children);
        }

        return results;
    }
    return [];
};
