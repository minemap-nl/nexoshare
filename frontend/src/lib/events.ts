/** Wordt getriggerd na upload-flow die de shares-lijst beïnvloedt (finalize, cancel, fout). My Shares luistert mee. */
export const SHARES_LIST_CHANGED_EVENT = 'famretera-shares-changed';
export const dispatchSharesListChanged = () => {
    window.dispatchEvent(new CustomEvent(SHARES_LIST_CHANGED_EVENT));
};

/** Welk share-id krijgt momenteel chunked upload vanuit UploadView (null = geen). My Shares gebruikt dit om link-wijziging te blokkeren. */
export const ACTIVE_UPLOAD_SHARE_EVENT = 'famretera-active-upload-share';
export const dispatchActiveUploadShare = (shareId: string | null) => {
    window.dispatchEvent(new CustomEvent(ACTIVE_UPLOAD_SHARE_EVENT, { detail: { shareId } }));
};

/** Na PUT /config, branding, enz.: alle schermen die `useAppConfig()` gebruiken verversen mee. */
export const CONFIG_CHANGED_EVENT = 'famretera-config-changed';
export function dispatchConfigChanged() {
    window.dispatchEvent(new CustomEvent(CONFIG_CHANGED_EVENT));
}
