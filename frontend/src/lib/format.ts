export const formatBytes = (b: any) => {
    if (!b) return '0 B';
    const k = 1024,
        sizes = ['B', 'KB', 'MB', 'GB', 'TB'],
        i = Math.floor(Math.log(b) / Math.log(k));
    return parseFloat((b / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

export const UNITS = ['Minutes', 'Hours', 'Days', 'Weeks', 'Months', 'Years'];

export const getUnitLabel = (val: number, unit: string) => {
    const map: Record<string, [string, string]> = {
        Minutes: ['Minute', 'Minutes'],
        Hours: ['Hour', 'Hours'],
        Days: ['Day', 'Days'],
        Weeks: ['Week', 'Weeks'],
        Months: ['Month', 'Months'],
        Years: ['Year', 'Years'],
    };
    if (!map[unit]) return unit;
    return val === 1 ? map[unit][0] : map[unit][1];
};

export const getFutureDate = (val: number, unit: string, locale: string = 'en-GB') => {
    if (!val || val <= 0) return 'Never expires';

    const k: Record<string, number> = {
        Minutes: 60000,
        Hours: 3600000,
        Days: 86400000,
        Weeks: 604800000,
        Months: 2592000000,
        Years: 31536000000,
    };

    const ms = val * (k[unit] || 86400000);
    const date = new Date(Date.now() + ms);
    return date.toLocaleString(locale, { dateStyle: 'full', timeStyle: 'short' });
};
