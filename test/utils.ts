export function toKey(s: string) {
    return s.trim().replace(/\s/g, '').replace(/[^a-zA-Z0-9]/g, '_')
}