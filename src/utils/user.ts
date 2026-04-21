import { Bindings } from '../types'

export async function generateNextUid(env: Bindings): Promise<string> {
    const prefix = '02'
    
    // find maximum UID with prefix
    const lastUser = await env.DB.prepare('SELECT uid FROM users WHERE uid LIKE ? ORDER BY uid DESC LIMIT 1')
        .bind(`${prefix}%`)
        .first<{ uid: string }>()

    if (lastUser && lastUser.uid) {
        const lastNum = parseInt(lastUser.uid.substring(2))
        return prefix + String(lastNum + 1).padStart(3, '0')
    } else {
        return prefix + '001'
    }
}
