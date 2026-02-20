export async function sha256(message: string): Promise<string> {
    const msgBuffer = new TextEncoder().encode(message)
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')
}

export async function encrypt(text: string, keyString: string): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const encoded = new TextEncoder().encode(text)

    // Derive a 32-byte key from the input string using SHA-256
    const keyBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(keyString))

    const key = await crypto.subtle.importKey(
        'raw',
        keyBuffer,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    )

    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        encoded
    )

    // Return IV:CipherText (Hex encoded)
    const ivHex = Array.from(iv).map((b) => b.toString(16).padStart(2, '0')).join('')
    const cipherHex = Array.from(new Uint8Array(ciphertext)).map((b) => b.toString(16).padStart(2, '0')).join('')
    return `${ivHex}:${cipherHex}`
}

export async function decrypt(text: string, keyString: string): Promise<string> {
    const [ivHex, cipherHex] = text.split(':')
    if (!ivHex || !cipherHex) throw new Error('Invalid cipher format')

    const ivMatch = ivHex.match(/.{1,2}/g)
    const cipherMatch = cipherHex.match(/.{1,2}/g)

    if (!ivMatch || !cipherMatch) throw new Error('Invalid hex string')

    const iv = new Uint8Array(ivMatch.map((byte) => parseInt(byte, 16)))
    const ciphertext = new Uint8Array(cipherMatch.map((byte) => parseInt(byte, 16)))

    const keyBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(keyString))
    const key = await crypto.subtle.importKey(
        'raw',
        keyBuffer,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    )

    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        ciphertext
    )

    return new TextDecoder().decode(decrypted)
}

export async function verifyTurnstile(token: string, secretKey: string, ip?: string): Promise<{ success: boolean }> {
    const formData = new FormData()
    formData.append('secret', secretKey)
    formData.append('response', token)
    if (ip) formData.append('remoteip', ip)

    const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        body: formData,
        method: 'POST',
    })

    return await result.json() as { success: boolean }
}
