import { Bindings } from '../types'

export async function sendEmail(env: Bindings, to: string, subject: string, htmlContent: string): Promise<boolean> {
    const apiKey = env.RESEND_API_KEY

    if (!apiKey) {
        console.error('Missing RESEND_API_KEY')
        return false
    }

    try {
        const res = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                from: 'coffeeroom <noreply@caffeine.ink>',
                to: [to],
                subject: subject,
                html: htmlContent
            })
        })

        if (!res.ok) {
            const err = await res.text()
            console.error('Email send failed:', err)
            return false
        }

        return true
    } catch (e) {
        console.error('Email fetch error:', e)
        return false
    }
}
