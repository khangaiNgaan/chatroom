// Verify Email Template
export const getVerifyEmailHtml = (username: string, verifyLink: string) => `
<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
    <h2>Verify your email</h2>
    <p>Hi ${username},</p>
    <p>Please click the link below to verify your email address for your coffeeroom account.</p>
    <p><a href="${verifyLink}" style="padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
    <p>Or copy this link: ${verifyLink}</p>
    <p>This link will expire in 24 hours.</p>
    <p>If you didn't request this change, please ignore this email.</p>
    <p>Support: <a href="mailto:support@caffeine.ink">support@caffeine.ink</a></p>
</div>
`

// Welcome & Verify (Signup) Template
export const getWelcomeEmailHtml = (username: string, verifyLink: string) => `
<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
    <h2>Welcome to coffeeroom!</h2>
    <p>Hi ${username},</p>
    <p>You have successfully registered using an invite code.</p>
    <p>Please verify your email address to secure your account.</p>
    <p><a href="${verifyLink}" style="padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
    <p>Or copy this link: ${verifyLink}</p>
    <p>This link will expire in 24 hours.</p>
    <p>If you didn't sign up for coffeeroom, please ignore this email.</p>
    <p>Support: <a href="mailto:support@caffeine.ink">support@caffeine.ink</a></p>
</div>
`

// Verify Registration (Pending) Template
export const getVerifyRegistrationHtml = (username: string, verifyLink: string) => `
<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
    <h2>Welcome to coffeeroom!</h2>
    <p>Hi ${username},</p>
    <p>Please click the link below to verify your email and complete your registration.</p>
    <p><a href="${verifyLink}" style="padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Verify and Sign Up</a></p>
    <p>Or copy this link: ${verifyLink}</p>
    <p>This link will expire in 24 hours.</p>
    <p>If you didn't sign up for coffeeroom, please ignore this email.</p>
    <p>Support: <a href="mailto:support@caffeine.ink">support@caffeine.ink</a></p>
</div>
`

// Reset Password Email Template
export const getResetPasswordEmailHtml = (username: string, resetLink: string) => `
<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
    <h2>Reset your password</h2>
    <p>Hi ${username},</p>
    <p>We received a request to reset your password. If you didn't make this request, just ignore this email.</p>
    <p><a href="${resetLink}" style="padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
    <p>Or copy this link: ${resetLink}</p>
    <p>This link will expire in 15 minutes.</p>
    <p>If you didn't request a password reset, please ignore this email.</p>
    <p>Support: <a href="mailto:support@caffeine.ink">support@caffeine.ink</a></p>
</div>
`
