// Password Validation Function
function validatePassword(password) {
    if (!password || typeof password !== 'string') return { valid: false, error: "Password is required" };

    // Length check
    if (password.length < 8 || password.length > 64) {
        return { valid: false, error: "Password must be between 8 and 64 characters long" };
    }

    // Complexity check
    if (!/[A-Z]/.test(password)) return { valid: false, error: "Password must contain at least one uppercase letter" };
    if (!/[a-z]/.test(password)) return { valid: false, error: "Password must contain at least one lowercase letter" };
    if (!/[0-9]/.test(password)) return { valid: false, error: "Password must contain at least one number" };
    if (!/[\W_]/.test(password)) return { valid: false, error: "Password must contain at least one special character" };

    return { valid: true };
}

// Export the function so it can be reused in other files
module.exports = { validatePassword };