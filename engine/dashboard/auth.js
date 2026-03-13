/**
 * Cyber-Cipher Authentication Module
 * Simple session management - persists until explicit logout
 */

// Default credentials
const DEFAULT_USER = 'admin';
const DEFAULT_PASS_HASH = '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918';

let failedAttempts = 0;
let lockoutUntil = 0;

async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function isAuthenticated() {
    return sessionStorage.getItem('cybercipher_auth') === 'true';
}

async function login(username, password) {
    if (Date.now() < lockoutUntil) {
        return { success: false, message: `Locked out. Try again in ${Math.ceil((lockoutUntil - Date.now())/1000)}s` };
    }

    const passHash = await hashPassword(password);
    
    if (username === DEFAULT_USER && passHash === DEFAULT_PASS_HASH) {
        // Success - set sessionStorage (persists across refresh, clears when tab closes)
        sessionStorage.setItem('cybercipher_auth', 'true');
        failedAttempts = 0;
        return { success: true, message: 'Login successful' };
    } else {
        failedAttempts++;
        if (failedAttempts >= 3) {
            lockoutUntil = Date.now() + 30000;
            failedAttempts = 0;
            return { success: false, message: 'Locked out for 30 seconds' };
        }
        return { success: false, message: `Invalid credentials. ${3 - failedAttempts} attempts left` };
    }
}

function logout() {
    sessionStorage.removeItem('cybercipher_auth');
    window.location.href = 'login.html';
}

function requireAuth() {
    if (sessionStorage.getItem('cybercipher_auth') !== 'true') {
        window.location.href = 'login.html';
        return false;
    }
    return true;
}

window.CyberCipherAuth = { login, logout, isAuthenticated, requireAuth };
