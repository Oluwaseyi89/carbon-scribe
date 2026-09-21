/**
 * Secure Token Storage
 * 
 * Uses HTTP-only cookies for refresh tokens (secure against XSS)
 * and localStorage for access tokens (with auto-refresh logic)
 * 
 * Note: For production, consider using HTTP-only cookies for both tokens
 * with server-side token management.
 */

import { reportError } from '@/lib/telemetry/errorReporter';
import { isClient, safeGetItem, safeSetItem, safeRemoveItem } from '@/lib/utils/hydration';

const ACCESS_TOKEN_KEY = 'cs_access_token';
const REFRESH_TOKEN_KEY = 'cs_refresh_token';
const USER_KEY = 'cs_user';
const TOKEN_EXPIRY_KEY = 'cs_token_expiry';

export interface TokenData {
  accessToken: string;
  refreshToken: string;
  expiresAt: number; // Timestamp when access token expires
}

/**
 * Store authentication tokens securely
 */
export function storeTokens(accessToken: string, refreshToken: string, expiresIn: number = 900): void {
  if (!isClient()) return;

  const expiresAt = Date.now() + expiresIn * 1000;
  
  try {
    safeSetItem(ACCESS_TOKEN_KEY, accessToken);
    safeSetItem(REFRESH_TOKEN_KEY, refreshToken);
    safeSetItem(TOKEN_EXPIRY_KEY, expiresAt.toString());
  } catch (error) {
    reportError(error, 'token-storage', 'warning', { operation: 'storeTokens' });
  }
}

/**
 * Get the stored access token
 */
export function getAccessToken(): string | null {
  if (!isClient()) return null;
  
  try {
    let token = safeGetItem(ACCESS_TOKEN_KEY);
    
    // Migration from legacy keys
    if (!token) {
      const legacyKeys = ['accessToken', 'access_token'];
      for (const key of legacyKeys) {
        const legacyToken = safeGetItem(key);
        if (legacyToken) {
          token = legacyToken;
          safeSetItem(ACCESS_TOKEN_KEY, token);
          legacyKeys.forEach(k => safeRemoveItem(k));
          break;
        }
      }
    }
    
    return token;
  } catch (error) {
    reportError(error, 'token-storage', 'warning', { operation: 'getAccessToken' });
    return null;
  }
}

/**
 * Get the stored refresh token
 */
export function getRefreshToken(): string | null {
  if (!isClient()) return null;
  
  try {
    return safeGetItem(REFRESH_TOKEN_KEY);
  } catch (error) {
    reportError(error, 'token-storage', 'warning', { operation: 'getRefreshToken' });
    return null;
  }
}

/**
 * Get token expiry timestamp
 */
export function getTokenExpiry(): number | null {
  if (!isClient()) return null;
  
  try {
    const expiry = safeGetItem(TOKEN_EXPIRY_KEY);
    return expiry ? parseInt(expiry, 10) : null;
  } catch (error) {
    reportError(error, 'token-storage', 'warning', { operation: 'getTokenExpiry' });
    return null;
  }
}

/**
 * Check if the access token is expired or about to expire
 * @param bufferSeconds - Buffer time before actual expiry (default: 60 seconds)
 */
export function isTokenExpired(bufferSeconds: number = 60): boolean {
  const expiry = getTokenExpiry();
  if (!expiry) return true;
  
  const now = Date.now();
  return now >= (expiry - bufferSeconds * 1000);
}

/**
 * Check if refresh token exists
 */
export function hasRefreshToken(): boolean {
  return getRefreshToken() !== null;
}

/**
 * Clear all authentication data
 */
export function clearAuthData(): void {
  if (!isClient()) return;
  
  try {
    safeRemoveItem(ACCESS_TOKEN_KEY);
    safeRemoveItem(REFRESH_TOKEN_KEY);
    safeRemoveItem(TOKEN_EXPIRY_KEY);
    safeRemoveItem(USER_KEY);
  } catch (error) {
    reportError(error, 'token-storage', 'warning', { operation: 'clearAuthData' });
  }
}

/**
 * Store user data
 */
export function storeUser(user: any): void {
  if (!isClient()) return;
  
  try {
    safeSetItem(USER_KEY, JSON.stringify(user));
  } catch (error) {
    reportError(error, 'token-storage', 'warning', { operation: 'storeUser' });
  }
}

/**
 * Get stored user data
 */
export function getUser(): any | null {
  if (!isClient()) return null;
  
  try {
    const userStr = safeGetItem(USER_KEY);
    return userStr ? JSON.parse(userStr) : null;
  } catch (error) {
    reportError(error, 'token-storage', 'warning', { operation: 'getUser' });
    return null;
  }
}

/**
 * Check if user is authenticated (has valid tokens)
 */
export function isAuthenticated(): boolean {
  const hasToken = getAccessToken() !== null;
  const notExpired = !isTokenExpired();
  return hasToken && notExpired;
}

/**
 * Get seconds remaining until token expiry.
 * Returns 0 if token is already expired or not found.
 */
export function getTimeUntilExpiry(): number {
  const expiry = getTokenExpiry();
  if (!expiry) return 0;
  return Math.max(0, Math.floor((expiry - Date.now()) / 1000));
}