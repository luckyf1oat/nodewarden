import type { CiphersImportPayload } from '@/lib/api/vault';

interface ParsedOtpAuth {
  label: string;
  issuer: string;
  secret: string;
}

/**
 * Parse a single otpauth:// URI
 * Format: otpauth://totp/LABEL?secret=SECRET&issuer=ISSUER&algorithm=SHA1&digits=6&period=30
 */
function parseOtpAuthUri(uri: string): ParsedOtpAuth | null {
  try {
    const url = new URL(uri.trim());
    
    // Only support TOTP (not HOTP)
    if (url.protocol !== 'otpauth:') return null;
    if (url.hostname !== 'totp') return null;
    
    const secret = url.searchParams.get('secret');
    if (!secret || !secret.trim()) return null;
    
    // Label is in pathname, decode it
    const pathLabel = decodeURIComponent((url.pathname || '').replace(/^\/+/, ''));
    const issuer = (url.searchParams.get('issuer') || '').trim();
    
    // Extract the account/service name from the label
    // Format is typically "ServiceName:AccountName" or just "ServiceName"
    let label = pathLabel;
    if (label && issuer) {
      // If issuer is in label, extract just the account part
      const prefix = `${issuer}:`;
      if (label.toLowerCase().startsWith(prefix.toLowerCase())) {
        label = label.slice(prefix.length);
      }
    }
    
    return {
      label: label || issuer || 'OTP',
      issuer: issuer || pathLabel || 'OTP',
      secret: secret.trim(),
    };
  } catch {
    return null;
  }
}

/**
 * Parse otpauth URIs from text content
 * Each URI should be on a separate line or separated by whitespace
 */
export function parseOtpAuthText(textRaw: string): CiphersImportPayload {
  const result: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };
  
  if (!textRaw || !textRaw.trim()) {
    return result;
  }
  
  // Split by lines and process each line
  const lines = textRaw.split('\n');
  
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || !trimmed.startsWith('otpauth://')) {
      continue;
    }
    
    const parsed = parseOtpAuthUri(trimmed);
    if (!parsed) {
      continue;
    }
    
    // Create a cipher with login type and TOTP secret
    const cipher: Record<string, unknown> = {
      type: 1, // Login type
      name: parsed.label,
      notes: parsed.issuer ? `Issuer: ${parsed.issuer}` : null,
      favorite: false,
      reprompt: 0,
      key: null,
      login: {
        username: null,
        password: null,
        uris: null,
        totp: parsed.secret,
      },
      card: null,
      identity: null,
      secureNote: null,
      fields: null,
      passwordHistory: null,
      sshKey: null,
    };
    
    result.ciphers.push(cipher);
  }
  
  return result;
}
