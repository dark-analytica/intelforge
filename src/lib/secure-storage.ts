// Secure API Key Storage with Client-Side Encryption
class SecureStorage {
  private readonly storagePrefix = 'cqlforge_secure_';
  private readonly keyDerivationIterations = 100000;

  // Generate a key from user's browser fingerprint + timestamp
  private async generateEncryptionKey(): Promise<CryptoKey> {
    const fingerprint = await this.getBrowserFingerprint();
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(fingerprint),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode('cqlforge-salt-2024'),
        iterations: this.keyDerivationIterations,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  private async getBrowserFingerprint(): Promise<string> {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    if (ctx) {
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillText('IntelForge fingerprint', 2, 2);
    }
    
    const fingerprint = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height,
      new Date().getTimezoneOffset().toString(),
      canvas.toDataURL(),
      navigator.hardwareConcurrency || '0'
    ].join('|');

    // Hash the fingerprint for consistency
    const encoder = new TextEncoder();
    const data = encoder.encode(fingerprint);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async encryptAndStore(key: string, value: string): Promise<void> {
    if (!value.trim()) {
      localStorage.removeItem(this.storagePrefix + key);
      return;
    }

    try {
      const encryptionKey = await this.generateEncryptionKey();
      const encoder = new TextEncoder();
      const data = encoder.encode(value);
      
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        encryptionKey,
        data
      );

      const encryptedData = {
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(encrypted)),
        timestamp: Date.now()
      };

      localStorage.setItem(
        this.storagePrefix + key,
        JSON.stringify(encryptedData)
      );
    } catch (error) {
      console.error('Encryption failed, falling back to plain storage:', error);
      // Fallback to plain storage if encryption fails
      localStorage.setItem('cqlforge_' + key, value);
    }
  }

  async decryptAndRetrieve(key: string): Promise<string> {
    const encryptedItem = localStorage.getItem(this.storagePrefix + key);
    
    if (!encryptedItem) {
      // Check for legacy plain storage
      return localStorage.getItem('cqlforge_' + key) || '';
    }

    try {
      const encryptedData = JSON.parse(encryptedItem);
      const encryptionKey = await this.generateEncryptionKey();
      
      const iv = new Uint8Array(encryptedData.iv);
      const data = new Uint8Array(encryptedData.data);
      
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        encryptionKey,
        data
      );

      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    } catch (error) {
      console.error('Decryption failed:', error);
      // Try legacy plain storage as fallback
      return localStorage.getItem('cqlforge_' + key) || '';
    }
  }

  async removeKey(key: string): Promise<void> {
    localStorage.removeItem(this.storagePrefix + key);
    localStorage.removeItem('cqlforge_' + key); // Remove legacy key too
  }

  async clearAll(): Promise<void> {
    const keys = Object.keys(localStorage);
    keys.forEach(key => {
      if (key.startsWith(this.storagePrefix) || key.startsWith('cqlforge_')) {
        localStorage.removeItem(key);
      }
    });
  }

  // Migrate legacy plain storage to encrypted storage
  async migrateLegacyStorage(): Promise<void> {
    const legacyKeys = ['openai_key', 'anthropic_key', 'gemini_key', 'openrouter_key'];
    
    for (const key of legacyKeys) {
      const legacyValue = localStorage.getItem('cqlforge_' + key);
      if (legacyValue && !localStorage.getItem(this.storagePrefix + key)) {
        await this.encryptAndStore(key, legacyValue);
        localStorage.removeItem('cqlforge_' + key);
      }
    }
  }

  // Check if browser supports required crypto APIs
  isSupported(): boolean {
    return !!(crypto && crypto.subtle && crypto.getRandomValues);
  }
}

export const secureStorage = new SecureStorage();

// Initialize migration on load
if (typeof window !== 'undefined') {
  secureStorage.migrateLegacyStorage().catch(console.error);
}
