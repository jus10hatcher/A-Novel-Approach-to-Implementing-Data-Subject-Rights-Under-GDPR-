// Appendix A: Tokenization Pipeline Implementations in C#
// This appendix provides simplified versions of the three tokenization pipelines used in the experimental evaluation.

using System;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Concurrent;

// ----------------------
// 1. Encryption-Only Pipeline
// ----------------------
public static class EncryptionOnlyPipeline
{
    private static readonly byte[] Key = Convert.FromBase64String("YOUR_BASE64_KEY==");
    private static readonly byte[] IV = new byte[12]; // AES-GCM 12-byte nonce

    public static byte[] Encrypt(string plaintext)
    {
        using var aes = new AesGcm(Key);
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] ciphertext = new byte[plaintextBytes.Length];
        byte[] tag = new byte[16];

        aes.Encrypt(IV, plaintextBytes, ciphertext, tag);

        return ciphertext;
    }
}

// ----------------------
// 2. Vault-Based Tokenization Pipeline
// ----------------------
public static class VaultedTokenizationPipeline
{
    private static readonly ConcurrentDictionary<string, string> TokenVault = new();

    public static string Tokenize(string input)
    {
        string token = Guid.NewGuid().ToString();
        TokenVault[token] = input;
        return token;
    }

    public static string Detokenize(string token)
    {
        return TokenVault.TryGetValue(token, out var original) ? original : null;
    }
}

// ----------------------
// 3. Vaultless Tokenization Pipeline (Consent-Scoped FPE)
// ----------------------
public static class VaultlessTokenizationPipeline
{
    private static readonly string GlobalKey = "YourGlobalConsentScopedKey";

    public static string Tokenize(string consentId, string fieldValue)
    {
        string scopeKey = consentId + ":" + GlobalKey;
        string input = scopeKey + ":" + fieldValue;

        using var sha256 = SHA256.Create();
        byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        string token = Convert.ToBase64String(hashBytes)[..16]; // Shorten for readability

        return token;
    }

    public static bool RevokeConsent(string consentId)
    {
        // Invalidate consent-based scope (e.g., delete derived key or mapping)
        Console.WriteLine($"Consent revoked for {consentId}");
        return true;
    }
}

// Note: These implementations are illustrative only. Production systems should use secure key handling and proper cryptographic libraries (e.g., Microsoft.AspNetCore.DataProtection or third-party FPE providers).
