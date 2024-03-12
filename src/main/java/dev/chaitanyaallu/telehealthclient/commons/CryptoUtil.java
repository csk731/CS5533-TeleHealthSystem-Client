package dev.chaitanyaallu.telehealthclient.commons;

import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class CryptoUtil {

    public static byte[] hashUsingSHA3(byte[] data) throws Exception {
        SHA3.DigestSHA3 digestSHA3 = new SHA3.Digest256(); // Or Digest512, depending on your security requirement
        return digestSHA3.digest(data);
    }
    public static byte[] encryptChaCha20(byte[] plaintext, byte[] key, byte[] nonce) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            SecretKeySpec keySpec = new SecretKeySpec(key, "ChaCha20");
            IvParameterSpec ivSpec = new IvParameterSpec(nonce);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            return cipher.doFinal(plaintext);
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    public static byte[] decryptChaCha20(byte[] ciphertext, byte[] key, byte[] nonce) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305"); // Use the same algorithm name
        SecretKeySpec keySpec = new SecretKeySpec(key, "ChaCha20"); // Keep key spec consistent
        IvParameterSpec ivSpec = new IvParameterSpec(nonce); // Nonce (IV) must be the same as used in encryption
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec); // Init in decrypt mode
        return cipher.doFinal(ciphertext); // Decrypt the ciphertext which includes the Poly1305 tag
    }
    public static byte[] generateNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[12]; // ChaCha20 uses a 12-byte nonce
        random.nextBytes(nonce);
        return nonce;
    }
    public static byte[] extractNonce(byte[] encryptedResponseWithNonce) {
        return Arrays.copyOfRange(encryptedResponseWithNonce, 0, 12);
    }

    public static byte[] extractCiphertext(byte[] encryptedResponseWithNonce) {
        return Arrays.copyOfRange(encryptedResponseWithNonce, 12, encryptedResponseWithNonce.length);
    }
    public static byte[] combineNonceAndCiphertext(byte[] nonce, byte[] ciphertext) {
        byte[] combined = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, combined, 0, nonce.length);
        System.arraycopy(ciphertext, 0, combined, nonce.length, ciphertext.length);
        return combined;
    }


//    public static byte[] deriveKey(byte[] sharedSecret, int keyLength) throws Exception {
//        MessageDigest hash = MessageDigest.getInstance("SHA-256");
//        hash.update(sharedSecret);
//        byte[] derivedKey = new byte[keyLength];
//        System.arraycopy(hash.digest(), 0, derivedKey, 0, keyLength);
//        return derivedKey;
//    }
}
