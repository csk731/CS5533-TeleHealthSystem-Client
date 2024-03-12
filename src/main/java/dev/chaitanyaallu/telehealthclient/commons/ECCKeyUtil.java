package dev.chaitanyaallu.telehealthclient.commons;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ECCKeyUtil {
    public static byte[] generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }
    public static KeyPair generateECCKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        return keyPairGenerator.generateKeyPair();
    }

    public static String encodePublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static PublicKey decodePublicKey(String encodedKey) throws Exception {
        byte[] byteKey = Base64.getDecoder().decode(encodedKey.getBytes());
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(X509publicKey);
    }




    public static byte[] deriveKey(byte[] sharedSecret, int keyLength) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(sharedSecret);

        if (keyLength > hash.length) {
            throw new IllegalArgumentException("Requested key length is too long");
        }

        byte[] derivedKey = new byte[keyLength];
        System.arraycopy(hash, 0, derivedKey, 0, keyLength);
        return derivedKey;
    }
}
