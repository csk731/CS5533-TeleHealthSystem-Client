package dev.chaitanyaallu.telehealthclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import dev.chaitanyaallu.telehealthclient.commons.CryptoUtil;
import dev.chaitanyaallu.telehealthclient.commons.ECCKeyUtil;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.configurationprocessor.json.JSONObject;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Value;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

@Service
public class TelehealthClientService {

    @Value("${server.url}")
    private String serverUrl;
    private KeyPair keyPair;
    private PrivateKey clientPrivateKey;
    private PublicKey serverPublicKey;
    private byte[] derivedKey; // Attribute to store the derived key
    private static final Logger logger = LoggerFactory.getLogger(TelehealthClientService.class);


    @PostConstruct
    public void init() throws Exception {
        try {
            logger.info("Initializing ECC key pair for the client");
            this.keyPair = ECCKeyUtil.generateECCKeyPair();
            logger.info("Generated ECC key pair for the client");
            PublicKey clientPublicKey = keyPair.getPublic();
            logger.info("Client public key: " + clientPublicKey);
            this.clientPrivateKey = keyPair.getPrivate();
            logger.info("Client private key: " + clientPrivateKey);;

            sendPublicKeyToServer();
            logger.info("Successfully Sent public key to server");

            retrieveServerPublicKey();
            logger.info("Successfully retrieved Server public key: " + serverPublicKey);

        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Path decryptReceivedFile(Path encryptedFilePath) throws Exception {
        if (derivedKey == null) {
            throw new IllegalStateException("Encryption key has not been set.");
        }

        byte[] encryptedData = Files.readAllBytes(encryptedFilePath);

        // Extract nonce and decrypt
        byte[] nonce = Arrays.copyOfRange(encryptedData, 0, 12);
        byte[] ciphertextAndMac = Arrays.copyOfRange(encryptedData, 12, encryptedData.length);
        byte[] decryptedData = CryptoUtil.decryptChaCha20(ciphertextAndMac, derivedKey, nonce);

        // Verify hash and extract original file content
        int hashSize = 32; // For SHA3-256
        byte[] originalFileBytes = Arrays.copyOfRange(decryptedData, 0, decryptedData.length - hashSize);
        byte[] originalHash = Arrays.copyOfRange(decryptedData, decryptedData.length - hashSize, decryptedData.length);
        byte[] recalculatedHash = CryptoUtil.hashUsingSHA3(originalFileBytes);
        if (!Arrays.equals(originalHash, recalculatedHash)) {
            throw new SecurityException("File integrity check failed.");
        }

        // Safer path manipulation
        Path decryptedFilePath = encryptedFilePath.getParent().resolve(encryptedFilePath.getFileName().toString().replaceAll("\\.enc$", ""));
        Files.write(decryptedFilePath, originalFileBytes);

        return decryptedFilePath;
    }

    public String encryptAndSendFile(Path filePath, String originalFilename) throws Exception {
        if (derivedKey == null) {
            throw new IllegalStateException("Encryption key has not been derived.");
        }

        // Read file bytes
        byte[] fileBytes = Files.readAllBytes(filePath);

        // Hash, Encrypt, Combine with nonce
        byte[] messageHash = CryptoUtil.hashUsingSHA3(fileBytes);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(fileBytes);
        outputStream.write(messageHash);
        byte[] combinedMessage = outputStream.toByteArray();

        byte[] nonce = CryptoUtil.generateNonce();
        byte[] encryptedMessage = CryptoUtil.encryptChaCha20(combinedMessage, derivedKey, nonce);
        byte[] combinedEncryptedMessage = CryptoUtil.combineNonceAndCiphertext(nonce, encryptedMessage);

        // Temporarily write to a file (if needed)
        Path encryptedFilePath = Files.createTempFile(null, ".enc");
        Files.write(encryptedFilePath, combinedEncryptedMessage);

        // Prepare and send the encrypted file
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", new FileSystemResource(encryptedFilePath.toFile()));
        body.add("originalFilename", originalFilename); // Include original filename as form data

        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);
        ResponseEntity<String> response = restTemplate.postForEntity(serverUrl+"/receiveFile", requestEntity, String.class);

        // Check response status and handle errors
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to send file: " + response.getBody());
        }

        // Optionally, delete the temporary file after sending
        Files.delete(encryptedFilePath);

        // Return response body or handle as needed
        return response.getBody();
    }


    public void sendPublicKeyToServer() throws Exception {
        logger.info("Sending public key to server");
        String endpoint = serverUrl + "/clientPublicKey";

        logger.info("Public Key encoded: " + ECCKeyUtil.encodePublicKey(keyPair.getPublic()));
        String encodedPublicKey = ECCKeyUtil.encodePublicKey(keyPair.getPublic());

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);
        HttpEntity<String> request = new HttpEntity<>(encodedPublicKey, headers);

        ResponseEntity<String> response = restTemplate.postForEntity(endpoint, request, String.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to send public key to server. Status code: " + response.getStatusCode());
        }
    }
    public void retrieveServerPublicKey() throws Exception {
        logger.info("Retrieving server public key");
        RestTemplate restTemplate = new RestTemplate();
        String encodedPublicKey = restTemplate.getForObject(serverUrl + "/publicKey", String.class);
        this.serverPublicKey = ECCKeyUtil.decodePublicKey(encodedPublicKey);
        setServerPublicKey(encodedPublicKey);
    }
    public void setServerPublicKey(String encodedServerPublicKey) throws Exception {
        this.serverPublicKey = ECCKeyUtil.decodePublicKey(encodedServerPublicKey);
        byte[] sharedSecret = ECCKeyUtil.generateSharedSecret(clientPrivateKey, serverPublicKey);
        this.derivedKey = ECCKeyUtil.deriveKey(sharedSecret, 32); // Assume this method is correctly implemented
    }

    public String decryptServerResponse(byte[] encryptedResponseWithNonce) throws Exception {
        byte[] nonce = CryptoUtil.extractNonce(encryptedResponseWithNonce);
        byte[] encryptedResponse = CryptoUtil.extractCiphertext(encryptedResponseWithNonce);
        // Assume derivedKey has been generated and stored securely
        byte[] decryptedBytes = CryptoUtil.decryptChaCha20(encryptedResponse, derivedKey, nonce);
        return new String(decryptedBytes);
    }

    public byte[] decryptData(byte[] encryptedData) throws Exception {
        if (this.derivedKey == null) {
            throw new IllegalStateException("Encryption key has not been set.");
        }

        // Splitting nonce and ciphertext correctly
        logger.info("Decrypting data using ChaCha20-Poly1305");
        byte[] nonce = Arrays.copyOfRange(encryptedData, 0, 12); // First 12 bytes for nonce
        byte[] ciphertextAndMac = Arrays.copyOfRange(encryptedData, 12, encryptedData.length); // Rest for ciphertext + MAC

        ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
        cipher.init(false, new ParametersWithIV(new KeyParameter(derivedKey), nonce));

        byte[] decryptedData = new byte[cipher.getOutputSize(ciphertextAndMac.length)];
        int len = cipher.processBytes(ciphertextAndMac, 0, ciphertextAndMac.length, decryptedData, 0);
        cipher.doFinal(decryptedData, len); // MAC check happens here

        // Assuming the last 32 bytes (if SHA3-256 was used) are the original hash
        logger.info("Verifying data integrity using SHA-3");
        int hashSize = 32; // Adjust based on the hash function used
        byte[] originalMessage = Arrays.copyOf(decryptedData, decryptedData.length - hashSize);
        byte[] originalHash = Arrays.copyOfRange(decryptedData, decryptedData.length - hashSize, decryptedData.length);

        // Verify the hash
        logger.info("Recalculating hash using SHA-3");
        byte[] recalculatedHash = CryptoUtil.hashUsingSHA3(originalMessage);
        if (!Arrays.equals(originalHash, recalculatedHash)) {
            throw new SecurityException("Data integrity check failed.");
        }
        logger.info("Data integrity verified");

        return originalMessage;
    }

    public String encryptAndSend(String message) throws Exception {

        if (derivedKey == null) {
            throw new IllegalStateException("Encryption key has not been derived.");
        }

        logger.info("Encrypting and sending message");

        // First, hash the message using SHA-3
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        logger.info("Hashing message using SHA-3");
        byte[] messageHash = CryptoUtil.hashUsingSHA3(messageBytes);
        logger.info("Message hash: " + Base64.getEncoder().encodeToString(messageHash));


        // Combine the message and its hash
        logger.info("Combining message and its hash into a single message");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(messageBytes);
        outputStream.write(messageHash);
        byte[] combinedMessage = outputStream.toByteArray();

        // Encrypt the combined message
        logger.info("Encrypting the combined message using ChaCha20-Poly1305");
        byte[] nonce = CryptoUtil.generateNonce();
        byte[] encryptedMessage = CryptoUtil.encryptChaCha20(combinedMessage, derivedKey, nonce);
        byte[] combinedEncryptedMessage = CryptoUtil.combineNonceAndCiphertext(nonce, encryptedMessage);
        String encodedMessage = Base64.getEncoder().encodeToString(combinedEncryptedMessage);

        // Send the encrypted message to the client
        logger.info("Sending encrypted message to server");
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);
        HttpEntity<String> request = new HttpEntity<>(encodedMessage, headers);

        ResponseEntity<String> response = restTemplate.postForEntity(serverUrl + "/receiveEncryptedMessage", request, String.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to send encrypted message. Status: " + response.getStatusCode());
        }

// ERROR.....!!!!!!!!

        // Assuming the server response is also encrypted, decrypt it before returning
//        byte[] encryptedResponse = response.getBody().getBytes(StandardCharsets.UTF_8);
//        byte[] decodedResponse = Base64.getDecoder().decode(encryptedResponse);
//        String decryptedResponse = decryptServerResponse(decodedResponse);
//        return decryptedResponse;

        return response.getBody();
    }
}
