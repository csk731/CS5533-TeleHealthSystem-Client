package dev.chaitanyaallu.telehealthclient.controller;

import dev.chaitanyaallu.telehealthclient.service.TelehealthClientService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Objects;

@RestController
public class TelehealthClientController {

    private final TelehealthClientService telehealthClientService;
    private static final Logger logger = LoggerFactory.getLogger(TelehealthClientService.class);

    @Autowired
    public TelehealthClientController(TelehealthClientService telehealthClientService) {
        this.telehealthClientService = telehealthClientService;
    }

    @PostMapping("/sendEncryptedMessage")
    public ResponseEntity<?> sendEncryptedMessage(@RequestBody String message) {
        try {
            logger.info("Received request from user to send encrypted message to server");
            // This could be an endpoint in the server that expects encrypted messages
            String response = telehealthClientService.encryptAndSend(message);
            return ResponseEntity.ok("Received response from server: " + response);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("Failed to send encrypted message: " + e.getMessage());
        }
    }

    @PostMapping("/uploadFile")
    public ResponseEntity<?> uploadFile(@RequestParam("file") MultipartFile file) {
        try {
            Path tempFile = Files.createTempFile(null, null);
            file.transferTo(tempFile.toFile());
            // Encrypt and send file
            String encryptedFilePath = telehealthClientService.encryptAndSendFile(tempFile, file.getOriginalFilename());
            return ResponseEntity.ok().body("File encrypted and sent successfully: " + encryptedFilePath);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("Failed to encrypt and send file: " + e.getMessage());
        }
    }

    @PostMapping("/receiveFile")
    public ResponseEntity<String> receiveFile(@RequestParam("file") MultipartFile file, @RequestParam("originalFilename") String originalFilename) {
        String directoryPath = "received_files";
        Path directory = Paths.get(directoryPath);

        try {
            // Ensure the directory exists
            if (!Files.exists(directory)) {
                Files.createDirectories(directory); // Create the directory if it does not exist
            }

            // Save the encrypted file
            Path encryptedFilePath = directory.resolve(Objects.requireNonNull(originalFilename));
            file.transferTo(encryptedFilePath);

            // Decrypt the file
            Path decryptedFilePath = directory.resolve(originalFilename.replace(".enc", ""));
            telehealthClientService.decryptReceivedFile(encryptedFilePath);

            // After decryption, handle the decrypted file as needed
            System.out.println("Decrypted file saved: " + decryptedFilePath);

            return ResponseEntity.ok("File received and decrypted successfully: " + decryptedFilePath);
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("Failed to receive and decrypt file: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("Unexpected error during decryption: " + e.getMessage());
        }
    }


    @PostMapping("/receiveEncryptedMessage")
    public ResponseEntity<String> receiveEncryptedMessage(@RequestBody String encodedMessage) {
        try {

            System.out.println("Received encrypted message: " + encodedMessage);

            byte[] encryptedDataWithNonce = Base64.getDecoder().decode(encodedMessage);

            // Decrypt the data
            byte[] decryptedData = telehealthClientService.decryptData(encryptedDataWithNonce);

            // Assuming the decrypted data is a UTF-8 encoded string
            String decryptedMessage = new String(decryptedData, StandardCharsets.UTF_8);
            System.out.println("Decrypted message: " + decryptedMessage);
            // Process the decrypted message as needed

            return ResponseEntity.ok().body("Message decrypted successfully: " + decryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to process encrypted message");
        }
    }

}
