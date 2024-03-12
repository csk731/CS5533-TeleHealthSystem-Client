package dev.chaitanyaallu.telehealthclient.controller;

import dev.chaitanyaallu.telehealthclient.service.TelehealthClientService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

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
