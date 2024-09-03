package com.schrodingdong.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class GitHubWebhookValidator {

    /**
     * Validates the GitHub webhook by verifying the HMAC SHA-256 signature.
     *
     * @param payloadBody     The body of the request (usually the raw JSON payload).
     * @param secretToken     The secret token used to create the HMAC signature.
     * @param signatureHeader The signature from the GitHub header (x-hub-signature-256).
     * @throws SecurityException If the signatures do not match or the header is missing.
     */
    public static void validateGitHubWebhook(byte[] payloadBody, String secretToken, String signatureHeader) throws SecurityException {
        if (signatureHeader == null || signatureHeader.isEmpty()) {
            throw new SecurityException("x-hub-signature-256 header is missing!");
        }

        try {
            // Create the HMAC SHA-256 signature
            Mac hmacSha256 = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(secretToken.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            hmacSha256.init(secretKey);

            byte[] hash = hmacSha256.doFinal(payloadBody);
            String expectedSignature = "sha256=" + encodeHexString(hash);

            // Compare the signatures
            if (!expectedSignature.equals(signatureHeader)) {
                throw new SecurityException("Request signatures didn't match!");
            }

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new SecurityException("Failed to calculate HMAC SHA-256 hash.", e);
        }
    }

    /**
     * Encodes a byte array into a hexadecimal string.
     *
     * @param bytes The byte array to encode.
     * @return The hexadecimal string representation of the byte array.
     */
    private static String encodeHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}