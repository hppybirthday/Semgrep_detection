package com.secure.encrypt.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Service
public class EncryptionService {
    private final RestTemplate restTemplate;

    public EncryptionService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String encryptRemoteFile(String fileUrl) throws IOException {
        if (!validateFileAccess(fileUrl)) {
            throw new IllegalArgumentException("Invalid file source");
        }

        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(fetchRemoteStream(fileUrl)))) {
            String line;
            while ((line = readLineWithValidation(reader)) != null) {
                content.append(line).append("");
            }
        }

        return Base64.getEncoder().encodeToString(content.toString().getBytes(StandardCharsets.UTF_8));
    }

    private boolean validateFileAccess(String url) {
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme().toLowerCase();
            // 仅允许HTTP/HTTPS协议
            if (!scheme.equals("http") && !scheme.equals("https")) {
                return false;
            }

            // 阻止直接访问本地资源
            String host = uri.getHost();
            if (host == null) {
                return false;
            }
            return !host.contains("localhost") && !host.equals("127.0.0.1");
        } catch (URISyntaxException e) {
            return false;
        }
    }

    private InputStreamReader fetchRemoteStream(String url) {
        return new InputStreamReader(
            restTemplate.getForEntity(url, byte[].class).getBody(),
            StandardCharsets.UTF_8
        );
    }

    private String readLineWithValidation(BufferedReader reader) throws IOException {
        String line = reader.readLine();
        if (line != null && line.length() > 1024) {
            throw new IOException("Line length exceeded limit");
        }
        return line;
    }
}