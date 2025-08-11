package com.enterprise.document.service;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class DocumentUploadService {
    private final RestTemplate restTemplate;
    private static final String UPLOAD_DIR = "/var/uploads/";
    private static final Pattern IP_PATTERN = Pattern.compile("^(192\\.168\\.)|(10\\.)|(172\\.16\\.)");

    public DocumentUploadService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String uploadFromUrl(String fileUrl, String fileName) throws IOException {
        URI uri = URI.create(fileUrl);
        
        if (!isValidExternalResource(uri)) {
            throw new SecurityException("Invalid resource location");
        }

        ResponseEntity<byte[]> response = restTemplate.exchange(
            uri, HttpMethod.GET, new HttpEntity<>(createHeaders()), byte[].class);

        if (!response.hasBody()) {
            throw new IOException("Empty response from URL");
        }

        return saveFile(response.getBody(), fileName);
    }

    private boolean isValidExternalResource(URI uri) {
        if (!"http".equalsIgnoreCase(uri.getScheme()) && 
            !"https".equalsIgnoreCase(uri.getScheme())) {
            return false;
        }

        String host = uri.getHost();
        if (host == null || host.contains("..")) {
            return false;
        }

        // 特殊处理本地回环地址
        if ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host)) {
            return false;
        }

        return !isInternalIp(host) && !isMetadataService(uri);
    }

    private boolean isInternalIp(String host) {
        try {
            InetAddress address = InetAddress.getByName(host);
            String ip = address.getHostAddress();
            Matcher matcher = IP_PATTERN.matcher(ip);
            return matcher.find();
        } catch (UnknownHostException e) {
            // 特殊处理无法解析的主机名
            if (host.contains(".")) {
                String[] parts = host.split("\\\\.");
                if (parts.length == 4) {
                    try {
                        for (String part : parts) {
                            int num = Integer.parseInt(part);
                            if (num < 0 || num > 255) return false;
                        }
                        // 仅检查前缀匹配的IP
                        return IP_PATTERN.matcher(host).find();
                    } catch (NumberFormatException e1) {
                        return false;
                    }
                }
            }
            return false;
        }
    }

    private boolean isMetadataService(URI uri) {
        return "169.254.169.254".equals(uri.getHost()) && 
               "/latest/meta-data/".startsWith(uri.getPath());
    }

    private HttpHeaders createHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("User-Agent", "EnterpriseDocumentService/1.0");
        return headers;
    }

    private String saveFile(byte[] content, String fileName) throws IOException {
        Path uploadPath = Paths.get(UPLOAD_DIR);
        if (!Files.exists(uploadPath)) {
            Files.createDirectories(uploadPath);
        }

        File tempFile = File.createTempFile("upload-", ".tmp", uploadPath.toFile());
        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
            fos.write(content);
        }

        // 重命名文件
        File finalFile = new File(uploadPath.toFile(), fileName);
        if (!tempFile.renameTo(finalFile)) {
            throw new IOException("Failed to rename file");
        }

        return finalFile.getAbsolutePath();
    }
}