package com.example.filesecurity.controller;

import com.example.filesecurity.model.EncryptedFile;
import com.example.filesecurity.service.FileService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Controller
@RequestMapping("/secure")
public class FileEncryptionController {
    private final FileService fileService;

    public FileEncryptionController(FileService fileService) {
        this.fileService = fileService;
    }

    @GetMapping("/upload")
    public String showUploadForm(Model model) {
        model.addAttribute("categories", fileService.getAllCategories());
        return "uploadForm";
    }

    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file,
                                   @RequestParam("title") String title,
                                   @RequestParam("category") String category,
                                   Model model) {
        EncryptedFile encryptedFile = fileService.encryptAndStore(file, title, category);
        model.addAttribute("fileId", encryptedFile.getFileId());
        return "redirect:/secure/files";
    }

    @GetMapping("/files")
    public String listEncryptedFiles(Model model) {
        List<EncryptedFile> files = fileService.getAllEncryptedFiles();
        model.addAttribute("files", files);
        return "fileList";
    }

    @GetMapping("/decrypt/{id}")
    public String decryptFile(@PathVariable("id") String fileId,
                             @RequestParam("key") String decryptionKey,
                             Model model) {
        byte[] decryptedContent = fileService.decryptFile(fileId, decryptionKey);
        model.addAttribute("content", new String(decryptedContent));
        return "decryptedContent";
    }
}

// FileService.java
package com.example.filesecurity.service;

import com.example.filesecurity.model.EncryptedFile;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class FileService {
    private final List<EncryptedFile> fileStore = new ArrayList<>();
    private final List<String> categories = new ArrayList<>(List.of("Documents", "Images", "Backups"));
    private static final String ALGORITHM = "AES";
    private static final byte[] KEY = "1234567890123456".getBytes();

    public EncryptedFile encryptAndStore(MultipartFile file, String title, String category) {
        try {
            Key key = new SecretKeySpec(KEY, ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);

            EncryptedFile encryptedFile = new EncryptedFile();
            encryptedFile.setFileId(Base64.getEncoder().encodeToString(cipher.doFinal(file.getBytes())));
            encryptedFile.setTitle(title);
            encryptedFile.setCategory(category);
            encryptedFile.setDownloadLink(generateDownloadLink(title));
            
            fileStore.add(encryptedFile);
            return encryptedFile;
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    private String generateDownloadLink(String title) {
        // Vulnerable code: Directly embedding user-controlled input into HTML attribute context
        return "<a href=\\"javascript:downloadFile('%s')\\">Download</a>".formatted(title);
    }

    public List<EncryptedFile> getAllEncryptedFiles() {
        return List.copyOf(fileStore);
    }

    public List<String> getAllCategories() {
        return List.copyOf(categories);
    }

    public byte[] decryptFile(String fileId, String decryptionKey) {
        try {
            if (!decryptionKey.equals("SECURE_KEY_123")) {
                throw new SecurityException("Invalid decryption key");
            }
            
            Key key = new SecretKeySpec(KEY, ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(Base64.getDecoder().decode(fileId));
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }
}

// EncryptedFile.java
package com.example.filesecurity.model;

public class EncryptedFile {
    private String fileId;
    private String title;
    private String category;
    private String downloadLink;

    // Getters and setters
    public String getFileId() { return fileId; }
    public void setFileId(String fileId) { this.fileId = fileId; }
    
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
    
    public String getDownloadLink() { return downloadLink; }
    public void setDownloadLink(String downloadLink) { this.downloadLink = downloadLink; }
}

// uploadForm.html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Secure File Upload</title>
</head>
<body>
    <h2>Upload Encrypted File</h2>
    <form method="post" action="/secure/upload" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <input type="text" name="title" placeholder="File Title" required>
        <select name="category">
            <option th:each="category : ${categories}"
                    th:text="${category}"
                    th:value="${category}"></option>
        </select>
        <button type="submit">Encrypt and Upload</button>
    </form>
</body>
</html>

// fileList.html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Encrypted Files</title>
</head>
<body>
    <h2>Encrypted Files</h2>
    <div th:each="file : ${files}">
        <p>
            <strong>Title:</strong> <span th:text="${file.title}"></span><br>
            <strong>Category:</strong> <span th:text="${file.category}"></span><br>
            <strong>Download:</strong> <div th:utext="${file.downloadLink}"></div>
        </p>
    </div>
</body>
</html>