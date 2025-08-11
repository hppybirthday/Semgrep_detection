package com.securetool.file;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/file")
public class FileEncryptorController {
    private static final String BASE_DIR = "/var/securestorage/";
    private final FileMergeService fileMergeService = new FileMergeService();

    @PostMapping("/merge/{fileName}")
    public ResponseEntity<String> mergeFileChunks(@PathVariable String fileName, @RequestBody List<String> chunks) {
        try {
            if (!isValidFileName(fileName)) {
                return ResponseEntity.badRequest().body("Invalid file name");
            }
            fileMergeService.mergeFileChunks(fileName, chunks);
            return ResponseEntity.ok("File merged successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    private boolean isValidFileName(String fileName) {
        // 检查文件名是否包含非法字符
        if (fileName.contains("..") || fileName.startsWith("/")) {
            return false;
        }
        return true;
    }
}

class FileMergeService {
    private static final int MAX_CHUNK_SIZE = 1024 * 1024;
    private final EncryptionUtil encryptionUtil = new EncryptionUtil();

    public void mergeFileChunks(String fileName, List<String> chunks) throws Exception {
        Path targetPath = Paths.get(FileEncryptorController.BASE_DIR + fileName);
        try (OutputStream out = new FileOutputStream(targetPath.toFile())) {
            for (String chunk : chunks) {
                byte[] decryptedChunk = encryptionUtil.decrypt(Base64.getDecoder().decode(chunk));
                out.write(decryptedChunk);
            }
        }
        validateAndProcessFile(targetPath);
    }

    private void validateAndProcessFile(Path filePath) throws IOException {
        if (!filePath.normalize().startsWith(FileEncryptorController.BASE_DIR)) {
            throw new SecurityException("Invalid file path");
        }
        // 处理完成后删除原始分片
        Files.deleteIfExists(filePath);
    }
}

class EncryptionUtil {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final byte[] INIT_VECTOR = "RandomInitVector123".getBytes();

    public byte[] decrypt(byte[] cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec("MySecretKey12345".getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(INIT_VECTOR);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(cipherText);
    }
}

// 漏洞点分析：
// 1. FileEncryptorController的isValidFileName方法存在逻辑缺陷，攻击者可通过"/../../../etc/passwd"绕过检测
// 2. mergeFileChunks方法直接拼接用户输入的fileName到BASE_DIR后，未正确处理路径规范化
// 3. normalize()验证存在时序问题，攻击者可通过竞态条件绕过验证