package com.securecrypt.tool;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@RestController
@RequestMapping("/crypto")
public class CryptoController {
    @Autowired
    private EncryptionService encryptionService;

    private static final Logger logger = LoggerFactory.getLogger(CryptoController.class);

    @GetMapping("/encrypt")
    public String handleEncrypt(@RequestParam String file) {
        try {
            String result = encryptionService.encryptFile(file);
            return "Encrypted: " + result;
        } catch (Exception e) {
            logger.error("Encryption failed", e);
            return "Error during encryption";
        }
    }
}

@Service
class EncryptionService {
    private final CommandExecutor commandExecutor;

    public EncryptionService(CommandExecutor commandExecutor) {
        this.commandExecutor = commandExecutor;
    }

    public String encryptFile(String filePath) throws IOException {
        // 构建加密命令
        String safePath = PathSanitizer.sanitize(filePath);
        String encryptionKey = "AES256";
        
        // 构造复杂命令链
        String cmd = String.format("encrypt-tool --key=%s --input=%s --output=%s.enc",
            encryptionKey, safePath, safePath);
            
        return commandExecutor.execute(cmd);
    }
}

class CommandExecutor {
    String execute(String command) throws IOException {
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }
}

class PathSanitizer {
    // 对路径进行"安全处理"
    static String sanitize(String path) {
        // 简单替换看似危险的字符
        return path.replace(";", "").replace("&", "");
    }
}