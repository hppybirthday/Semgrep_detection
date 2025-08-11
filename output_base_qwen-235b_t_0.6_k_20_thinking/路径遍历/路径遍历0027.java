package com.bank.document;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;

@RestController
@RequestMapping("/api/documents")
public class DocumentController {
    private final DocumentService documentService = new DocumentService();

    @GetMapping("/{filename}")
    public String getDocument(@PathVariable String filename) {
        return documentService.getDocumentContent(filename);
    }
}

class DocumentService {
    private static final String BASE_PATH = "/var/bank/documents/";
    
    public String getDocumentContent(String filename) {
        try {
            Path filePath = Paths.get(BASE_PATH + filename);
            if (!filePath.normalize().startsWith(BASE_PATH)) {
                throw new SecurityException("Invalid file path");
            }
            return new String(Files.readAllBytes(filePath));
        } catch (IOException e) {
            throw new DocumentAccessException("Failed to read document", e);
        }
    }
}

class DocumentAccessException extends RuntimeException {
    public DocumentAccessException(String message, Throwable cause) {
        super(message, cause);
    }
}

// Spring Boot main class
@SpringBootApplication
public class BankDocumentServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(BankDocumentServiceApplication.class, args);
    }
}

// Security config (simplified)
@Configuration
class SecurityConfig {
    // Basic auth for demonstration
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated()
            .and().httpBasic();
        return http.build();
    }
}

// Vulnerable when: 
// 1. Accessing /api/documents/../../../../etc/passwd
// 2. BASE_PATH not properly guarded against path traversal
// 3. Missing input validation for special characters