import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SpringBootApplication
@RestController
public class VulnerableBackupService {

    private static final Logger logger = LoggerFactory.getLogger(VulnerableBackupService.class);

    public static void main(String[] args) {
        SpringApplication.run(VulnerableBackupService.class, args);
    }

    @PostMapping("/backup")
    public ResponseEntity<String> handleBackup(@RequestBody BackupRequest request) {
        try {
            String user = request.getUser();
            String password = request.getPassword();
            String database = request.getDatabase();
            
            // 漏洞点：直接拼接用户输入到命令字符串
            String rawCommand = String.format("mysqldump -u %s -p%s -h %s %s > /var/backups/%s.sql",
                user, password, request.getHost(), database, database);
            
            logger.info("Executing backup command: {}", rawCommand);
            ProcessBuilder builder = new ProcessBuilder("sh", "-c", rawCommand);
            builder.redirectErrorStream(true);
            Process process = builder.start();
            
            CompletableFuture<Void> logFuture = new CompletableFuture<>();
            new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                    
                    String line;
                    while ((line = reader.readLine()) != null) {
                        logger.info("Command output: {}", line);
                    }
                    logFuture.complete(null);
                } catch (IOException e) {
                    logger.error("Error reading command output", e);
                    logFuture.completeExceptionally(e);
                }
            }).start();

            int exitCode = process.waitFor();
            logFuture.join();
            
            if (exitCode == 0) {
                return ResponseEntity.ok(String.format("Backup of %s completed successfully", database));
            } else {
                return ResponseEntity.status(500).body(String.format("Backup failed with exit code %d", exitCode));
            }
            
        } catch (Exception e) {
            logger.error("Backup execution error", e);
            return ResponseEntity.status(500).body("Internal server error: " + e.getMessage());
        }
    }

    static class BackupRequest {
        private String user;
        private String password;
        private String database;
        private String host;
        
        // Getters and setters
        public String getUser() { return user; }
        public void setUser(String user) { this.user = user; }
        
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
        
        public String getDatabase() { return database; }
        public void setDatabase(String database) { this.database = database; }
        
        public String getHost() { return host; }
        public void setHost(String host) { this.host = host; }
    }

    static class StreamLogger implements Runnable {
        private final InputStream stream;
        private final Consumer<String> logger;
        
        public StreamLogger(InputStream stream, Consumer<String> logger) {
            this.stream = stream;
            this.logger = logger;
        }

        @Override
        public void run() {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    logger.accept(line);
                }
            } catch (IOException e) {
                throw new RuntimeException("Stream logging error", e);
            }
        }
    }
}