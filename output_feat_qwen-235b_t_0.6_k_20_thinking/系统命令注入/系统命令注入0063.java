import java.io.IOException;

@RestController
public class BackupController {
    private final DatabaseBackupService backupService = new DatabaseBackupService();

    @PostMapping("/backup")
    public String handleBackup(@RequestBody BackupRequest request) {
        try {
            return backupService.backupDatabase(
                request.getDbName(),
                request.getBackupPath()
            );
        } catch (IOException e) {
            return "Backup failed: " + e.getMessage();
        }
    }
}

class DatabaseBackupService {
    public String backupDatabase(String dbName, String backupPath) throws IOException {
        // 漏洞点：直接拼接用户输入到系统命令中
        String command = "sh -c \\"mysqldump -u admin -p securepass " + dbName + 
                        " > " + backupPath + "\\"";
        
        Process process = Runtime.getRuntime().exec(command);
        int exitCode = process.exitValue();
        
        return "Backup completed with exit code " + exitCode;
    }
}

class BackupRequest {
    private String dbName;
    private String backupPath;
    
    // Getters and setters
    public String getDbName() { return dbName; }
    public void setDbName(String dbName) { this.dbName = dbName; }
    
    public String getBackupPath() { return backupPath; }
    public void setBackupPath(String backupPath) { this.backupPath = backupPath; }
}