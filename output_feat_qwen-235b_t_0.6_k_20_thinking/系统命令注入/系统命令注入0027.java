package com.bank.backup;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class BackupJob {
    private final String dbUser;
    private final String dbPassword;
    private final String dbName;
    private final String backupPath;

    public BackupJob(String dbUser, String dbPassword, String dbName, String backupPath) {
        this.dbUser = dbUser;
        this.dbPassword = dbPassword;
        this.dbName = dbName;
        this.backupPath = backupPath;
    }

    public String executeBackup() {
        try {
            // Vulnerable command construction
            String command = "mysqldump -u" + dbUser + " -p" + dbPassword + " --set-charset=utf8 " + dbName + " > " + backupPath;
            Process process = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", command});
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            while ((line = errorReader.readLine()) != null) {
                output.append("ERROR: ").append(line).append("\
");
            }
            return output.toString();
            
        } catch (IOException e) {
            return "Backup failed: " + e.getMessage();
        }
    }
}

// Application layer
class BackupService {
    private final BackupRepository backupRepo;

    public BackupService(BackupRepository repo) {
        this.backupRepo = repo;
    }

    public String triggerScheduledBackup(String jobId) {
        BackupConfig config = backupRepo.findConfigById(jobId);
        BackupJob job = new BackupJob(
            config.getDbUser(),
            config.getDbPassword(),
            config.getDbName(),
            config.getBackupPath()
        );
        return job.executeBackup();
    }
}

// Infrastructure layer
interface BackupRepository {
    BackupConfig findConfigById(String jobId);
}

// Value object
class BackupConfig {
    private final String dbUser;
    private final String dbPassword;
    private final String dbName;
    private final String backupPath;

    public BackupConfig(String dbUser, String dbPassword, String dbName, String backupPath) {
        this.dbUser = dbUser;
        this.dbPassword = dbPassword;
        this.dbName = dbName;
        this.backupPath = backupPath;
    }

    // Getters
    public String getDbUser() { return dbUser; }
    public String getDbPassword() { return dbPassword; }
    public String getDbName() { return dbName; }
    public String getBackupPath() { return backupPath; }
}

// Scheduler entry point
class BackupScheduler {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java BackupScheduler <jobId>");
            return;
        }
        
        BackupRepository repo = new DatabaseBackupRepository();
        BackupService service = new BackupService(repo);
        
        String jobId = args[0];
        String result = service.triggerScheduledBackup(jobId);
        System.out.println("Backup Result:\
" + result);
    }
}

// Mock repository implementation
class DatabaseBackupRepository implements BackupRepository {
    @Override
    public BackupConfig findConfigById(String jobId) {
        // Simulated database lookup
        if ("prod_backup".equals(jobId)) {
            return new BackupConfig(
                System.getenv("DB_USER"),
                System.getenv("DB_PASSWORD"),
                "banking_db",
                "C:\\\\backups\\\\daily.sql"
            );
        }
        throw new IllegalArgumentException("Invalid job ID");
    }
}