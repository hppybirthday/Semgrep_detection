import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

interface CommandExecutor {
    String execute(String command) throws IOException;
}

class CommandExecUtil implements CommandExecutor {
    @Override
    public String execute(String command) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        return output.toString();
    }
}

abstract class DatabaseService {
    protected abstract String getBackupScriptPath();
    protected abstract CommandExecutor getCommandExecutor();
    
    public void backupDatabase(String backupPath) throws IOException {
        String command = String.format("%s %s", getBackupScriptPath(), backupPath);
        System.out.println("[INFO] Executing command: " + command);
        String result = getCommandExecutor().execute(command);
        System.out.println("[RESULT] " + result);
    }
}

class BankingDatabaseService extends DatabaseService {
    private static final String BACKUP_SCRIPT = "/opt/bank/scripts/backup.sh";
    private final CommandExecutor executor;

    public BankingDatabaseService(CommandExecutor executor) {
        this.executor = executor;
    }

    @Override
    protected String getBackupScriptPath() {
        return BACKUP_SCRIPT;
    }

    @Override
    protected CommandExecutor getCommandExecutor() {
        return executor;
    }
}

public class BankingSystemSimulator {
    public static void main(String[] args) {
        try {
            CommandExecutor executor = new CommandExecUtil();
            DatabaseService dbService = new BankingDatabaseService(executor);
            
            System.out.print("Enter backup path (e.g., /backup/2024): ");
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(System.in));
            String userInput = reader.readLine();
            
            dbService.backupDatabase(userInput);
            
        } catch (Exception e) {
            System.err.println("[ERROR] " + e.getMessage());
        }
    }
}