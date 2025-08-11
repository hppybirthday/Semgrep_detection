import java.lang.reflect.Method;
import java.util.Arrays;

public class DynamicCommandExecutor {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: java DynamicCommandExecutor <commandType> <param>");
            return;
        }
        
        CommandExecutor executor = new CommandExecutor();
        Method method = executor.getClass().getMethod(args[0] + "Command", String.class);
        method.invoke(executor, args[1]);
    }
}

class CommandExecutor {
    public void backupCommand(String dbName) {
        String[] cmd = {"/bin/sh", "-c", "mysqldump -u admin -p securepass " + dbName + " > /data/backup/" + dbName + "_$(date +%Y%m%d).sql"};
        executeCommand(cmd);
    }
    
    public void analyzeCommand(String dataset) {
        String[] cmd = {"/bin/sh", "-c", "hadoop jar /opt/analytics.jar ProcessData -Dinput=" + dataset + " -Doutput=/results/" + dataset + "_processed"};
        executeCommand(cmd);
    }
    
    private void executeCommand(String[] command) {
        try {
            System.out.println("Executing: " + Arrays.toString(command));
            Process process = new ProcessBuilder(command).start();
            int exitCode = process.waitFor();
            System.out.println("Execution completed with exit code " + exitCode);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}