import java.io.*;
import java.util.Scanner;
import java.util.function.Supplier;

public class CRMBackupSystem {
    public static void main(String[] args) {
        try {
            Supplier<String> userInput = () -> {
                Scanner scanner = new Scanner(System.in);
                System.out.print("Enter DB Username: ");
                return scanner.nextLine();
            };

            Supplier<String> passwordInput = () -> {
                Scanner scanner = new Scanner(System.in);
                System.out.print("Enter DB Password: ");
                return scanner.nextLine();
            };

            Supplier<String> dbInput = () -> {
                Scanner scanner = new Scanner(System.in);
                System.out.print("Enter DB Name: ");
                return scanner.nextLine();
            };

            String user = userInput.get();
            String password = passwordInput.get();
            String db = dbInput.get();

            // Vulnerable command construction
            String command = "mysqldump -u" + user + " -p" + password + " --set-charset=utf8 " + db;
            System.out.println("Executing command: " + command);

            // Simulate scheduled task execution
            executeBackupCommand(command);
        } catch (Exception e) {
            System.err.println("Backup failed: " + e.getMessage());
        }
    }

    private static void executeBackupCommand(String command) throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder(command.split(" "));
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("Backup Output: " + line);
            }
        }

        int exitCode = process.exitValue();
        System.out.println("Backup completed with exit code: " + exitCode);
    }
}