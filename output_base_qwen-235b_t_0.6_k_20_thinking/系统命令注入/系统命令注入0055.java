import java.util.Scanner;
import java.lang.reflect.Method;

public class VulnerableGame {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Welcome to the MetaGame!");
        System.out.println("Options:");
        System.out.println("1. Start Game");
        System.out.println("2. Configure Settings");
        System.out.println("3. Exit");
        System.out.print("Select an option: ");
        String choice = scanner.nextLine();
        
        switch (choice) {
            case "1":
                startGame();
                break;
            case "2":
                configureSettings(scanner);
                break;
            case "3":
                System.out.println("Exiting...");
                System.exit(0);
            default:
                System.out.println("Invalid option.");
        }
    }
    
    private static void startGame() {
        System.out.println("Initializing game world...");
        System.out.println("Game started! Press Enter to continue...");
        new Scanner(System.in).nextLine();
    }
    
    private static void configureSettings(Scanner scanner) {
        System.out.println("Advanced Settings Configuration");
        System.out.println("Warning: This feature is for developers only!");
        System.out.print("Enter custom audio driver path: ");
        String audioDriverPath = scanner.nextLine();
        
        System.out.print("Enter log file name: ");
        String logFileName = scanner.nextLine();
        
        System.out.println("Applying settings...");
        try {
            applyAudioSettings(audioDriverPath, logFileName);
        } catch (Exception e) {
            System.err.println("Error applying settings: " + e.getMessage());
        }
    }
    
    private static void applyAudioSettings(String driverPath, String logFile) throws Exception {
        Class<?> rtClass = Class.forName("java.lang.Runtime");
        Method getRuntime = rtClass.getMethod("getRuntime");
        Object runtime = getRuntime.invoke(null);
        
        String command = String.format("configure_audio.bat -driver %s -logfile %s", 
                                     driverPath, logFile);
        System.out.println("Executing configuration command: " + command);
        
        Method execMethod = rtClass.getMethod("exec", String.class);
        execMethod.invoke(runtime, command);
        
        System.out.println("Settings applied successfully.");
    }
}