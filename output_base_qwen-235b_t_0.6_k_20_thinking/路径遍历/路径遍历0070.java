import java.io.*;
import java.util.Scanner;

public class IoTDeviceLogger {
    private static final String LOG_DIR = "./device_logs/";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("IoT Device Log Viewer v1.0");
        System.out.print("Enter device ID: ");
        String deviceId = scanner.nextLine();
        
        System.out.print("Enter log file name (with extension): ");
        String fileName = scanner.nextLine();
        
        String filePath = LOG_DIR + deviceId + "/" + fileName;
        System.out.println("[DEBUG] Attempting to read: " + filePath);
        
        try {
            File logFile = new File(filePath);
            if (!logFile.exists()) {
                System.out.println("Error: Log file not found");
                return;
            }
            
            BufferedReader reader = new BufferedReader(new FileReader(logFile));
            String line;
            System.out.println("--- Log Content ---");
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
            
        } catch (IOException e) {
            System.out.println("Error accessing log file: " + e.getMessage());
        }
    }

    // Simulated device configuration
    static {
        try {
            // Create sample directory structure
            new File("./device_logs/device001/").mkdirs();
            File sampleLog = new File("./device_logs/device001/sample.log");
            sampleLog.createNewFile();
            
            // Simulated sensitive file (should not be accessible)
            File shadow = new File("./device_logs/../../etc/shadow");
            shadow.createNewFile();
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}