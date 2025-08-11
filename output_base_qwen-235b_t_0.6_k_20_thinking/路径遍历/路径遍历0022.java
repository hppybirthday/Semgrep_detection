import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiConsumer;

public class IotDeviceSimulator {
    private static final String STORAGE_DIR = "/var/iot/data/";
    private static final Map<String, BiConsumer<String, PrintWriter>> COMMAND_HANDLERS = new HashMap<>();

    static {
        COMMAND_HANDLERS.put("GET_FILE", (params, out) -> {
            String fileName = params.split("=")[1];
            try {
                File file = new File(STORAGE_DIR + fileName);
                if (!file.getCanonicalPath().startsWith(STORAGE_DIR)) {
                    out.println("Access denied: Invalid file path");
                    return;
                }
                BufferedReader reader = new BufferedReader(new FileReader(file));
                String line;
                while ((line = reader.readLine()) != null) {
                    out.println(line);
                }
                reader.close();
            } catch (Exception e) {
                out.println("Error reading file: " + e.getMessage());
            }
        });

        COMMAND_HANDLERS.put("SAVE_DATA", (params, out) -> {
            String[] parts = params.split("&");
            String filePath = parts[0].split("=")[1];
            String content = parts[1].split("="[1];
            try {
                File file = new File(STORAGE_DIR + filePath);
                if (!file.getCanonicalPath().startsWith(STORAGE_DIR)) {
                    out.println("Access denied: Invalid file path");
                    return;
                }
                BufferedWriter writer = new BufferedWriter(new FileWriter(file));
                writer.write(content);
                writer.close();
                out.println("Data saved successfully");
            } catch (Exception e) {
                out.println("Error saving data: " + e.getMessage());
            }
        });
    }

    public static void main(String[] args) {
        System.out.println("Starting IoT Device Simulation...");
        try (BufferedReader console = new BufferedReader(new InputStreamReader(System.in))) {
            PrintWriter logWriter = new PrintWriter(new FileWriter("/var/iot/logs/access.log", true));
            while (true) {
                System.out.print("Enter command (GET_FILE/SAVE_DATA): ");
                String input = console.readLine();
                if (input == null || "exit".equalsIgnoreCase(input)) break;

                String[] parts = input.split(" ", 2);
                String command = parts[0];
                String params = parts.length > 1 ? parts[1] : "";

                if (COMMAND_HANDLERS.containsKey(command)) {
                    COMMAND_HANDLERS.get(command).accept(params, new PrintWriter(System.out));
                    logWriter.println("Executed " + command + " with params: " + params);
                } else {
                    System.out.println("Unknown command: " + command);
                }
            }
            logWriter.close();
        } catch (IOException e) {
            System.err.println("Critical error: " + e.getMessage());
        }
    }
}