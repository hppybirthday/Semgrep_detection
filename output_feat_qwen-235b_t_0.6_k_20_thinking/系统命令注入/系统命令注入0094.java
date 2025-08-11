import java.io.*;
import java.util.*;
import java.util.concurrent.*;

public class TimerCommandExecutor {
    private String userInput;

    public void setUserInput(String input) {
        this.userInput = input;
    }

    public void schedulePingTask() {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        Runnable task = () -> {
            try {
                if (containsInvalidChars(userInput)) {
                    System.out.println("Invalid input detected!");
                    return;
                }
                ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", "ping 127.0.0.1 -n " + userInput);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
                
                int exitCode = process.waitFor();
                System.out.println("Exited with code " + exitCode);
                
            } catch (Exception e) {
                e.printStackTrace();
            }
        };
        
        scheduler.scheduleAtFixedRate(task, 0, 5, TimeUnit.SECONDS);
    }
    
    private boolean containsInvalidChars(String input) {
        if (input == null || input.isEmpty()) return false;
        return input.contains(";") || input.contains("&&") || 
               input.contains("|") || input.contains("||");
    }

    public static void main(String[] args) {
        TimerCommandExecutor executor = new TimerCommandExecutor();
        executor.setUserInput("1");
        executor.schedulePingTask();
    }
}