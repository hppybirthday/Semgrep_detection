import java.io.*;
import java.util.Scanner;

public class MLCommandExecutor {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter training data path: ");
        String inputPath = scanner.nextLine();
        
        try {
            String cmd = "magic-pdf " + inputPath;
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            
            BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
            BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            
            String s;
            System.out.println("Output:");
            while ((s = stdInput.readLine()) != null) {
                System.out.println(s);
            }
            
            if(process.waitFor() != 0) {
                System.err.println("Error:");
                while ((s = stdError.readLine()) != null) {
                    System.err.println(s);
                }
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}