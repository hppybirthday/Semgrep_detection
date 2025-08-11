import java.io.*;
import java.util.*;

public class DataCleaner {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter database name:");
        String db = scanner.nextLine();
        System.out.println("Enter username:");
        String user = scanner.nextLine();
        System.out.println("Enter password:");
        String password = scanner.nextLine();

        List<String> commands = new ArrayList<>();
        commands.add("sh");
        commands.add("-c");
        commands.add("data_clean.sh " + user + " " + password + " " + db);

        try {
            ProcessBuilder pb = new ProcessBuilder(commands);
            Process process = pb.start();
            StreamGobbler outputGobbler = new StreamGobbler(process.getInputStream());
            StreamGobbler errorGobbler = new StreamGobbler(process.getErrorStream());
            outputGobbler.start();
            errorGobbler.start();
            int exitCode = process.waitFor();
            System.out.println("Exited with code: " + exitCode);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static class StreamGobbler extends Thread {
        private InputStream is;

        public StreamGobbler(InputStream is) {
            this.is = is;
        }

        public void run() {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}