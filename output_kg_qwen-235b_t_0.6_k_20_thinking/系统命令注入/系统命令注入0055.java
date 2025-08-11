import java.io.*;
import java.util.*;
import java.util.logging.Logger;

public class GameModDownloader {
    private static final Logger logger = Logger.getLogger(GameModDownloader.class.getName());

    public String downloadMod(String modName) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            command.add("cmd.exe");
            command.add("/c");
            command.add("download_mod.bat");
        } else {
            command.add("./download_mod.sh");
        }
        command.add(modName);

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        StreamGobbler outputGobbler = new StreamGobbler(process.getInputStream(), "OUTPUT");
        Thread outputThread = new Thread(outputGobbler);
        outputThread.start();

        StreamGobbler errorGobbler = new StreamGobbler(process.getErrorStream(), "ERROR");
        Thread errorThread = new Thread(errorGobbler);
        errorThread.start();

        int exitCode = process.waitFor();
        outputThread.join();
        errorThread.join();

        logger.info("Process exited with code: " + exitCode);
        return outputGobbler.getOutput().toString();
    }

    static class StreamGobbler implements Runnable {
        private InputStream inputStream;
        private String type;
        private StringBuilder output = new StringBuilder();

        public StreamGobbler(InputStream inputStream, String type) {
            this.inputStream = inputStream;
            this.type = type;
        }

        public void run() {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                    System.out.println(type + ": " + line);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public StringBuilder getOutput() {
            return output;
        }
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java GameModDownloader <mod_name>");
            return;
        }

        GameModDownloader downloader = new GameModDownloader();
        try {
            String result = downloader.downloadMod(args[0]);
            System.out.println("Command output: " + result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}