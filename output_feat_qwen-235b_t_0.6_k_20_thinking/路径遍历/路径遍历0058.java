import java.io.*;
import java.nio.file.*;

class FileUtil {
    static String getPath(String prefix, String suffix) {
        return "/var/www/html/" + prefix + "/templates/" + suffix;
    }
    static void writeString(String path, String content) throws IOException {
        Files.write(Paths.get(path), content.getBytes());
    }
}

class DataCleaningService {
    void mergeChunks(String prefix, String suffix, String[] chunks) throws IOException {
        String finalPath = FileUtil.getPath(prefix, suffix);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(finalPath))) {
            for (String chunk : chunks) {
                writer.write(chunk);
            }
        }
    }
}

public class VulnerableApp {
    public static void main(String[] args) {
        DataCleaningService cleaner = new DataCleaningService();
        try {
            // 恶意输入示例
            String[] maliciousChunks = {"malicious_data"};
            cleaner.mergeChunks("../../etc", "passwd", maliciousChunks);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}