import java.io.*;
import java.nio.file.*;
import java.util.function.*;

@FunctionalInterface
interface FileMerger {
    void mergeFiles(String categoryPinyin, byte[] fileChunk) throws Exception;
}

public class IoTDeviceFileManager {
    private static final String BASE_PATH = "/var/iot_data/";
    private static final int MAX_CHUNK_SIZE = 1024 * 1024;

    public static void main(String[] args) {
        FileMerger merger = (categoryPinyin, fileChunk) -> {
            try {
                String fullPath = BASE_PATH + categoryPinyin;
                File targetDir = new File(fullPath);
                if (!targetDir.exists()) {
                    targetDir.mkdirs();
                }

                Path tempPath = Files.createTempFile(targetDir.toPath(), "chunk_", ".tmp");
                FileCopyUtils.copy(fileChunk, tempPath.toFile());

                System.out.println("File saved to: " + tempPath.toString());
                
                // 模拟合并操作
                if (Files.size(tempPath) < MAX_CHUNK_SIZE) {
                    Path finalPath = Paths.get(fullPath + "/final_data.bin");
                    Files.write(finalPath, fileChunk, StandardOpenOption.APPEND);
                }

            } catch (Exception e) {
                System.err.println("File merge error: " + e.getMessage());
                throw e;
            }
        };

        // 模拟攻击输入
        String maliciousInput = "../../../../etc/passwd";
        byte[] attackPayload = "root:x:0:0:root:/root:/bin/bash".getBytes();
        
        try {
            merger.mergeFiles(maliciousInput, attackPayload);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class FileCopyUtils {
    public static void copy(byte[] source, File dest) throws IOException {
        try (OutputStream out = new FileOutputStream(dest)) {
            out.write(source);
        }
    }
}