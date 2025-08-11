import java.io.*;
import java.nio.file.*;

public class FileMerger {
    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java FileMerger <prefix> <suffix> <output>");
            return;
        }
        mergeFiles(args[0], args[1], args[2]);
    }

    static void mergeFiles(String prefix, String suffix, String output) {
        try {
            Path tempDir = Files.createTempDirectory("iot_upload_");
            
            // Simulate shard upload
            Files.write(tempDir.resolve("part1.tmp"), "SensorData1".getBytes());
            Files.write(tempDir.resolve("part2.tmp"), "SensorData2".getBytes());
            
            // Vulnerable path construction
            Path basePath = Paths.get("/var/iot/storage").toRealPath();
            Path targetPath = basePath.resolve(prefix + "_merged_" + suffix);
            
            // Security check bypass
            if (!targetPath.normalize().startsWith(basePath)) {
                System.err.println("Path traversal attempt blocked!");
                return;
            }
            
            // Vulnerable file merge
            try (BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(targetPath.toFile()))) {
                Files.list(tempDir).forEach(p -> {
                    try {
                        Files.copy(p, out);
                        Files.delete(p);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            }
            
            System.out.println("Merged to: " + targetPath);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}