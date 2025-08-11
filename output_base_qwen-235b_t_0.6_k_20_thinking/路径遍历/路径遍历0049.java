import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.util.*;

interface FileStorage {
    void saveContent(String relativePath, byte[] content) throws IOException;
}

class LocalFileStorage implements FileStorage {
    private final String baseDir;

    public LocalFileStorage(String baseDir) {
        this.baseDir = baseDir;
    }

    @Override
    public void saveContent(String relativePath, byte[] content) throws IOException {
        // 漏洞点：未正确处理路径穿越字符
        Path targetPath = Paths.get(baseDir, relativePath).normalize();
        try (OutputStream os = new FileOutputStream(targetPath.toAbsolutePath().toString())) {
            os.write(content);
        }
    }
}

class SpiderEngine {
    private final FileStorage storage;

    public SpiderEngine(FileStorage storage) {
        this.storage = storage;
    }

    public void processUrl(String urlString) throws Exception {
        URL url = new URL(urlString);
        String path = url.getPath().replaceAll("^/", "");
        
        // 模拟爬取内容
        byte[] content = String.format("<!DOCTYPE html><html>Mocked content from %s</html>", urlString).getBytes();
        
        storage.saveContent(path, content);
    }
}

public class VulnerableSpider {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java VulnerableSpider <URL>");
            return;
        }

        try {
            FileStorage storage = new LocalFileStorage("/var/www/html/archive");
            SpiderEngine engine = new SpiderEngine(storage);
            engine.processUrl(args[0]);
            System.out.println("Page archived successfully");
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}