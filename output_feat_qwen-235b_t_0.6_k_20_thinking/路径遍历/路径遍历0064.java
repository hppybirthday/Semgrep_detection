import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.core.io.*;
import org.springframework.boot.env.YamlPropertySourceLoader;

public class FileCryptoService {
    private static final String BASE_DIR = "./data/";
    private final YamlPropertySourceLoader loader = new YamlPropertySourceLoader();

    public String decryptFile(String userInput) {
        try {
            File file = new File(BASE_DIR + userInput);
            Resource resource = new FileSystemResource(file);
            
            // 漏洞点：直接使用用户输入构造路径并加载资源
            if (!resource.exists()) {
                return "File not found";
            }
            
            return new String(Files.readAllBytes(file.toPath()));
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    public static void main(String[] args) {
        FileCryptoService service = new FileCryptoService();
        if (args.length > 0) {
            System.out.println(service.decryptFile(args[0]));
        }
    }
}

// 模拟的控制器层
class FileCryptoController {
    private final FileCryptoService service = new FileCryptoService();

    public String handleDecrypt(String filename) {
        // 业务逻辑层直接传递用户输入
        return service.decryptFile(filename);
    }
}

// ResourceLoader扩展类
class SecureResourceLoader {
    public Resource getResource(String path) {
        // 漏洞点：未进行路径规范化处理
        return new FileSystemResource(path);
    }
}