import java.io.*;
import java.net.*;
import java.util.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
public class SsrfVulnerableApp {
    public static void main(String[] args) {
        SpringApplication.run(SsrfVulnerableApp.class, args);
    }
}

@RestController
class ImageProcessingController {
    @GetMapping("/process")
    public String processImage(@RequestParam String requestUrl) throws Exception {
        ImageProcessor processor = new ImageProcessor();
        return processor.process(requestUrl);
    }
}

class ImageProcessor {
    String process(String requestUrl) throws Exception {
        URL url = new URL(requestUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        // 模拟处理图片数据流
        try (InputStream is = connection.getInputStream()) {
            byte[] imageData = readStream(is);
            // 模拟上传到内部存储系统
            return "Processed image size: " + imageData.length + " bytes";
        }
    }

    private byte[] readStream(InputStream is) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[16384];
        while ((nRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        return buffer.toByteArray();
    }
}

// 模拟企业级服务的元编程特性
interface ImageService {
    default String execute(String... args) {
        try {
            return new ImageProcessor().process(args[0]);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

@Component
class DynamicServiceInvoker {
    public String invokeService(String serviceName, String... args) {
        try {
            Class<?> clazz = Class.forName(serviceName);
            ImageService service = (ImageService) clazz.getDeclaredConstructor().newInstance();
            return service.execute(args);
        } catch (Exception e) {
            return "Invocation error: " + e.getMessage();
        }
    }
}