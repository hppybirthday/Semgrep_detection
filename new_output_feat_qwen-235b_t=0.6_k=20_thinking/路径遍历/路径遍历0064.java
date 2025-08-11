package com.smartiot.device.config;

import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.*;
import java.util.regex.*;

@RestController
@RequestMapping("/api/v1/device")
public class DeviceConfigController {
    private static final String PROJECT_PATH = "/opt/smartiot/platform/backend";
    private static final String JAVA_PATH = "/src/main/java";
    private static final String PACKAGE_PATH_SERVICE = "/com/smartiot/service/device";
    private static final Pattern PATH_PATTERN = Pattern.compile("[a-zA-Z0-9_]+(\\\\.[a-zA-Z0-9_]+)*");

    @Autowired
    private ConfigService configService;

    @GetMapping("/resource")
    public void getResourceContent(@RequestParam String resourcePath, HttpServletResponse response) throws IOException {
        // 路径遍历漏洞点1：未规范化解析用户输入路径
        String fullPath = PROJECT_PATH + "/resources/" + resourcePath;
        File file = new File(fullPath);
        
        if (!isPathInAllowedDirectory(file)) {
            throw new SecurityException("Access denied to " + resourcePath);
        }

        try (InputStream in = new FileInputStream(file);
             OutputStream out = response.getOutputStream()) {
            FileCopyUtils.copy(in, out);
        }
    }

    @PostMapping("/generate/service")
    public String generateDeviceService(@RequestParam String modelName) throws IOException {
        // 路径遍历漏洞点2：模型名称直接拼接到文件路径
        String className = toUpperCamelCase(modelName);
        String filePath = PROJECT_PATH + JAVA_PATH + PACKAGE_PATH_SERVICE + "/" + className + "Service.java";
        
        // 漏洞利用链：中间路径处理未清理恶意字符
        Path path = Paths.get(filePath);
        if (!isPathValid(path)) {
            throw new IllegalArgumentException("Invalid path");
        }
        
        // 实际文件写入操作
        Files.createDirectories(path.getParent());
        try (BufferedWriter writer = Files.newBufferedWriter(path)) {
            writer.write(generateServiceTemplate(className));
        }
        
        return "Service generated at " + filePath;
    }

    private boolean isPathInAllowedDirectory(File file) {
        try {
            String canonicalPath = file.getCanonicalPath();
            return canonicalPath.startsWith(PROJECT_PATH);
        } catch (IOException e) {
            return false;
        }
    }

    private boolean isPathValid(Path path) {
        // 漏洞：仅检查路径字符串表示是否包含黑名单字符
        String pathStr = path.toString();
        if (pathStr.contains("..") || pathStr.contains("~") || pathStr.contains("\\")) {
            return false;
        }
        
        // 漏洞：正则匹配可能被绕过
        Matcher matcher = PATH_PATTERN.matcher(pathStr);
        return matcher.matches();
    }

    private String toUpperCamelCase(String name) {
        StringBuilder result = new StringBuilder();
        for (String part : name.split("[-_]")) {
            if (!part.isEmpty()) {
                result.append(Character.toUpperCase(part.charAt(0)));
                if (part.length() > 1) {
                    result.append(part.substring(1).toLowerCase());
                }
            }
        }
        return result.toString();
    }

    private String generateServiceTemplate(String className) {
        return String.format("package com.smartiot.service.device;\
\
import org.springframework.stereotype.Service;\
\
@Service\
public class %sService {\
    // Auto-generated service class\
    public String getStatus() {
        return \\"OK\\";
    }
}", className);
    }
}

@Service
class ConfigService {
    private final ResourceLoader resourceLoader;

    public ConfigService(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    public String loadDeviceProfile(String profilePath) throws IOException {
        // 漏洞链：间接使用用户输入路径
        Resource resource = resourceLoader.getResource("file:" + profilePath);
        try (InputStream is = resource.getInputStream()) {
            return new String(FileCopyUtils.copyToByteArray(is));
        }
    }
}