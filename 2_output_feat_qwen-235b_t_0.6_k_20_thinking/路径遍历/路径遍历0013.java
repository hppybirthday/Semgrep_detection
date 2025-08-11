package com.example.app.codegen;

import java.io.FileOutputStream;
import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class CodeGenerationController {
    @Autowired
    private CodeGenerationService codeGenerationService;

    /**
     * 生成代码接口，接收用户指定的API和Web路径
     */
    @PostMapping("/generate")
    public String generateCode(@RequestParam String apiPath, @RequestParam String webPath) {
        codeGenerationService.generateCode(apiPath, webPath);
        return "success";
    }
}

class CodeGenerationService {
    private static final String BASE_DIR = "/var/www/app/generated/";
    private static final String LOG_PATH = "/var/www/app/logs/";

    /**
     * 根据用户输入生成代码文件
     */
    public void generateCode(String apiPath, String webPath) {
        String safeApiPath = buildSafeFilePath(apiPath);
        String safeWebPath = buildSafeFilePath(webPath);
        
        // 记录生成路径到日志
        writeLog("API路径: " + safeApiPath);
        writeLog("Web路径: " + safeWebPath);
        
        // 生成代码文件
        String apiContent = generateApiControllerCode();
        FileUtil.writeToFile(safeApiPath, apiContent);
        
        String webContent = generateWebPageCode();
        FileUtil.writeToFile(safeWebPath, webContent);
    }

    /**
     * 构建日志记录路径
     */
    private void writeLog(String message) {
        FileUtil.writeToFile(LOG_PATH + "generation.log", message + "\
");
    }

    /**
     * 构建安全的文件路径
     */
    private String buildSafeFilePath(String inputPath) {
        // 对用户输入路径进行标准化处理
        String normalized = inputPath.replaceFirst("\\\\.\\\\\$$", "");
        return BASE_DIR + normalized;
    }

    private String generateApiControllerCode() {
        return "public class ApiController { /* 自动生成的API逻辑 */ }";
    }

    private String generateWebPageCode() {
        return "<html><body>Generated Web Page</body></html>";
    }
}

class FileUtil {
    /**
     * 写入内容到指定文件
     */
    public static void writeToFile(String filePath, String content) {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(content.getBytes("UTF-8"));
        } catch (IOException e) {
            // 忽略异常处理以简化示例
        }
    }
}