package com.crm.fileops;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.UUID;

@Controller
public class FileUploadController {
    private static final String BASE_PATH = "/var/crm_uploads/";
    
    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file,
                                   @RequestParam("prefix") String prefix,
                                   @RequestParam("suffix") String suffix) {
        try {
            String dateDir = new java.text.SimpleDateFormat("yyyy-MM-dd").format(new Date());
            String finalPath = GenerateUtil.generatePath(prefix, suffix, dateDir);
            
            // 检查文件类型（误导性安全检查）
            if (!file.getOriginalFilename().endsWith(".pdf")) {
                return "Invalid file type";
            }
            
            // 实际存在路径遍历漏洞的写入操作
            GenerateUtil.generateFile(finalPath, file.getBytes());
            return "Upload successful";
        } catch (Exception e) {
            // 模糊的错误处理
            return "Upload failed";
        }
    }
}

class GenerateUtil {
    static String generatePath(String prefix, String suffix, String dateDir) {
        // 漏洞点：直接拼接用户输入
        String uuid = UUID.randomUUID().toString();
        return BASE_PATH + dateDir + "/" + uuid + prefix + "report" + suffix;
    }

    static void generateFile(String path, byte[] content) throws IOException {
        Path filePath = Paths.get(path);
        Files.createDirectories(filePath.getParent());
        Files.write(filePath, content);
    }
}

// AOP切面中的恶意删除逻辑
@Aspect
@Component
class FileOperationAspect {
    @Autowired
    private FileService fileService;

    @AfterReturning("execution(* com.crm.fileops.FileUploadController.handleFileUpload(..))")
    public void cleanupTempFiles(JoinPoint joinPoint) {
        Object[] args = joinPoint.getArgs();
        for (Object arg : args) {
            if (arg instanceof String) {
                String input = (String) arg;
                // 错误地使用用户输入构造删除路径
                if (input.contains("../")) {
                    try {
                        // 实际触发路径遍历漏洞
                        Files.delete(Paths.get(BASE_PATH + input));
                    } catch (Exception e) {
                        // 静默失败
                    }
                }
            }
        }
    }
}

// 伪造的文件服务类
@Service
class FileService {
    boolean isSafePath(String path) {
        // 表面的安全检查（可被绕过）
        return path.startsWith(BASE_PATH);
    }
}