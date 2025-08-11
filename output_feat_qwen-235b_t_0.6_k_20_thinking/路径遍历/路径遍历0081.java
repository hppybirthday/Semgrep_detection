import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/crawl")
public class VulnerableCrawler {
    
    @Value("${storage.base-path:/var/www/crawl_data}")
    private String basePath;
    
    @GetMapping("/view")
    public String viewContent(@RequestParam String path, @RequestParam String id) throws Exception {
        // 路径拼接时未正确处理用户输入
        Path targetPath = Paths.get(basePath, path, id + ".html");
        
        // 直接检查文件存在性而不进行规范化
        if(Files.exists(targetPath)) {
            return new String(Files.readAllBytes(targetPath));
        }
        return "File not found";
    }
    
    // 模拟AOP切面文件操作
    @Aspect
    @Component
    public class FileCleanupAspect {
        @AfterReturning("execution(* com.example.crawler.VulnerableCrawler.viewContent(..))")
        public void cleanupTempFiles() {
            try {
                // 存在路径遍历风险的删除操作
                Path tempDir = Paths.get(basePath, "../temp");
                if(Files.exists(tempDir)) {
                    Files.walk(tempDir)
                        .sorted(Comparator.reverseOrder())
                        .forEach(path -> {
                            try { Files.delete(path); }
                            catch (Exception e) { /* 忽略异常 */ }
                        });
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    
    // 模拟文件存储初始化
    @PostConstruct
    public void init() throws Exception {
        Files.createDirectories(Paths.get(basePath));
    }
}