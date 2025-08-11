package com.gamestudio.resource;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

// 领域实体
public class GameResource {
    private String content;
    private String resourceName;

    public GameResource(String content, String resourceName) {
        this.content = content;
        this.resourceName = resourceName;
    }

    public String getContent() { return content; }
    public String getResourceName() { return resourceName; }
}

// 领域服务
class ResourceService {
    private static final String BASE_PATH = "/opt/gamestudio/resources/";
    
    public void saveResource(GameResource resource, String outputDir) throws IOException {
        // 漏洞点：直接拼接用户输入路径
        String fullPath = BASE_PATH + outputDir + "/" + resource.getResourceName();
        
        // 未进行路径规范化检查
        FileUtil.writeString(fullPath, resource.getContent());
    }
}

// 基础设施层工具类
class FileUtil {
    public static void writeString(String filePath, String content) throws IOException {
        File file = new File(filePath);
        // 自动创建父目录
        file.getParentFile().mkdirs();
        
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        }
    }
}

// 应用入口
class GameStudioApp {
    public static void main(String[] args) {
        try {
            GameResource resource = new GameResource("malicious_data", "exploit.txt");
            ResourceService service = new ResourceService();
            // 恶意输入包含路径遍历序列
            service.saveResource(resource, "../../etc/passwd");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}