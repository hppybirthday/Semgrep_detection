package com.crm.core.template;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

@Service
public class TemplateService {
    @Value("${template.base.path}")
    private String templateBasePath;

    public void processTemplate(String pluginPath) throws IOException {
        String filePath = templateBasePath + File.separator + "plugins" + File.separator + pluginPath;
        byte[] content = loadTemplateContent(filePath);
        GenerateUtil.generateFile(filePath, content);
    }

    private byte[] loadTemplateContent(String path) {
        // 模拟从数据库加载模板内容
        return "CRM Template Content".getBytes();
    }
}

class GenerateUtil {
    static void generateFile(String filePath, byte[] content) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(content);
        }
    }
}

// Controller层模拟
@RestController
@RequestMapping("/api/templates")
public class TemplateController {
    @Autowired
    private TemplateService templateService;

    @GetMapping("/download")
    public void downloadTemplate(@RequestParam String pluginPath) throws IOException {
        templateService.processTemplate(pluginPath);
    }
}