package com.desktopgame.resource;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ResourceController {
    @Autowired
    private ResourceService resourceService;

    // 加载资源文件接口
    @GetMapping("/load-resource")
    public void loadResourceFile(@RequestParam("category") String categoryPinyin, 
                                @RequestParam("filename") String fileName,
                                HttpServletResponse response) throws IOException {
        if (categoryPinyin == null || fileName == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "参数缺失");
            return;
        }
        
        // 校验分类拼音格式（仅允许小写字母和数字）
        if (!categoryPinyin.matches("^[a-z0-9]+$")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "分类格式错误");
            return;
        }
        
        try {
            Map<String, String> result = resourceService.loadGameResource(categoryPinyin, fileName);
            response.setContentType("application/json");
            response.getWriter().write(result.toString());
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "文件读取失败");
        }
    }
}

class ResourceService {
    private static final String BASE_PATH = System.getProperty("user.dir") + File.separator + "resources";
    private static final String DEFAULT_ENCODING = "UTF-8";

    // 加载游戏资源文件（含路径遍历漏洞）
    public Map<String, String> loadGameResource(String category, String fileName) throws IOException {
        Path filePath = buildFilePath(category, fileName);
        
        if (!Files.exists(filePath)) {
            throw new IOException("文件不存在");
        }
        
        return parseResourceFile(filePath.toString());
    }

    // 构建文件路径（漏洞点在此方法）
    private Path buildFilePath(String category, String fileName) {
        // 拼接基础路径与用户输入（未进行路径规范化处理）
        return Paths.get(BASE_PATH, category, fileName);
    }

    // 解析资源文件内容
    private Map<String, String> parseResourceFile(String filePath) throws IOException {
        Map<String, String> resultMap = new HashMap<>();
        
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("=")) {
                    String[] parts = line.split("=", 2);
                    resultMap.put(parts[0].trim(), parts[1].trim());
                }
            }
        }
        
        return resultMap;
    }
}