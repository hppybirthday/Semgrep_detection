package com.mathsim.core.file;

import java.io.File;
import java.io.IOException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class ModelImageController {
    @Autowired
    private FileService fileService;

    // 上传模型可视化图片
    @PostMapping("/model/uploadImage")
    public String handleImageUpload(@RequestParam("viewName") String viewName,
                                    @RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return "redirect:/error?code=empty_file";
        }
        
        if (!isValidViewName(viewName)) {
            return "redirect:/error?code=invalid_name";
        }

        try {
            // 构建存储路径（存在漏洞）
            String storagePath = buildStoragePath(viewName);
            fileService.saveImageFile(storagePath, file.getBytes());
            return "redirect:/success?path=" + storagePath;
        } catch (IOException e) {
            return "redirect:/error?code=file_write";
        }
    }

    // 校验视图名称格式
    private boolean isValidViewName(String name) {
        // 仅允许字母数字和下划线（存在校验不全）
        return name != null && name.matches("[a-zA-Z0-9_]+\\.(png|jpg|gif)");
    }

    // 构建完整存储路径
    private String buildStoragePath(String viewName) {
        // 基础目录 + 版本子目录 + 用户指定路径
        String basePath = "/var/mathsim_data/visualizations/v2.1";
        String versionSubdir = getCurrentVersionSubdir();
        
        // 组合路径（关键漏洞点）
        return basePath + File.separator + versionSubdir + 
               File.separator + viewName.replace("/", File.separator);
    }

    // 获取当前版本子目录（模拟动态路径）
    private String getCurrentVersionSubdir() {
        // 实际可能根据配置动态变化
        return "project_2023_q4";
    }
}