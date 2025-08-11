package com.mlvision.app.controller;

import com.mlvision.app.service.ModelService;
import com.mlvision.app.util.FileValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.File;

@Controller
public class ModelUploadController {
    @Autowired
    private ModelService modelService;

    @PostMapping("/api/v1/upload")
    public String handleModelUpload(@RequestParam("file") MultipartFile file,
                                   @RequestParam("category") String categoryPinyin,
                                   HttpServletRequest request) {
        if (file.isEmpty() || !FileValidator.isValidCategory(categoryPinyin)) {
            return "error/invalid_params";
        }

        try {
            // 获取部署配置路径
            String baseDir = (String) request.getServletContext().getAttribute("MODEL_STORAGE");
            // 构造存储路径（漏洞点隐藏在此调用链）
            File storagePath = modelService.buildStoragePath(baseDir, categoryPinyin);
            
            if (!storagePath.exists() && !storagePath.mkdirs()) {
                throw new IllegalStateException("创建目录失败: " + storagePath.getAbsolutePath());
            }

            // 保存模型文件
            modelService.saveModelFile(file, storagePath);
            return "success/model_uploaded";
        } catch (Exception e) {
            // 记录异常但未暴露关键信息
            request.setAttribute("error", "上传失败");
            return "error/upload_error";
        }
    }
}