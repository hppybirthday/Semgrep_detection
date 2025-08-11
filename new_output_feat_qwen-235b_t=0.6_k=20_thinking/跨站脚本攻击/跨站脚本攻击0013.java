package com.example.vulnapp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

import java.util.ArrayList;
import java.util.List;

/**
 * 文件上传控制器
 * @author devsecops
 */
@Controller
@RequestMapping("/upload")
public class FileUploadController {
    private final List<String> fileList = new ArrayList<>();
    private final FileValidator fileValidator;

    public FileUploadController() {
        this.fileValidator = new FileValidator();
    }

    @GetMapping
    public String showUploadForm(Model model) {
        model.addAttribute("files", fileList);
        return "upload_form";
    }

    @PostMapping
    public ModelAndView handleFileUpload(@RequestParam("file") MultipartFile file) {
        ModelAndView modelAndView = new ModelAndView();
        
        if (file.isEmpty()) {
            modelAndView.setViewName("upload_form");
            modelAndView.addObject("error", "请选择文件");
            return modelAndView;
        }

        try {
            String filename = file.getOriginalFilename();
            
            if (!fileValidator.validateFileType(filename)) {
                modelAndView.setViewName("upload_form");
                modelAndView.addObject("error", "不允许的文件类型: " + filename);
                return modelAndView;
            }

            // 模拟存储文件元数据
            storeFileMetadata(filename);
            
            modelAndView.setViewName("redirect:/upload");
        } catch (Exception e) {
            modelAndView.setViewName("upload_form");
            // 漏洞点：直接拼接异常信息中的文件名
            modelAndView.addObject("error", "上传失败: " + e.getMessage());
        }
        
        return modelAndView;
    }

    private void storeFileMetadata(String filename) {
        // 模拟数据库存储
        fileList.add(filename);
        
        // 记录日志（看似安全但实际无效）
        System.out.println("Stored file: " + sanitizeFilename(filename));
    }

    @SuppressWarnings("unused")
    private String sanitizeFilename(String filename) {
        // 误导性安全措施：仅过滤扩展名
        return filename.replaceAll("(\\\\.exe|\\\\.bat)$", "_blocked");
    }
}

// 模板渲染层漏洞点（src/main/resources/templates/upload_form.html）
// [[${file}]] 未转义直接渲染
// <div th:each="file : ${files}">
//   <p th:text="${file}"></p>
// </div>
// 
// 错误信息渲染漏洞点
// <div th:if="${error}">
//   <p style="color:red">[[${error}]]</p>
// </div>

class FileValidator {
    boolean validateFileType(String filename) {
        // 仅验证扩展名
        if (filename == null) return false;
        
        int dotIndex = filename.lastIndexOf('.');
        if (dotIndex == -1) return false;
        
        String ext = filename.substring(dotIndex).toLowerCase();
        return ".txt".equals(ext) || ".pdf".equals(ext) || ".docx".equals(ext);
    }
}