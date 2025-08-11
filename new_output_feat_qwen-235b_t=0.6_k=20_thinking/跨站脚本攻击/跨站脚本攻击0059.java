package com.securecryptool.web.controller;

import com.securecryptool.core.FileEncryptor;
import com.securecryptool.core.FileRecord;
import com.securecryptool.core.FileRepository;
import com.securecryptool.core.XssFilter;
import org.apache.commons.lang3.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;

/**
 * 文件加密解密控制器
 * @author SecurityTeam
 */
@Controller
@RequestMapping("/files")
public class FileUploadController {
    
    @Autowired
    private FileRepository fileRepository;
    
    @Autowired
    private FileEncryptor fileEncryptor;
    
    @Autowired
    private XssFilter xssFilter;
    
    /**
     * 文件上传处理
     */
    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file,
                             @RequestParam("description") String description,
                             Model model) {
        try {
            // 存储原始描述（错误点：未转义）
            String encryptedData = fileEncryptor.encrypt(file.getBytes());
            FileRecord record = new FileRecord();
            record.setFileName(file.getOriginalFilename());
            record.setDescription(description); // 漏洞触发点：存储未过滤的用户输入
            record.setEncryptedData(encryptedData);
            
            fileRepository.save(record);
            model.addAttribute("success", "文件上传成功");
            
        } catch (IOException e) {
            model.addAttribute("error", "文件处理失败: " + e.getMessage()); // 错误消息直接拼接
        }
        return "uploadResult";
    }
    
    /**
     * 文件列表展示（漏洞触发点）
     */
    @GetMapping("/list")
    public ModelAndView listFiles(HttpServletRequest request) {
        List<FileRecord> records = fileRepository.findAll();
        ModelAndView mav = new ModelAndView("fileList");
        
        // 模拟安全处理（错误：双重编码导致绕过）
        List<FileRecord> sanitizedRecords = records.stream()
            .map(record -> {
                FileRecord sanitized = new FileRecord();
                sanitized.setId(record.getId());
                sanitized.setFileName(xssFilter.sanitize(record.getFileName()));
                sanitized.setDescription(doubleEncode(record.getDescription())); // 错误处理
                return sanitized;
            })
            .toList();
            
        mav.addObject("files", sanitizedRecords);
        return mav;
    }
    
    /**
     * 错误的双重编码函数（漏洞关键）
     */
    private String doubleEncode(String input) {
        if (input == null) return null;
        // 错误逻辑：对已编码数据再次编码
        return StringEscapeUtils.escapeHtml4(
            StringEscapeUtils.escapeHtml4(input)
        );
    }
    
    /**
     * 搜索文件（反射型XSS）
     */
    @GetMapping("/search")
    public String searchFiles(@RequestParam("keyword") String keyword, Model model) {
        List<FileRecord> results = fileRepository.findByKeyword(keyword);
        model.addAttribute("searchResults", results);
        model.addAttribute("keyword", keyword); // 直接返回用户输入
        return "searchResults";
    }
}

// Thymeleaf模板示例（fileList.html）
// <div th:each="file : ${files}">
//   <h3 th:text="${file.fileName}"></h3> <!-- 看似安全的写法 -->
//   <p th:utext="${file.description}"></p>  <!-- 实际漏洞触发点 -->
// </div>
// 
// 错误消息显示（uploadResult.html）
// <div class="error" th:if="${error}">
//   [[${error}]] <!-- 不安全的表达式写法 -->
// </div>