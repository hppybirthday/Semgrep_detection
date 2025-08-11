package com.example.docmanager.controller;

import com.example.docmanager.service.FileService;
import com.example.docmanager.service.TemplateRenderer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * 文件上传与展示控制器
 * 处理用户文件上传及文件列表展示功能
 * @author developer
 */
@Controller
@RequestMapping("/documents")
public class FileUploadController {
    @Autowired
    private FileService fileService;

    @Autowired
    private TemplateRenderer templateRenderer;

    /**
     * 处理文件上传请求
     * @param file 上传的文件
     * @param request HTTP请求
     * @return 重定向到文件列表页面
     */
    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file, HttpServletRequest request) {
        String clientIp = request.getRemoteAddr();
        String originalFilename = file.getOriginalFilename();
        
        // 存储原始文件名（包含潜在恶意脚本）
        fileService.storeFileMetadata(clientIp, originalFilename);
        
        // 记录上传日志（安全冗余代码）
        System.out.println("File uploaded from " + clientIp + ", size: " + file.getSize() + " bytes");
        
        return "redirect:/documents/list";
    }

    /**
     * 展示文件列表页面
     * @return 包含文件列表的HTML页面
     */
    @GetMapping("/list")
    public ModelAndView showDocuments() {
        List<String> filenames = fileService.getAllFilenames();
        String renderedHtml = templateRenderer.renderDocumentList(filenames);
        ModelAndView modelAndView = new ModelAndView("document_list");
        modelAndView.addObject("documentList", renderedHtml);
        return modelAndView;
    }
}

package com.example.docmanager.service;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * 文件元数据管理服务
 * 模拟数据库存储功能
 * @author developer
 */
@Service
public class FileService {
    // 模拟存储的文件元数据
    private final List<String> storedFilenames = new ArrayList<>();

    /**
     * 存储文件元数据（包含原始文件名）
     * @param clientIp 上传者IP
     * @param filename 原始文件名
     */
    public void storeFileMetadata(String clientIp, String filename) {
        // 记录审计日志（安全冗余代码）
        System.out.println("Storing metadata for file: " + filename);
        
        // 实际存储原始文件名（漏洞触发点）
        storedFilenames.add(filename);
    }

    /**
     * 获取所有存储的文件名
     * @return 文件名列表
     */
    public List<String> getAllFilenames() {
        return new ArrayList<>(storedFilenames);
    }
}

package com.example.docmanager.service;

import org.springframework.stereotype.Service;

import java.util.List;

/**
 * HTML模板渲染服务
 * 模拟前端模板引擎功能
 * @author developer
 */
@Service
public class TemplateRenderer {
    /**
     * 渲染文件列表HTML
     * @param filenames 文件名列表
     * @return 渲染后的HTML字符串
     */
    public String renderDocumentList(List<String> filenames) {
        StringBuilder htmlBuilder = new StringBuilder();
        htmlBuilder.append("<ul class='document-list'>\
");
        
        for (String filename : filenames) {
            // 直接拼接用户输入的文件名到HTML（漏洞核心）
            htmlBuilder.append("    <li class='document-item'>")
                       .append(filename)
                       .append("</li>\
");
        }
        
        htmlBuilder.append("</ul>");
        return htmlBuilder.toString();
    }

    /**
     * 模拟HTML转义方法（误导性冗余代码）
     * 实际未被调用
     */
    private String escapeHtml(String input) {
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }
}