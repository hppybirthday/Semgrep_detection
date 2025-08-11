package com.example.vulnerableapp;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

@Controller
public class FileViewController {
    // 基础目录配置（看似安全的限制）
    private static final String BASE_DIR = "/var/www/html/files/";

    @GetMapping("/view")
    public String viewFile(@RequestParam String filename, Model model) {
        try {
            // 漏洞点：直接拼接用户输入到文件路径
            Path targetPath = Paths.get(BASE_DIR + filename);
            
            // 尝试防御：检查文件是否存在
            if (!Files.exists(targetPath)) {
                model.addAttribute("error", "File not found");
                return "error";
            }
            
            // 二次验证：确保路径在允许目录内（存在绕过可能）
            if (!targetPath.normalize().startsWith(BASE_DIR)) {
                model.addAttribute("error", "Access denied");
                return "error";
            }
            
            // 漏洞利用：读取任意文件内容
            List<String> content = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(
                 new FileReader(targetPath.toFile()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    content.add(line);
                }
            }
            
            model.addAttribute("filename", filename);
            model.addAttribute("content", content);
            return "fileview";
            
        } catch (IOException e) {
            model.addAttribute("error", "File access error: " + e.getMessage());
            return "error";
        } catch (Exception e) {
            model.addAttribute("error", "Unexpected error: " + e.getClass().getName());
            return "error";
        }
    }

    // 用于展示文件列表的辅助方法（可能被利用发现路径）
    @GetMapping("/list")
    public String listFiles(Model model) {
        try {
            List<String> files = new ArrayList<>();
            Files.list(Paths.get(BASE_DIR))
                 .filter(Files::isRegularFile)
                 .map(path -> path.getFileName().toString())
                 .forEach(files::add);
            
            model.addAttribute("files", files);
            return "filelist";
            
        } catch (IOException e) {
            model.addAttribute("error", "Directory access error");
            return "error";
        }
    }
}