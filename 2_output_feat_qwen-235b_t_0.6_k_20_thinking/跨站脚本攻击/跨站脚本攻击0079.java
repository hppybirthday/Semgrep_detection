package com.example.filesecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
import java.util.List;

/**
 * 文件加密控制器，处理用户加密请求并展示结果。
 */
@Controller
public class FileEncryptController {

    // 模拟存储用户提交的加密内容
    private static final List<String> USER_SUBMISSIONS = new ArrayList<>();

    /**
     * 处理加密请求，保存用户输入并返回结果页面。
     */
    @GetMapping("/encrypt")
    public String handleEncryption(@RequestParam String content, Model model) {
        // 保存用户输入用于后续展示
        USER_SUBMISSIONS.add(content);
        // 添加属性到模型以供结果页面使用
        model.addAttribute("userContent", content);
        return "encryptionResult";
    }

    /**
     * 管理界面展示所有用户提交的内容。
     */
    @GetMapping("/admin/submissions")
    public String viewSubmissions(Model model) {
        model.addAttribute("submissions", USER_SUBMISSIONS);
        return "submissionList";
    }
}