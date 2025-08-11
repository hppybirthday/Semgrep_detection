package com.example.filemanager.controller;

import com.example.filemanager.service.FileService;
import com.example.filemanager.util.PathUtil;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;

@Controller
@RequestMapping("/plugin")
public class PluginController {
    @Autowired
    private FileService fileService;

    @GetMapping("/config/{categoryPinyin}")
    public ModelAndView loadPluginConfig(@PathVariable String categoryPinyin) throws IOException {
        // 业务需求：根据拼音分类加载插件配置文件
        String basePath = "/opt/app/plugins/configs";
        String safePath = PathUtil.normalizePath(categoryPinyin);
        
        // 漏洞点：未验证规范化路径是否超出基础目录
        File configFile = new File(basePath, safePath + "/config.json");
        
        if (!configFile.exists()) {
            return new ModelAndView("error/404");
        }

        ModelAndView modelAndView = new ModelAndView("plugin/config");
        modelAndView.addObject("content", Files.readAllLines(configFile.toPath()));
        return modelAndView;
    }

    @PostMapping("/delete")
    public @ResponseBody String deletePlugin(@RequestParam String categoryPinyin) {
        try {
            String basePath = "/opt/app/plugins";
            // 多层调用隐藏漏洞
            String pluginPath = fileService.getPluginPath(categoryPinyin);
            File targetDir = new File(basePath, pluginPath);
            
            // 看似安全的检查
            if (!targetDir.getAbsolutePath().startsWith(basePath)) {
                return "Invalid path";
            }
            
            // 实际漏洞触发点：路径遍历删除任意目录
            FileUtils.deleteQuietly(targetDir);
            return "Deleted successfully";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    @GetMapping("/download")
    public void downloadPlugin(HttpServletResponse response, @RequestParam String categoryPinyin) throws IOException {
        String basePath = "/opt/app/plugins/archives";
        String safePath = categoryPinyin.replace("../", "").trim(); // 不彻底的过滤
        File zipFile = new File(basePath, safePath + ".zip");
        
        if (!zipFile.exists()) {
            response.sendError(404);
            return;
        }
        
        response.setContentType("application/zip");
        response.setHeader("Content-Disposition", "attachment; filename=" + zipFile.getName());
        
        // 漏洞利用：通过../../路径读取任意文件
        try (FileInputStream fis = new FileInputStream(zipFile)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
        }
    }
}