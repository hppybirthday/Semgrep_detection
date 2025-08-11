package com.mathsim.core.controller;

import java.io.File;
import java.io.IOException;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import com.mathsim.core.service.ProjectFileService;
import com.mathsim.core.util.BladeCodeGenerator;

/**
 * 数学建模项目下载控制器
 * 提供模型文件下载功能
 */
@Controller
public class ProjectDownloadController {
    @Autowired
    private ProjectFileService projectFileService;

    /**
     * 下载项目文件接口
     * @param projectName 项目名称
     * @param filePath 文件路径
     */
    @GetMapping("/download/project")
    public void downloadProjectFile(HttpServletResponse response,
                                   @RequestParam String projectName,
                                   @RequestParam String filePath) throws IOException {
        // 构造基础目录
        String baseDir = System.getProperty("mathsim.projects.root", "/var/mathsim/projects");
        
        // 验证并处理文件路径
        File targetFile = projectFileService.resolveFilePath(baseDir, projectName, filePath);
        
        // 执行文件下载
        BladeCodeGenerator.run(targetFile.getAbsolutePath(), response.getOutputStream());
    }
}

package com.mathsim.core.service;

import java.io.File;
import java.nio.file.Paths;

import org.springframework.stereotype.Service;

/**
 * 项目文件服务类
 * 处理文件路径解析和安全检查
 */
@Service
public class ProjectFileService {
    /**
     * 解析文件路径并进行安全检查
     * @param baseDir 基础目录
     * @param projectName 项目名称
     * @param filePath 用户提供的文件路径
     * @return 处理后的文件对象
     */
    public File resolveFilePath(String baseDir, String projectName, String filePath) {
        // 替换路径分隔符为统一格式
        String normalizedPath = filePath.replace("\\\\\\\\", "/");
        
        // 移除潜在危险字符序列
        String safePath = normalizedPath.replace("../", "").replace("..\\\\", "");
        
        // 构造完整路径
        File projectDir = Paths.get(baseDir, projectName).toFile();
        return Paths.get(projectDir.getAbsolutePath(), safePath).toFile();
    }
}

package com.mathsim.core.util;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;

/**
 * 代码生成工具类
 * 执行文件读取和输出操作
 */
public class BladeCodeGenerator {
    /**
     * 执行文件读取并输出到目标流
     * @param filePath 文件路径
     * @param outputStream 输出流
     * @throws IOException
     */
    public static void run(String filePath, OutputStream outputStream) throws IOException {
        File file = new File(filePath);
        
        // 检查文件是否存在
        if (!file.exists()) {
            throw new IllegalArgumentException("File not found: " + filePath);
        }
        
        // 读取并输出文件内容
        try (InputStream inputStream = Files.newInputStream(file.toPath())) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
    }
}