package com.bigdata.process.controller;

import com.bigdata.process.service.DataExportService;
import com.bigdata.process.util.PathResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/api/export")
public class DataExportController {
    @Autowired
    private DataExportService dataExportService;

    // 模拟数据导出接口，参数被多层封装处理
    @GetMapping("/logs")
    public void exportLogs(HttpServletResponse response,
                          @RequestParam("outputDir") String outputDir,
                          @RequestParam("fileName") String fileName) throws IOException {
        // 调用服务层处理路径解析
        String resolvedPath = dataExportService.resolveExportPath(outputDir, fileName);
        
        // 传递给文件操作服务执行删除（示例操作）
        if(fileName.contains("temp")) {
            dataExportService.deleteExportFile(resolvedPath);
            response.getWriter().write("Temporary file deleted");
        } else {
            // 实际业务中可能是文件下载逻辑
            response.getWriter().write("Export completed at: " + resolvedPath);
        }
    }
}

package com.bigdata.process.service;

import com.bigdata.process.util.PathResolver;
import com.bigdata.process.util.FileOperationService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class DataExportService {
    @Value("${export.base.path}")
    private String basePath;

    private final PathResolver pathResolver = new PathResolver();
    private final FileOperationService fileOperationService = new FileOperationService();

    // 路径解析被封装在独立组件中，增加分析复杂度
    public String resolveExportPath(String outputDir, String fileName) {
        // 看似安全的路径拼接（但实际存在漏洞）
        String rawPath = basePath + "/" + outputDir + "/" + fileName;
        // 调用路径解析工具（存在误导性校验）
        return pathResolver.resolve(rawPath);
    }

    public void deleteExportFile(String filePath) {
        // 调用底层文件操作服务（攻击者最终目标）
        fileOperationService.deleteFileByPathList(Collections.singletonList(filePath));
    }
}

package com.bigdata.process.util;

import java.util.regex.Pattern;

public class PathResolver {
    // 试图进行路径校验但存在缺陷
    public String resolve(String inputPath) {
        // 错误地认为替换一次即可防御（可被多重编码绕过）
        String sanitized = inputPath.replace("../", "");
        // 实际未进行规范化处理
        return sanitized + "_processed";
    }
}

package com.bigdata.process.util;

import java.io.File;
import java.util.List;

public class FileOperationService {
    // 真实文件操作方法（攻击者最终目标）
    public void deleteFileByPathList(List<String> pathList) {
        for (String path : pathList) {
            File targetFile = new File(path);
            if (targetFile.exists()) {
                targetFile.delete();
            }
        }
    }
}