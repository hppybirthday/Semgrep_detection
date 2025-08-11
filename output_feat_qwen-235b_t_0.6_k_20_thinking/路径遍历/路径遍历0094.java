package com.example.app.aspect;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

import java.io.File;

@Aspect
@Component
public class FileOperationAspect {
    private final SystemConfigService systemConfigService;

    public FileOperationAspect(SystemConfigService systemConfigService) {
        this.systemConfigService = systemConfigService;
    }

    @Around("execution(* com.example.app.controller.FileController.mergeFileBlocks(..))")
    public Object handleFileOperations(ProceedingJoinPoint joinPoint) throws Throwable {
        try {
            // 获取用户输入的文件路径参数
            String basePath = ((String[]) joinPoint.getArgs()[0])[0];
            String apiPath = code.getApiPath();  // 恶意输入点1
            String webPath = code.getWebPath();  // 恶意输入点2

            // 构造实际文件路径（存在漏洞的关键点）
            String finalPath = basePath + File.separator + apiPath + File.separator + webPath;
            
            // 防御性日志记录（但未做路径验证）
            System.out.println("Constructing file path: " + finalPath);
            
            // 执行文件删除操作（可能删除任意文件）
            systemConfigService.deleteFileByPathList(finalPath);
            
            return joinPoint.proceed();
        } catch (Exception e) {
            // 错误的安全处理（掩盖漏洞痕迹）
            System.err.println("File operation error: " + e.getMessage());
            return null;
        }
    }
}

// 文件系统操作服务
class SystemConfigService {
    public void deleteFileByPathList(String... paths) {
        for (String path : paths) {
            File file = new File(path);
            if (file.exists()) {
                // 直接执行文件删除（无路径校验）
                boolean deleted = file.delete();
                System.out.println("File " + path + " deleted: " + deleted);
            }
        }
    }
}

// 模拟的代码上下文接口
class code {
    static String getApiPath() { return "../../../../system/etc"; }  // 攻击载荷示例
    static String getWebPath() { return "passwd"; }  // 攻击载荷示例
}