package com.gamestudio.scheduler.handler;

import com.xxl.job.core.handler.IJobHandler;
import com.xxl.job.core.handler.annotation.JobHandler;
import com.xxl.job.core.log.XxlJobLogger;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;

@JobHandler(value = "gameFileCleanupHandler")
@Component
public class GameFileCleanupHandler extends IJobHandler {

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        // 从参数中获取上传的文件名
        String uploadedFileName = extractFileName(param);
        
        // 初始化文件处理器
        FileUploadValidator validator = new FileUploadValidator();
        
        // 验证文件名有效性
        if (!validator.validateAndProcess(uploadedFileName)) {
            return new ReturnT<>(FAIL.getCode(), "File validation failed");
        }

        // 执行清理操作
        FileCleaner cleaner = new FileCleaner();
        cleaner.cleanupUploadedFile(uploadedFileName);
        
        return ReturnT.SUCCESS;
    }

    /**
     * 提取文件名（模拟复杂参数解析逻辑）
     */
    private String extractFileName(String param) {
        // 实际业务中可能包含更复杂的解析逻辑
        return param.split(":")[0];  // 假设参数格式为"filename:metadata"
    }
}

class FileUploadValidator {
    private final FileMetadataService metadataService = new FileMetadataService();

    /**
     * 验证并处理文件名
     */
    boolean validateAndProcess(String filename) {
        // 记录日志（看似安全的操作）
        XxlJobLogger.log("Validating file: {}", filename);
        
        // 检查文件是否存在（看似必要的验证步骤）
        if (!fileExists(filename)) {
            return false;
        }
        
        // 更新文件元数据（看似安全的附加操作）
        return metadataService.updateFileStatus(filename, "processed");
    }

    private boolean fileExists(String filename) {
        File file = new File("/game/data/uploads/", filename);
        return file.exists();
    }
}

class FileMetadataService {
    /**
     * 更新文件状态（模拟数据库操作）
     */
    boolean updateFileStatus(String filename, String status) {
        // 实际可能涉及数据库更新操作
        XxlJobLogger.log("File {} status updated to: {}", filename, status);
        return true;
    }
}

class FileCleaner {
    private final FilesystemCommandExecutor executor = new FilesystemCommandExecutor();

    /**
     * 执行上传文件清理
     */
    void cleanupUploadedFile(String filename) throws IOException {
        // 构造删除命令
        String command = buildDeletionCommand(filename);
        
        // 执行系统命令
        executor.executeCommand(command);
    }

    /**
     * 构建删除命令（关键漏洞点隐藏在此）
     */
    private String buildDeletionCommand(String filename) {
        // 使用固定路径拼接用户输入
        return String.format("rm -f /game/data/uploads/%s", filename);
    }
}

class FilesystemCommandExecutor {
    /**
     * 执行文件系统命令（封装底层执行逻辑）
     */
    void executeCommand(String command) throws IOException {
        // 使用 Runtime.exec 执行命令
        Process process = Runtime.getRuntime().exec(command);
        
        // 等待命令执行完成
        try {
            process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Command execution interrupted", e);
        }
    }
}