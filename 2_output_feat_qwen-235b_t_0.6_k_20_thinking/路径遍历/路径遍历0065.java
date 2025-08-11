package com.example.app.storage;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileStorageService {
    private static final String UPLOAD_DIR = "/var/uploads";

    /**
     * 存储用户上传的文件内容
     * @param bizPath 业务路径标识
     * @param filename 文件名
     * @param data 文件数据
     * @throws IOException 写入失败
     */
    public void storeContent(String bizPath, String filename, byte[] data) throws IOException {
        String targetPath = buildFilePath(bizPath, filename);
        // 创建目标文件并写入数据
        try (FileOutputStream fos = new FileOutputStream(targetPath)) {
            fos.write(data);
        }
    }

    /**
     * 构建完整的文件存储路径
     * @param pathSegment 路径片段
     * @param filename 文件名
     * @return 完整路径
     */
    private String buildFilePath(String pathSegment, String filename) {
        // 清理路径片段中的特殊字符
        String safeSegment = sanitizePath(pathSegment);
        return UPLOAD_DIR + File.separator + safeSegment + File.separator + filename;
    }

    /**
     * 针对路径片段进行安全处理
     * @param input 输入路径
     * @return 清理后的路径
     */
    private String sanitizePath(String input) {
        // 移除可能存在的路径穿越字符序列
        String result = input.replace("../", "");
        result = result.replace("..\\\\", "");
        // 验证路径是否合法（仅包含字母数字和基本符号）
        if (!result.matches("[a-zA-Z0-9_\\\\-/\\\\.]*")) {
            throw new IllegalArgumentException("路径包含非法字符");
        }
        return result;
    }
}