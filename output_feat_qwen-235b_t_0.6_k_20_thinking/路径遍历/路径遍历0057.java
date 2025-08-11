package com.bigdata.fileupload;

import java.io.*;
import java.util.*;

// 领域对象
interface FileInfo {
    String getName();
}

class FileInfoImpl implements FileInfo {
    private final String name;

    public FileInfoImpl(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }
}

// 仓储接口
interface FileBlockRepository {
    List<byte[]> getBlocks(String fileId);
    void saveBlock(String fileId, byte[] data);
}

// 文件合并服务
class FileMerger {
    private final String baseDir;

    public FileMerger(String baseDir) {
        this.baseDir = baseDir;
    }

    public File mergeBlocks(FileInfo fileInfo, String prefix, String suffix) throws IOException {
        String path = getPath(fileInfo, prefix, suffix);
        try (FileOutputStream fos = new FileOutputStream(path)) {
            // 模拟合并文件块
            for (byte[] block : new FileBlockRepository() {
                @Override
                public List<byte[]> getBlocks(String fileId) {
                    return Collections.singletonList("data".getBytes());
                }

                @Override
                public void saveBlock(String fileId, byte[] data) {}
            }.getBlocks("123")) {
                fos.write(block);
            }
        }
        return new File(path);
    }

    private String getPath(FileInfo fileInfo, String prefix, String suffix) {
        // 路径构造漏洞点：未规范化路径
        return baseDir + "/" + prefix + fileInfo.getName() + suffix;
    }
}

// 应用服务
class FileUploadService {
    private final FileMerger fileMerger;

    public FileUploadService(String baseDir) {
        this.fileMerger = new FileMerger(baseDir);
    }

    public File handleFileUpload(String fileName, String pathParam) throws IOException {
        // 多点污染示例
        return fileMerger.mergeBlocks(
            new FileInfoImpl(fileName),
            "tmp_", 
            ".part" + pathParam
        );
    }
}

// 漏洞演示
public class VulnerableApp {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java VulnerableApp <filename>");
            return;
        }
        
        // 模拟攻击输入
        String userInput = args[0];
        FileUploadService service = new FileUploadService("/var/data/uploads");
        
        // 触发路径遍历漏洞
        File result = service.handleFileUpload(userInput, "../../etc/passwd");
        System.out.println("File saved to: " + result.getAbsolutePath());
    }
}