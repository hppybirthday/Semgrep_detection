package com.example.filestorage;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileStorageApplication {
    public static void main(String[] args) {
        FileService fileService = new FileService();
        fileService.deleteFile("user_input/../../etc/passwd");
    }
}

class FileService {
    private final FileRepository fileRepository;

    public FileService() {
        this.fileRepository = new LocalFileRepository("/var/www/html/uploads");
    }

    public void deleteFile(String fileName) {
        try {
            fileRepository.delete(fileName);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

interface FileRepository {
    void delete(String fileName) throws IOException;
}

class LocalFileRepository implements FileRepository {
    private final String basePath;

    public LocalFileRepository(String basePath) {
        this.basePath = basePath;
    }

    @Override
    public void delete(String fileName) throws IOException {
        Path targetPath = Paths.get(basePath, fileName);
        System.out.println("Deleting file: " + targetPath.toString());
        
        // 模拟云存储API上传操作前的本地临时处理
        File file = targetPath.toFile();
        
        if (!file.exists()) {
            throw new IOException("File not found");
        }
        
        // 存在路径遍历漏洞：未校验路径是否超出限定目录
        Files.delete(file.toPath());
    }
}

// 模拟AOP切面处理
@Aspect
class FileOperationAspect {
    @AfterReturning("execution(* com.example.filestorage.FileRepository.delete(..))")
    public void afterFileDelete(JoinPoint joinPoint) {
        Object[] args = joinPoint.getArgs();
        if (args[0] instanceof String) {
            System.out.println("AOP监控：已删除文件 " + args[0]);
        }
    }
}