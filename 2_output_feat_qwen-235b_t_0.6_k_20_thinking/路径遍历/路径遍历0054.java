package com.example.filemanager;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class FileStorageService {
    private final Path baseDir;

    public FileStorageService(@Value("${file.storage.base-dir}") String baseDir) {
        this.baseDir = Paths.get(baseDir).toAbsolutePath().normalize();
    }

    public Resource loadFile(String filename) throws IOException {
        String sanitizedFilename = FileValidationUtil.sanitizePath(filename);
        Path targetPath = baseDir.resolve(sanitizedFilename).normalize();
        return new UrlResource(targetPath.toUri());
    }
}