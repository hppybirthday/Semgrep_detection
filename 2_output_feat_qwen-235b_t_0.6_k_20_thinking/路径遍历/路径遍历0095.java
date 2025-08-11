package com.example.bank.controller;

import com.example.bank.service.DocumentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;

@RestController
public class DocumentController {
    @Autowired
    private DocumentService documentService;

    @PostMapping("/delete")
    public String deleteFile(@RequestParam String fileName) {
        try {
            documentService.deleteDocument(fileName);
            return "Deleted successfully";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

package com.example.bank.service;

import com.example.bank.util.FileStorageUtil;
import com.example.bank.util.SystemConfigService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;

@Service
public class DocumentService {
    @Autowired
    private SystemConfigService systemConfigService;

    public void deleteDocument(String fileName) {
        String basePath = "/var/bank/files/";
        File safeFile = FileStorageUtil.buildSecurePath(basePath, fileName);
        systemConfigService.deleteFileByPathList(Collections.singletonList(safeFile.getAbsolutePath()));
    }
}

package com.example.bank.util;

import java.io.File;

public class FileStorageUtil {
    public static File buildSecurePath(String basePath, String userInput) {
        userInput = userInput.strip();
        userInput = userInput.replace("\\\\", "/");
        return new File(basePath, userInput);
    }
}

package com.example.bank.util;

import java.util.List;

public class SystemConfigService {
    public void deleteFileByPathList(List<String> pathList) {
        for (String path : pathList) {
            File file = new File(path);
            if (file.exists()) {
                file.delete();
            }
        }
    }
}