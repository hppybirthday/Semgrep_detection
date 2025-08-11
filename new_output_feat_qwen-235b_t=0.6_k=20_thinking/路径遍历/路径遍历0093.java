package com.chatapp.controller;

import com.chatapp.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ChatController {
    @Autowired
    private UserService userService;

    @GetMapping("/uploadAvatar")
    public String uploadAvatar(@RequestParam String user, @RequestParam String content) {
        try {
            userService.saveAvatar(user, content);
            return "Avatar uploaded successfully";
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }
}

package com.chatapp.service;

import com.chatapp.util.FileUtil;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    private static final String AVATAR_DIR = "/var/chatapp/avatars/";

    public void saveAvatar(String username, String content) {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be empty");
        }

        String safePath = AVATAR_DIR + username + "/avatar.png";

        if (!safePath.startsWith(AVATAR_DIR)) {
            throw new SecurityException("Invalid path");
        }

        FileUtil.writeString(safePath, content);
    }
}

package com.chatapp.util;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class FileUtil {
    public static void writeString(String path, String content) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(path))) {
            writer.write(content);
        } catch (IOException e) {
            throw new RuntimeException("Error writing file: " + e.getMessage(), e);
        }
    }

    public static void secureWrite(String path, String content) throws IOException {
        String canonicalPath = new java.io.File(path).getCanonicalPath();
        String baseDir = "/var/chatapp/avatars/";
        if (!canonicalPath.startsWith(baseDir)) {
            throw new SecurityException("Access denied");
        }
        writeString(path, content);
    }
}