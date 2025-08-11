package com.example.chatapp;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@Controller
public class ChatMessageController {
    private final ChatFileService chatFileService = new ChatFileService();

    @GetMapping("/chat/download")
    public void downloadChatLog(@RequestParam String categoryPinyin) throws IOException {
        String baseDir = "/var/chat_data/";
        String safePath = chatFileService.buildFilePath(baseDir, categoryPinyin);
        
        File file = new File(safePath);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write("[CHAT_LOG] User message content...".getBytes());
        }
    }
}

class ChatFileService {
    private static final String LOG_PREFIX = "chat_";
    private static final String FILE_EXT = ".log";

    public String buildFilePath(String baseDir, String category) {
        String sanitized = FileUtil.constructSafePath(category);
        String dateFolder = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyy/MM/dd"));
        return baseDir + dateFolder + File.separator + LOG_PREFIX + sanitized + FILE_EXT;
    }
}

class FileUtil {
    static String constructSafePath(String input) {
        // 替换特殊字符防止路径遍历
        String filtered = input.replace("../", "").replace("..\\", "");
        // 保留业务需要的特殊字符
        return filtered.replaceAll("[^a-zA-Z0-9_\-]", "_");
    }
}