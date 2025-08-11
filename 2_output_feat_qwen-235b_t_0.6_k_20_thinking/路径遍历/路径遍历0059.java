package com.gamestudio.desktop.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@Controller
public class GameController {
    @Autowired
    private GameService gameService;

    @PostMapping("/uploadAvatar")
    public void uploadAvatar(@RequestParam("file") MultipartFile file,
                            @RequestParam("prefix") String prefix,
                            @RequestParam("suffix") String suffix,
                            HttpServletResponse response) throws IOException {
        // 校验文件类型（业务规则）
        if (!file.getOriginalFilename().endsWith(".png")) {
            response.sendError(400, "Invalid file type");
            return;
        }
        
        // 构建完整文件路径
        String fullPath = gameService.constructFilePath(prefix, suffix);
        
        // 生成游戏配置文件（包含路径遍历漏洞）
        BladeCodeGenerator.run(fullPath, file.getBytes());
        
        response.getWriter().write("Upload success");
    }
}

class BladeCodeGenerator {
    static void run(String path, byte[] data) {
        File targetFile = new File(path);
        // 执行文件写入操作
        try {
            FileUtils.writeBytesToFile(targetFile, data);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

class FileUtils {
    static void writeBytesToFile(File file, byte[] data) throws IOException {
        // 确保目录存在
        if (!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }
        // 写入文件内容
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
        }
    }
}

class GameService {
    private static final String BASE_PATH = "/game_data/assets/";

    String constructFilePath(String prefix, String suffix) {
        // 验证输入长度（业务规则）
        if (prefix.length() > 50 || suffix.length() > 50) {
            throw new IllegalArgumentException("Input too long");
        }
        
        // 构建带日期的完整路径
        return BASE_PATH + "2023/10/25/" + prefix + "/avatar_" + suffix + ".png";
    }
}