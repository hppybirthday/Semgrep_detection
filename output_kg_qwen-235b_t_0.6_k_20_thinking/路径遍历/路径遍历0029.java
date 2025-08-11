package com.example.mobileapp;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Scanner;

public class FileService {
    private static final String BASE_DIR = "/data/data/com.example.mobileapp/files/user_uploads/";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter username to download avatar:");
        String username = scanner.nextLine();
        
        try {
            byte[] avatarData = downloadAvatar(username);
            System.out.println("Avatar downloaded successfully (" + avatarData.length + " bytes)");
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    /**
     * 模拟下载用户头像的功能
     * @param username 用户名
     * @return 头像文件数据
     * @throws IOException
     */
    public static byte[] downloadAvatar(String username) throws IOException {
        // 漏洞点：直接拼接用户输入到文件路径中
        String filePath = BASE_DIR + username + "/avatar.png";
        File file = new File(filePath);
        
        if (!file.exists()) {
            throw new IOException("Avatar not found");
        }
        
        // 检查文件是否在预期目录内（本意是加强安全）
        // 但这个检查存在绕过可能
        if (!file.getCanonicalPath().startsWith(BASE_DIR)) {
            throw new IOException("Invalid file path");
        }
        
        // 读取文件内容
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fis.read(data);
        fis.close();
        return data;
    }

    /**
     * 模拟上传头像功能
     * @param username 用户名
     * @param avatarData 头像数据
     * @throws IOException
     */
    public static void uploadAvatar(String username, byte[] avatarData) throws IOException {
        String filePath = BASE_DIR + username + "/avatar.png";
        File file = new File(filePath);
        
        // 创建用户目录
        file.getParentFile().mkdirs();
        
        // 写入文件（简化处理）
        // 实际应使用更安全的方式处理
        // ...
    }
}