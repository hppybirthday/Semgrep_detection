package com.gamestudio.desktop;

import java.io.*;
import java.util.Scanner;

/**
 * 游戏存档加载器 - 演示路径遍历漏洞
 * @author GameDev
 */
public class GameLoader {
    private static final String GAME_DIR = "./game_data/";
    
    /**
     * 主游戏入口
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 桌面游戏存档加载器 ===");
        System.out.print("请输入存档文件名: ");
        String filename = scanner.nextLine();
        
        try {
            String content = loadGameFile(filename);
            System.out.println("加载成功! 存档内容:");
            System.out.println(content);
        } catch (Exception e) {
            System.err.println("加载失败: " + e.getMessage());
        }
    }
    
    /**
     * 加载指定存档文件
     * @param filename 用户输入的文件名
     * @return 文件内容
     * @throws IOException
     */
    public static String loadGameFile(String filename) throws IOException {
        // 漏洞点：直接拼接用户输入
        File file = new File(GAME_DIR + filename);
        
        // 检查文件是否存在
        if (!file.exists()) {
            throw new FileNotFoundException("存档文件不存在");
        }
        
        // 读取文件内容
        BufferedReader reader = new BufferedReader(new FileReader(file));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\
");
        }
        reader.close();
        return content.toString();
    }
    
    /**
     * 保存游戏进度（漏洞扩展点）
     * @param filename 文件名
     * @param data 数据
     * @throws IOException
     */
    public static void saveGameFile(String filename, String data) throws IOException {
        File file = new File(GAME_DIR + filename);
        BufferedWriter writer = new BufferedWriter(new FileWriter(file));
        writer.write(data);
        writer.close();
    }
}