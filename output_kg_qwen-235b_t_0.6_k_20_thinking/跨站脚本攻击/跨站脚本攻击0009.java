package com.example.xssdemo;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 数据清洗工具类 - 存在XSS漏洞示例
 */
public class DataCleaner {
    // 模拟HTML模板
    private static final String HTML_TEMPLATE = "<html><body><h1>用户资料</h1><div>%s</div></body></html>";

    /**
     * 模拟不安全的数据清洗方法
     * 试图通过正则表达式移除脚本标签，但存在绕过可能
     */
    public String cleanInput(String input) {
        // 错误的清洗逻辑：仅移除<script>标签
        Pattern scriptPattern = Pattern.compile("<script.*?>.*?</script>", Pattern.CASE_INSENSITIVE);
        Matcher matcher = scriptPattern.matcher(input);
        return matcher.replaceAll("");
    }

    /**
     * 生成用户页面（存在XSS漏洞）
     */
    public void generateUserPage(String username, String content) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(username + ".html"))) {
            // 错误地将未完全清洗的内容插入HTML
            String safeContent = cleanInput(content);
            writer.write(String.format(HTML_TEMPLATE, safeContent));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 模拟不安全的HTML生成服务
     */
    public static void main(String[] args) {
        DataCleaner cleaner = new DataCleaner();
        
        // 模拟用户输入（包含XSS攻击载荷）
        String userInput = "<img src=x onerror=alert('XSS')> <b>正常内容</b>";
        
        // 生成包含漏洞的用户页面
        cleaner.generateUserPage("vulnerable_user", userInput);
        
        System.out.println("[+] 页面生成完成，存在XSS漏洞");
        System.out.println("[!] 访问生成的HTML文件将触发恶意脚本");
    }
}
