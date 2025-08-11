import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DataSanitizer {
    // 模拟HTML内容清理
    public static String sanitizeHTML(String input) {
        if (input == null) return "";
        
        // 错误的清理方式：仅移除<script>标签
        String result = input.replaceAll("(?i)<script.*?>.*?</script>", "");
        
        // 错误地允许部分HTML标签
        result = result.replaceAll("(?i)<(?!/?(b|u|i|br)\\b)[^>]*>", "");
        
        // 存在缺陷的属性过滤
        result = result.replaceAll("(?i)(onerror|onclick)=", "removed_");
        
        return result;
    }

    // 模拟数据库存储
    public static void storeData(String data) {
        // 实际应用中会存储到数据库
        System.out.println("[INFO] Storing sanitized data: " + data);
    }

    // 模拟前端渲染
    public static String renderHTML(String data) {
        return "<html><body><div>" + data + "</div></body></html>";
    }

    public static void main(String[] args) {
        // 测试用例1：基本XSS攻击
        String userInput1 = "<script>alert('XSS')</script>";
        
        // 测试用例2：绕过标签过滤
        String userInput2 = "<img src='x' onerror='alert(1)'>";
        
        // 测试用例3：编码绕过
        String userInput3 = "<ScRiPt>prompt(1)</sCrIpT>";
        
        System.out.println("=== Vulnerable Data Sanitization ===");
        
        // 处理测试用例1
        String clean1 = sanitizeHTML(userInput1);
        System.out.println("Original 1: " + userInput1);
        System.out.println("Sanitized 1: " + clean1);
        storeData(clean1);
        
        // 处理测试用例2
        String clean2 = sanitizeHTML(userInput2);
        System.out.println("\
Original 2: " + userInput2);
        System.out.println("Sanitized 2: " + clean2);
        storeData(clean2);
        
        // 处理测试用例3
        String clean3 = sanitizeHTML(userInput3);
        System.out.println("\
Original 3: " + userInput3);
        System.out.println("Sanitized 3: " + clean3);
        storeData(clean3);
        
        // 渲染示例
        System.out.println("\
[DEBUG] Rendered HTML:");
        System.out.println(renderHTML(clean2));
    }
}