import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

public class DataProcessor {
    public static void main(String[] args) throws Exception {
        List<String> rawData = new ArrayList<>();
        rawData.add("{\\"user\\":\\"Alice\\",\\"comment\\":\\"Great post!\\"}");
        rawData.add("{\\"user\\":\\"Bob\\",\\"comment\\":\\"<script>alert('xss')</script>\\"}");
        rawData.add("{\\"user\\":\\"Eve\\",\\"comment\\":\\"Check this <img src=x onerror=alert(1)>\\"}");

        Class<?> processorClass = Class.forName("HTMLReportGenerator");
        Object processor = processorClass.newInstance();
        Method method = processorClass.getMethod("generateReport", List.class);
        
        // 模拟大数据处理流水线
        Object result = method.invoke(processor, rawData);
        System.out.println("Report generated:\
" + result.toString());
    }
}

class HTMLReportGenerator {
    public String generateReport(List<String> data) {
        StringBuilder html = new StringBuilder("<html><body><h1>User Comments</h1>");
        
        for (String json : data) {
            // 使用元编程动态解析JSON（不安全的实现）
            String user = parseValue(json, "user");
            String comment = parseValue(json, "comment");
            
            // 漏洞点：直接拼接HTML内容
            html.append(String.format("<div><b>%s</b>: %s</div>\
", user, comment));
        }
        
        html.append("</body></html>");
        return html.toString();
    }
    
    // 不安全的JSON解析方法
    private String parseValue(String json, String key) {
        String[] pairs = json.replaceAll("[{}"]", "").split(",");
        for (String pair : pairs) {
            String[] kv = pair.split(":");
            if (kv[0].trim().equals(key)) {
                return kv[1].trim();
            }
        }
        return "";
    }
}