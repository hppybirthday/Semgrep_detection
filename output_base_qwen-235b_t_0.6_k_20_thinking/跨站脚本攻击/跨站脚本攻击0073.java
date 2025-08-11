import java.util.*;
import java.io.*;

// 模拟大数据处理中的日志分析组件
class LogProcessor {
    public List<String> processLogs(List<String> rawLogs) {
        List<String> processed = new ArrayList<>();
        for (String log : rawLogs) {
            // 模拟数据处理（错误地信任输入数据）
            processed.add(log.trim());
        }
        return processed;
    }
}

// 生成HTML报告的组件
class ReportGenerator {
    public String generateReport(List<String> data) {
        StringBuilder html = new StringBuilder();
        html.append("<html><body><h1>数据报告</h1><table border='1'>");
        
        // 存在漏洞的代码：直接拼接原始数据到HTML
        for (String item : data) {
            html.append("<tr><td>").append(item).append("</td></tr>\
");
        }
        
        html.append("</table></body></html>");
        return html.toString();
    }
}

// 模拟外部数据源（可能包含恶意输入）
class ExternalDataSource {
    public List<String> fetchMaliciousData() {
        List<String> data = new ArrayList<>();
        // 模拟正常数据
        data.add("用户访问记录123");
        // 恶意载荷
        data.add("<script>alert('XSS攻击成功！');window.location='http://malicious.com'</script>");
        data.add("安全测试数据456");
        return data;
    }
}

public class Main {
    public static void main(String[] args) {
        try {
            // 模拟大数据处理流程
            ExternalDataSource source = new ExternalDataSource();
            LogProcessor processor = new LogProcessor();
            ReportGenerator generator = new ReportGenerator();
            
            List<String> rawData = source.fetchMaliciousData();
            List<String> processedData = processor.processLogs(rawData);
            String report = generator.generateReport(processedData);
            
            // 输出到文件模拟实际应用
            FileWriter writer = new FileWriter("vulnerable_report.html");
            writer.write(report);
            writer.close();
            
            System.out.println("报告生成完成，存在XSS漏洞");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}