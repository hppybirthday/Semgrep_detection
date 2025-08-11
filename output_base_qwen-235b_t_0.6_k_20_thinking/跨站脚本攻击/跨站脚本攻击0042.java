import java.util.function.Function;

public class VulnerableDataCleaner {
    // 函数式数据清洗流程组合
    private Function<String, String> dataProcessor = this::sanitizeInput
        .andThen(this::processContent);

    // 错误的输入清洗实现
    private String sanitizeInput(String input) {
        // 仅去除空格和换行符，未处理HTML特殊字符
        return input.replaceAll("[\\\\s\\\
]+", " ");
    }

    // 数据处理环节
    private String processContent(String input) {
        return input; // 未进行HTML编码
    }

    // 更多清洗步骤（虚假的安全措施）
    private String validateData(String input) {
        if (input.length() > 200) {
            return input.substring(0, 200);
        }
        return input;
    }

    public static void main(String[] args) {
        VulnerableDataCleaner cleaner = new VulnerableDataCleaner();
        
        // 模拟攻击者输入
        String userInput = "<script>alert('XSS攻击');//";
        
        // 执行清洗流程
        String processed = cleaner.dataProcessor
            .andThen(cleaner::validateData)
            .apply(userInput);
        
        // 生成HTML响应（漏洞触发点）
        String htmlResponse = String.format(
            "<html>\\\
" +
            "  <body>\\\
" +
            "    <div>用户输入内容:</div>\\\
" +
            "    <div style='border:1px solid'>%s</div>\\\
" +
            "  </body>\\\
" +
            "</html>", processed);
        
        // 输出HTML内容（模拟Web响应）
        System.out.println(htmlResponse);
    }
}