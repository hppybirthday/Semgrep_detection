package com.example.xss.demo;

import java.util.function.Function;
import java.util.stream.Stream;
import java.util.List;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

class Sanitizer {
    // 函数式组合清洗规则（存在漏洞）
    private static final List<Function<String, String>> FILTERS = Stream.of(
        s -> s.replace("<script>", ""),
        s -> s.replace("</script>", "")
    ).toList();

    public static String sanitize(String input) {
        // 错误的清洗逻辑：仅移除script标签
        return FILTERS.stream().reduce(input, (s, f) -> f.apply(s));
    }
}

@RestController
class DemoController {
    @PostMapping("/process")
    public String processInput(@RequestParam String userInput) {
        // 清洗后直接插入HTML（未转义）
        String cleaned = Sanitizer.sanitize(userInput);
        return "<html><body><h2>User Input:</h2><div>" + cleaned + "</div></body></html>";
    }

    // 模拟其他数据清洗函数
    public String cleanEmail(String email) {
        return email.replaceAll("[^a-zA-Z0-9@._-\$$", "");
    }

    public String truncateText(String text, int maxLength) {
        return text.length() > maxLength ? text.substring(0, maxLength) : text;
    }
}
