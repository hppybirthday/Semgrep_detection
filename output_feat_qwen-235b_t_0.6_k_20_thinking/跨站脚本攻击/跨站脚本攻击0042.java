import java.util.*;
import java.util.function.*;
import java.util.stream.*;

public class DataCleaner {
    static Map<String, String> db = new HashMap<>();

    public static void main(String[] args) {
        List<String> rawInputs = Arrays.asList(
            "<script>alert('xss')</script>",
            "Safe Title 1",
            "<img src=x onerror=alert(1)>",
            "Safe Title 2"
        );

        List<String> cleaned = rawInputs.stream()
            .map(DataCleaner::storeAndRetrieve)
            .collect(Collectors.toList());

        cleaned.forEach(title -> {
            String html = "<div class='post'><h2>" + title + "</h2></div>";
            System.out.println(html);
        });
    }

    static String storeAndRetrieve(String input) {
        // 模拟数据库存储和检索
        String id = UUID.randomUUID().toString();
        db.put(id, input);
        return db.get(id);
    }
}

/*
编译运行后输出：
<div class='post'><h2><script>alert('xss')</h2></div>
...其他内容
当这段HTML被浏览器解析时，脚本会立即执行
*/