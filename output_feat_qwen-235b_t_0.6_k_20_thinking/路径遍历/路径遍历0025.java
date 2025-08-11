import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

public class BigDataCategoryManager {
    private static final String BASE_PATH = "/var/data/warehouse/";
    private Map<String, CategoryHandler> handlers = new HashMap<>();

    public static void main(String[] args) {
        BigDataCategoryManager manager = new BigDataCategoryManager();
        manager.initHandlers();
        
        // 模拟API请求参数
        CategoryEntity category = new CategoryEntity();
        category.setCategoryId("1");
        category.setCategoryPinyin("../../etc/passwd");  // 恶意输入
        
        try {
            manager.updateCategory(category);
        } catch (Exception e) {
            System.out.println("[ERROR] 操作失败: " + e.getMessage());
        }
    }

    private void initHandlers() {
        // 元编程风格的处理器注册
        handlers.put("hadoop", new HadoopCategoryHandler());
        handlers.put("spark", new SparkCategoryHandler());
    }

    public void updateCategory(CategoryEntity category) throws IOException {
        String handlerKey = category.getCategoryType();
        if (!handlers.containsKey(handlerKey)) {
            throw new IllegalArgumentException("未知分类类型: " + handlerKey);
        }

        CategoryHandler handler = handlers.get(handlerKey);
        handler.processCategory(category);
    }

    static class CategoryEntity {
        private String categoryId;
        private String categoryPinyin;
        private String categoryType = "hadoop";

        // Getters & Setters
        public String getCategoryId() { return categoryId; }
        public void setCategoryId(String id) { this.categoryId = id; }
        
        public String getCategoryPinyin() { return categoryPinyin; }
        public void setCategoryPinyin(String pinyin) { this.categoryPinyin = pinyin; }
        
        public String getCategoryType() { return categoryType; }
    }

    interface CategoryHandler {
        void processCategory(CategoryEntity category) throws IOException;
    }

    static class HadoopCategoryHandler implements CategoryHandler {
        @Override
        public void processCategory(CategoryEntity category) throws IOException {
            String path = BASE_PATH + category.getCategoryPinyin() + "/metadata.conf";
            File file = new File(path);
            // 模拟写入操作
            Files.write(file.toPath(), "admin:root".getBytes());  // 危险操作
            System.out.println("[INFO] 配置已保存至: " + path);
        }
    }

    static class SparkCategoryHandler implements CategoryHandler {
        @Override
        public void processCategory(CategoryEntity category) throws IOException {
            String path = BASE_PATH + "spark/" + category.getCategoryId() + ".tmp";
            File file = new File(path);
            Files.write(file.toPath(), "temp_data".getBytes());
        }
    }
}