import com.alibaba.fastjson.JSONObject;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

// 模拟Spring服务组件
public class DataCleaningService {
    private static final Logger logger = Logger.getLogger("DataCleaningService");
    private final Map<String, Depot> depotMap = new HashMap<>();

    // 模拟数据库操作
    public void insertDepot(String jsonData) {
        try {
            // 不安全的反序列化：直接将用户输入JSON转换为对象
            Depot depot = JSONObject.parseObject(jsonData, Depot.class);
            depotMap.put(depot.getId(), depot);
            logger.info("Depot inserted: " + depot.getName());
        } catch (Exception e) {
            logger.severe("Insert depot failed: " + e.getMessage());
        }
    }

    public void updateDepot(String jsonData) {
        try {
            // 不安全的反序列化：未验证类型直接转换
            Depot depot = JSONObject.parseObject(jsonData, Depot.class);
            if (depotMap.containsKey(depot.getId())) {
                depotMap.put(depot.getId(), depot);
                logger.info("Depot updated: " + depot.getName());
            }
        } catch (Exception e) {
            logger.severe("Update depot failed: " + e.getMessage());
        }
    }

    // 模拟Excel文件处理
    public void processExcelFile(String filePath) throws IOException {
        try (Workbook workbook = new XSSFWorkbook(new FileInputStream(filePath))) {
            Sheet sheet = workbook.getSheetAt(0);
            for (Row row : sheet) {
                if (row.getRowNum() == 0) continue; // 跳过标题行
                
                // 从Excel读取JSON字符串并直接反序列化
                String jsonData = row.getCell(0).getStringCellValue();
                insertDepot(jsonData);
                
                // 模拟业务逻辑：修改后重新更新
                String updatedJson = modifyJsonData(jsonData);
                updateDepot(updatedJson);
            }
        }
    }

    // 模拟不安全的JSON处理
    private String modifyJsonData(String originalJson) {
        // 实际业务中可能进行字段清洗，但此处保留原始结构
        return originalJson;
    }

    // 模拟实体类
    static class Depot {
        private String id;
        private String name;
        private String location;
        
        // 必须的getter/setter
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getLocation() { return location; }
        public void setLocation(String location) { this.location = location; }
    }

    // 模拟Spring控制器
    public static void main(String[] args) {
        DataCleaningService service = new DataCleaningService();
        try {
            // 模拟处理用户上传的恶意Excel文件
            service.processExcelFile("/tmp/malicious_data.xlsx");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}