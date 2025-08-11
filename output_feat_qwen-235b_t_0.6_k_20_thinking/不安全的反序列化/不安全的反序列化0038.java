import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import java.io.*;
import java.util.*;

@Component
@RestController
@RequestMapping("/iot")
public class DeviceController {
    
    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file) {
        try {
            Workbook workbook = new XSSFWorkbook(file.getInputStream());
            Sheet sheet = workbook.getSheetAt(0);
            List<String> jsonData = new ArrayList<>();
            
            for (Row row : sheet) {
                StringBuilder sb = new StringBuilder();
                for (Cell cell : row) {
                    sb.append(cell.toString()).append(",");
                }
                jsonData.add(sb.toString());
            }
            
            saveDetails(jsonData);
            return "OK";
            
        } catch (Exception e) {
            return "ERROR";
        }
    }
    
    private void saveDetails(List<String> rows) {
        List<DepotItem> items = new ArrayList<>();
        for (String row : rows) {
            JSONArray array = JSONArray.parseArray(row);
            for (Object obj : array) {
                String json = obj.toString();
                DepotItem item = JSONObject.parseObject(json, DepotItem.class);
                items.add(item);
            }
        }
        // 模拟持久化操作
        System.out.println("Items saved: " + items.size());
    }
}

class DepotItem {
    private String deviceId;
    private String config;
    private int priority;
    
    // 必须有无参构造函数
    public DepotItem() {}
    
    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }
    
    public String getConfig() { return config; }
    public void setConfig(String config) { this.config = config; }
    
    public int getPriority() { return priority; }
    public void setPriority(int priority) { this.priority = priority; }
}