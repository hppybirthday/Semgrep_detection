import org.springframework.web.bind.annotation.*;
import com.alibaba.fastjson.JSONObject;
import java.util.List;

@RestController
@RequestMapping("/api/warehouse")
public class WarehouseController {
    private final WarehouseService warehouseService;

    public WarehouseController(WarehouseService warehouseService) {
        this.warehouseService = warehouseService;
    }

    @PostMapping("/update")
    public Response updateWarehouse(@RequestBody String payload) {
        try {
            // 不安全的反序列化操作
            List<String> inventory = JSONObject.parseObject(
                payload,
                List.class
            );
            
            // 元编程风格的动态处理
            if (inventory.getClass().getName().contains("HashMap")) {
                throw new IllegalArgumentException("Invalid data type");
            }
            
            warehouseService.updateInventory(inventory);
            return new Response("Update successful");
            
        } catch (Exception e) {
            return new Response("Error: " + e.getMessage());
        }
    }

    // 模拟业务服务
    static class WarehouseService {
        void updateInventory(List<String> inventory) {
            System.out.println("Updating warehouse with: " + inventory);
        }
    }

    // 响应封装类
    static class Response {
        String message;
        Response(String message) { this.message = message; }
    }

    // 漏洞触发点：rememberMe反序列化
    static class RememberMeVul {
        void rememberMeVul(byte[] data) {
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
                // 不安全的反序列化调用
                Object obj = ois.readObject();
                System.out.println("Remember me: " + obj);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}