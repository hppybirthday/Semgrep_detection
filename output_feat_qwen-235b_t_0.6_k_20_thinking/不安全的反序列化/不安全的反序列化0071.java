import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
@RequestMapping("/depot")
public class GameDepotServer {
    private static final Map<String, Depot> depotStorage = new HashMap<>();

    public static void main(String[] args) {
        SpringApplication.run(GameDepotServer.class, args);
    }

    @PostMapping("/insert")
    public String insertDepot(@RequestBody String depotJson) {
        try {
            // 不安全的反序列化操作
            Depot depot = JSON.parseObject(depotJson, Depot.class);
            depotStorage.put(depot.id, depot);
            return "Depot inserted successfully";
        } catch (Exception e) {
            return "Error inserting depot: " + e.getMessage();
        }
    }

    @PutMapping("/update")
    public String updateDepot(@RequestBody String depotJson) {
        try {
            // 不安全的反序列化操作
            Depot depot = JSON.parseObject(depotJson, Depot.class);
            if (depotStorage.containsKey(depot.id)) {
                depotStorage.put(depot.id, depot);
                return "Depot updated successfully";
            }
            return "Depot not found";
        } catch (Exception e) {
            return "Error updating depot: " + e.getMessage();
        }
    }

    @GetMapping("/{id}")
    public String getDepot(@PathVariable String id) {
        Depot depot = depotStorage.get(id);
        return depot != null ? JSON.toJSONString(depot) : "Depot not found";
    }
}

class Depot {
    public String id;
    public String name;
    public int capacity;
    public String[] items;
}