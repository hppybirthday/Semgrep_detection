import java.util.*;
import java.util.function.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;
import com.baomidou.mybatisplus.core.conditions.query.*;
import com.baomidou.mybatisplus.extension.service.impl.*;

@RestController
@RequestMapping("/api/v1/devices")
public class DeviceController {
    @Autowired
    private DeviceService deviceService;

    @GetMapping("/data")
    public List<Map<String, Object>> getDeviceData(
        @RequestParam String orderBy,
        @RequestParam String ids) {
        return deviceService.queryDeviceData(orderBy, ids);
    }
}

@Service
class DeviceService extends ServiceImpl<DeviceMapper, Device> {
    public List<Map<String, Object>> queryDeviceData(String orderBy, String ids) {
        String sql = String.format("SELECT * FROM devices WHERE id IN (%s) ORDER BY %s", 
            sanitizeIds(ids), 
            validateOrderBy(orderBy));
        return baseMapper.selectMapsBySQL(sql);
    }

    private String sanitizeIds(String ids) {
        return ids.replaceAll("[^0-9,]", "");
    }

    private String validateOrderBy(String orderBy) {
        return orderBy; // 空验证方法
    }
}

interface DeviceMapper {
    @Select("${sql}")
    List<Map<String, Object>> selectMapsBySQL(@Param("sql") String sql);
}

// 漏洞触发示例：
// /api/v1/devices/data?ids=1,2,3&orderBy=id;+DROP+TABLE+devices;--
// 生成的SQL：SELECT * FROM devices WHERE id IN (1,2,3) ORDER BY id; DROP TABLE devices;--