import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
public class DeviceController {
    @Autowired private DeviceService deviceService;

    @PostMapping("/delete")
    public String deleteDevices(@RequestParam String[] ids) {
        deviceService.batchDelete(ids);
        return "SUCCESS";
    }
}

@Service
class DeviceService {
    @Autowired DeviceMapper mapper;

    void batchDelete(String[] ids) {
        String idList = "'" + String.join("','", ids) + "'";
        mapper.deleteDevices(idList);
    }
}

@Mapper
class DeviceMapper {
    @Delete("DELETE FROM iot_devices WHERE device_id IN (${ids})")
    void deleteDevices(@Param("ids") String ids);
}

// 模拟启动类
@SpringBootApplication
class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}