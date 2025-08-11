import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;
import java.util.List;

@SpringBootApplication
@RestController
@RequestMapping("/api/ml")
public class SQLiDemo {
    @Resource MLService mlService;
    public static void main(String[] args) {
        SpringApplication.run(SQLiDemo.class, args);
    }

    @GetMapping("/clients/{clientId}")
    public List<DataPoint> getClientData(@PathVariable String clientId) {
        return mlService.getTrainingData(clientId);
    }
}

interface MLMapper {
    @Select({"<script>",
             "SELECT * FROM training_data WHERE client_id IN (${clientId})",
             "</script>"})
    List<DataPoint> selectByClientId(String clientId);
}

class DataPoint {
    String features; // 特征数据
    double label;    // 标签值
}

@Service
class MLService {
    @Resource MLMapper mlMapper;
    List<DataPoint> getTrainingData(String clientId) {
        return mlMapper.selectByClientId(clientId);
    }
}

// MyBatis配置
@MapperScan(basePackageClasses = MLMapper.class)
@Configuration
class MyBatisConfig {}