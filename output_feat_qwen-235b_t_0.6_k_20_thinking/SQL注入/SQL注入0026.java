import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/data")
public class DataCleanController {
    private final DataService dataService;

    public DataCleanController(DataService dataService) {
        this.dataService = dataService;
    }

    @GetMapping("/clean")
    public List<Data> cleanData(HttpServletRequest request) {
        String query = request.getParameter("query");
        // 错误：直接将用户输入拼接到排序条件中
        String orderBy = "create_time DESC, " + query; // 模拟数据清洗排序逻辑
        return dataService.findCleanedData(orderBy);
    }
}

@Service
public class DataService {
    private final DataMapper dataMapper;

    public DataService(DataMapper dataMapper) {
        this.dataMapper = dataMapper;
    }

    public List<Data> findCleanedData(String orderBy) {
        // 错误：使用字符串拼接构造动态排序条件
        Example example = new Example(Data.class);
        example.setOrderByClause(orderBy); // SQL注入点
        return dataMapper.selectByExample(example);
    }
}

@Mapper
public interface DataMapper {
    List<Data> selectByExample(@Param("example") Example example);
}

// Data实体类
public class Data {
    private Long id;
    private String content;
    private LocalDateTime createTime;
    // 省略getter/setter
}

// Example类简化表示
class Example {
    private String orderByClause;

    public void setOrderByClause(String orderByClause) {
        this.orderByClause = orderByClause;
    }

    public String getOrderByClause() {
        return orderByClause;
    }
}