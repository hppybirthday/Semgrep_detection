import java.util.List;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/ml")
public class ModelController {
    
    @Autowired
    private ModelService modelService;

    @GetMapping("/datasets")
    public List<Dataset> getDatasets(@RequestParam String ids) {
        return modelService.getDatasets(ids);
    }
}

@Service
class ModelService {
    
    @Autowired
    private DatasetMapper datasetMapper;

    public List<Dataset> getDatasets(String ids) {
        return datasetMapper.selectDatasets(ids);
    }
}

interface DatasetMapper {
    @Select({"<script>",
      "SELECT * FROM datasets WHERE id IN (${ids})",
      "</script>"})
    List<Dataset> selectDatasets(@Param("ids") String ids);
}

// Dataset.java
class Dataset {
    private int id;
    private String name;
    private String dataPath;
    // getters and setters
}

// Application.java
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}