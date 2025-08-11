import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/ml")
public class ModelTrainingController {

    @Autowired
    private ModelTrainingService modelTrainingService;

    @GetMapping("/records")
    public List<ModelTrainingRecord> getRecords(
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize,
            @RequestParam(required = false) String orderField,
            @RequestParam(required = false) String orderDirection) {
        return modelTrainingService.getRecords(pageNum, pageSize, orderField, orderDirection);
    }

    @DeleteMapping("/delete/{ids}")
    public ResponseEntity<?> deleteRecords(@PathVariable String ids) {
        modelTrainingService.deleteRecords(ids);
        return ResponseEntity.ok().build();
    }
}

@Service
class ModelTrainingService {

    @Autowired
    private ModelTrainingMapper modelTrainingMapper;

    public List<ModelTrainingRecord> getRecords(int pageNum, int pageSize, String orderField, String orderDirection) {
        QueryWrapper<ModelTrainingRecord> wrapper = new QueryWrapper<>();
        if (StringUtils.isNotBlank(orderField)) {
            wrapper.orderBy(true, "asc".equalsIgnoreCase(orderDirection), orderField);
        }
        return modelTrainingMapper.selectList(wrapper);
    }

    public void deleteRecords(String ids) {
        modelTrainingMapper.deleteByIds(ids);
    }
}

interface ModelTrainingMapper extends BaseMapper<ModelTrainingRecord> {
    void deleteByIds(String ids);
}

/* Mapper XML配置（未显式编码，但漏洞存在于动态SQL构造）
<delete id="deleteByIds">
    DELETE FROM model_training_records 
    WHERE id IN (${ids})
</delete>

<select id="selectList" ...>
    SELECT * FROM model_training_records
    <where>...</where>
    ORDER BY ${orderField} ${orderDirection}
</select>
*/

class ModelTrainingRecord {
    private Long id;
    private String modelName;
    private Double accuracy;
    // getters/setters
}