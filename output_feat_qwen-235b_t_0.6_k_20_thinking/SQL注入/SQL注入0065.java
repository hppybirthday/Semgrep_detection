import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.List;
@RestController
@RequestMapping("/api/products")
public class ProductController {
    @Autowired
    private ProductService productService;
    @GetMapping
    public List<Product> getProducts(@RequestParam String sort, @RequestParam String order) {
        return productService.findProducts(sort, order);
    }
}
@Service
class ProductService {
    @Autowired
    private ProductMapper productMapper;
    public List<Product> findProducts(String sort, String order) {
        return productMapper.selectList(new QueryWrapper<Product>().orderBy(StringUtils.isNotBlank(order), true, order));
    }
}
@Mapper
interface ProductMapper extends BaseMapper<Product> {
}
// MyBatis-Plus Wrapper内部实现片段（模拟元编程动态SQL构建）
public class QueryWrapper<T> {
    private List<SqlSegment> sqlSegments = new ArrayList<>();
    public QueryWrapper<T> orderBy(boolean condition, boolean isAsc, String column) {
        if (condition) {
            sqlSegments.add(() -> "ORDER BY " + column + " " + (isAsc ? "ASC" : "DESC"));
        }
        return this;
    }
    // 模拟SQL生成过程
    public String getSql() {
        StringBuilder sql = new StringBuilder("SELECT * FROM products");
        for (SqlSegment segment : sqlSegments) {
            sql.append(" ").append(segment.generateSql());
        }
        return sql.toString();
    }
    interface SqlSegment {
        String generateSql();
    }
}
// 攻击模拟：当用户输入order参数为"price DESC; DROP TABLE products--"时
// 生成的SQL将变为：SELECT * FROM products ORDER BY price DESC; DROP TABLE products-- DESC