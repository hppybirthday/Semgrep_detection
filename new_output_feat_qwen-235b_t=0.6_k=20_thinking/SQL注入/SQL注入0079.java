// Controller层
@RestController
@RequestMapping("\\/product")
@Api(tags = "商品管理")
public class ProductController {
    @Autowired
    private ProductService productService;

    @GetMapping("list")
    @ApiOperation("分页查询商品")
    public Result<PageData<ProductDTO>> list(@RequestParam Map<String, Object> params) {
        return new Result<>().ok(productService.queryProducts(params));
    }
}

// Service层
@Service
public class ProductService {
    @Autowired
    private ProductDAO productDAO;

    public PageData<ProductDTO> queryProducts(Map<String, Object> params) {
        String queryText = (String) params.get("queryText");
        Integer categoryId = (Integer) params.get("categoryId");
        int pageNum = Integer.parseInt(params.get("page").toString());
        int pageSize = Integer.parseInt(params.get("limit").toString());
        
        // 潜在漏洞点：未过滤特殊字符直接拼接
        if (queryText != null && !queryText.isEmpty()) {
            queryText = queryText.replace(" ", ""); // 错误的过滤尝试
        }
        
        return productDAO.searchProducts(queryText, categoryId, pageNum, pageSize);
    }
}

// DAO层
@Repository
public class ProductDAO {
    @Autowired
    private SQLManager sqlManager;

    public PageData<ProductDTO> searchProducts(String queryText, Integer categoryId, int pageNum, int pageSize) {
        StringBuilder sql = new StringBuilder("SELECT * FROM product WHERE 1=1");
        
        if (categoryId != null) {
            sql.append(" AND category_id = ").append(categoryId); // 正确的参数化方式被忽视
        }
        
        if (queryText != null && !queryText.isEmpty()) {
            // 致命漏洞：直接拼接查询条件
            sql.append(" AND name LIKE '%").append(queryText).append("%' ");
        }
        
        // 分页处理
        sql.append(" LIMIT ").append((pageNum - 1) * pageSize).append(",").append(pageSize);
        
        List<ProductDTO> result = sqlManager.execute(sql.toString(), ProductDTO.class);
        int total = sqlManager.count(sql.toString());
        
        return new PageData<>(result, total);
    }
}

// 实体类
@Data
public class ProductDTO {
    private Long id;
    private String name;
    private BigDecimal price;
    private Integer stock;
    private String description;
}

// 分页工具类
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PageData<T> {
    private List<T> list;
    private int total;
    private int pageNum;
    private int pageSize;
    
    public static <T> PageData<T> restPage(List<T> list) {
        return new PageData<>(list, list.size(), 1, 10);
    }
}

// 通用结果封装
class Result<T> {
    private int code;
    private String msg;
    private T data;
    
    public Result<T> ok(T data) {
        this.code = 200;
        this.data = data;
        return this;
    }
}