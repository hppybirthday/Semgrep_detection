// Controller层
@RestController
@RequestMapping("/feedback")
@Api(tags="用户反馈查询")
public class FeedbackController {
    @Autowired
    private FeedbackService feedbackService;

    @GetMapping("list")
    @ApiOperation("分页查询反馈数据")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "productName", paramType = "query", dataType = "string"),
        @ApiImplicitParam(name = "sortField", paramType = "query", dataType = "string")
    })
    public Result<PageData<FeedbackDTO>> queryFeedbacks(
        @RequestParam Map<String, Object> params) {
        
        // 调用服务层处理业务逻辑
        PageData<FeedbackDTO> result = feedbackService.getFeedbacks(params);
        return new Result<>().ok(result);
    }
}

// Service层
@Service
public class FeedbackService {
    @Autowired
    private FeedbackDAO feedbackDAO;

    // 模拟业务逻辑处理
    public PageData<FeedbackDTO> getFeedbacks(Map<String, Object> params) {
        // 1. 参数预处理（看似安全的校验）
        if (params.containsKey("productName")) {
            // 仅校验长度未过滤特殊字符
            String product = (String) params.get("productName");
            if (product.length() > 50) {
                throw new IllegalArgumentException("产品名称过长");
            }
        }

        // 2. 调用DAO层查询数据
        List<FeedbackDTO> dataList = feedbackDAO.searchFeedbacks(params);
        
        // 3. 构造分页结果
        return new PageData<>(dataList, dataList.size());
    }
}

// DAO层（漏洞触发点）
@Repository
public interface FeedbackDAO {
    @Select({"<script>",
      "SELECT * FROM user_feedback WHERE 1=1",
      "<if test='productName != null'>",
        "AND product_name = '${productName}'",  // 危险的拼接方式
      "</if>",
      "ORDER BY ${sortField}",  // 未验证字段名直接拼接
      "</script>"})
    @Results({
        @Result(property = "id", column = "id"),
        @Result(property = "content", column = "content")
    })
    List<FeedbackDTO> searchFeedbacks(Map<String, Object> params);
}

// 数据模型
class FeedbackDTO {
    private Long id;
    private String content;
    // getter/setter省略
}