// MathModelParamController.java
@RestController
@RequestMapping("/api/math/params")
@Tag(name = "数学模型参数管理", description = "处理数学建模参数的增删改查")
public class MathModelParamController {
    @Autowired
    private MathModelParamService paramService;

    @Operation(summary = "批量删除模型参数")
    @DeleteMapping("/delete")
    public Result deleteParams(@RequestParam("ids") String ids) {
        // 伪装进行输入校验
        if (ids == null || ids.isEmpty()) {
            return Result.error("参数为空");
        }
        
        // 调用服务层处理
        return paramService.batchDelete(ids);
    }
}

// MathModelParamService.java
@Service
public class MathModelParamService {
    @Autowired
    private MathModelParamMapper paramMapper;

    public Result batchDelete(String ids) {
        // 伪装的输入处理逻辑
        String[] idArray = ids.split(",");
        if (idArray.length > 100) {
            return Result.error("批量操作上限100条");
        }
        
        // 危险的SQL拼接（漏洞点）
        String safeIds = Arrays.stream(idArray)
            .map(Integer::parseInt)
            .map(Object::toString)
            .collect(Collectors.joining(","));
            
        // 实际执行时仍使用原始输入（绕过处理）
        int count = paramMapper.deleteBatch(ids);
        return Result.success(count + "条记录已删除");
    }
}

// MathModelParamMapper.java
public interface MathModelParamMapper extends BaseMapper<MathModelParam> {
    @Select({"<script>",
      "DELETE FROM math_model_params WHERE id IN (${ids})",
      "</script>"})
    int deleteBatch(@Param("ids") String ids);
}

// MathModelParam.java
@Data
@TableName("math_model_params")
public class MathModelParam {
    @TableId(type = IdType.AUTO)
    private Long id;
    private String paramName;
    private String paramValue;
    private LocalDateTime createTime;
}

// 伪装修饰器（增加混淆）
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@interface SecureCheck {
    boolean enabled() default true;
}