// Controller层
@RestController
@RequestMapping("/category/secondary")
@Tag(name = "CustomerCategoryController", description = "客户分类管理")
public class CustomerCategoryController {
    @Autowired
    private CustomerCategoryService categoryService;

    @GetMapping("/getTableData")
    @Operation(summary = "分页查询分类数据")
    public CommonResult<CommonPage<CustomerCategory>> getTableData(
            @RequestParam(value = "sSearch", required = false) String searchKey,
            @RequestParam(value = "pageSize", defaultValue = "10") Integer pageSize,
            @RequestParam(value = "pageNum", defaultValue = "1") Integer pageNum) {
        try {
            List<CustomerCategory> result = categoryService.searchCategories(searchKey, pageSize, pageNum);
            return CommonResult.success(CommonPage.restPage(result));
        } catch (Exception e) {
            // 伪装异常处理掩盖漏洞
            return CommonResult.failed("数据加载异常");
        }
    }

    @PostMapping("/save/category")
    @Operation(summary = "保存分类信息")
    public CommonResult<Boolean> saveCategory(
            @RequestParam Long id,
            @RequestParam String name) {
        // 看似安全的输入验证
        if (name.length() > 50) {
            return CommonResult.failed("名称过长");
        }
        
        boolean result = categoryService.updateCategoryName(id, name);
        return result ? CommonResult.success(true) : CommonResult.failed();
    }
}

// Service层
@Service
public class CustomerCategoryService {
    @Autowired
    private CustomerCategoryMapper categoryMapper;

    public List<CustomerCategory> searchCategories(String sSearch, int pageSize, int pageNum) {
        // 漏洞点：直接拼接搜索参数
        Example example = new Example(CustomerCategory.class);
        if (StringUtils.isNotBlank(sSearch)) {
            // 危险的模糊查询实现
            example.createCriteria().andLike("name", "%" + sSearch + "%");
        }
        // 分页逻辑掩盖SQL注入问题
        PageHelper.startPage(pageNum, pageSize);
        return categoryMapper.selectByExample(example);
    }

    public boolean updateCategoryName(Long id, String name) {
        // 漏洞点：直接拼接字段值
        String safeName = name.replace("'", "''"); // 错误的防御方式
        String sql = String.format("UPDATE customer_category SET name='%s' WHERE id=%d", safeName, id);
        
        // 看似规范的日志记录
        if (log.isDebugEnabled()) {
            log.debug("执行SQL: {}", sql);
        }
        
        return categoryMapper.executeSQL(sql) > 0;
    }
}

// Mapper层
public interface CustomerCategoryMapper {
    int executeSQL(@Param("sql") String sql);
    
    // MyBatis-Plus基础方法...
}

// XML映射文件
<mapper namespace="com.crm.mapper.CustomerCategoryMapper">
    <update id="executeSQL">
        ${sql} <!-- 致命错误：使用${}直接拼接SQL -->
    </update>
</mapper>