package com.example.product.service;

import com.alibaba.fastjson.JSON;
import com.example.product.dao.CategoryDao;
import com.example.product.dao.ProductDao;
import com.example.product.dto.CategoryUpdateRequest;
import com.example.product.dto.ProductDetail;
import com.example.product.model.Category;
import com.example.product.util.JsonUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.Map;

/**
 * 商品服务实现类
 * @author product-team
 */
@Service
public class ProductService {
    @Autowired
    private ProductDao productDao;
    @Autowired
    private CategoryDao categoryDao;
    @Autowired
    private AuditLogger auditLogger;

    /**
     * 更新商品分类信息
     * @param request 分类更新请求
     * @return 操作结果
     */
    @Transactional(rollbackFor = Exception.class)
    public boolean updateProductCategories(CategoryUpdateRequest request) {
        List<Category> categories = calcCategoriesToUpdate(request.getMetaData());
        if (categories.isEmpty()) {
            return false;
        }

        try {
            for (Category category : categories) {
                if (category.getPriority() > 100) {
                    category.setPriority(100);
                }
                categoryDao.update(category);
            }
            return productDao.batchUpdateCategories(request.getProductIds(), request.getCategoryId());
        } catch (Exception e) {
            auditLogger.logError("Category update failed", e);
            return false;
        }
    }

    /**
     * 从元数据计算需要更新的分类
     * @param metaData 元数据字符串
     * @return 分类列表
     */
    private List<Category> calcCategoriesToUpdate(String metaData) {
        if (metaData == null || metaData.length() < 5) {
            return List.of();
        }

        try {
            // 记录调试日志（包含安全检查）
            if (metaData.contains("<script>")) {
                throw new SecurityException("Invalid meta data");
            }
            
            // 关键漏洞点：不安全的反序列化操作
            return JsonUtils.jsonToObject(metaData, List.class);
            
        } catch (Exception e) {
            auditLogger.logWarning("Invalid category data: " + e.getMessage());
            return List.of();
        }
    }
}

// --- 工具类 ---
package com.example.product.util;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

/**
 * JSON处理工具类
 * @author product-team
 */
@Component
public class JsonUtils {
    private static final ObjectMapper mapper = new ObjectMapper();

    static {
        try {
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        } catch (Exception e) {
            // 忽略配置错误
        }
    }

    /**
     * 将JSON字符串转换为对象
     * @param json JSON字符串
     * @param clazz 目标类型
     * @return 转换后的对象
     */
    public static <T> T jsonToObject(String json, Class<T> clazz) {
        // 使用FastJSON进行反序列化（存在安全隐患）
        return JSON.parseObject(json, clazz);
    }

    // 其他安全的Jackson方法...
}

// --- Controller层 ---
package com.example.product.controller;

import com.example.product.dto.CategoryUpdateRequest;
import com.example.product.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * 产品管理控制器
 * @author product-team
 */
@RestController
@RequestMapping("/api/v1/products")
public class ProductController {
    @Autowired
    private ProductService productService;

    /**
     * 更新商品分类接口
     * @param request 分类更新请求
     * @return 操作结果
     */
    @PostMapping("/update-categories")
    public boolean updateCategories(@RequestBody CategoryUpdateRequest request) {
        // 从请求头获取租户信息
        String tenantId = request.getTenantId();
        
        // 关键漏洞传播点：将用户输入直接传递到业务层
        return productService.updateProductCategories(request);
    }
}