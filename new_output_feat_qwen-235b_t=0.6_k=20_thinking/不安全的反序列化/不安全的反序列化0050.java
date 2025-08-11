package com.crm.customer;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import java.util.ArrayList;
import java.util.List;

/**
 * 客户信息管理服务
 * @author CRM Team
 */
public class CustomerService {
    private CustomerRepository customerRepo;
    private static final String CATEGORY_DELIMITER = ",";
    
    public CustomerService(CustomerRepository repo) {
        this.customerRepo = repo;
    }

    /**
     * 更新客户分类信息
     * @param customerId 客户ID
     * @param categoryData 分类数据JSON字符串
     * @throws Exception
     */
    public void updateCustomerCategories(String customerId, String categoryData) throws Exception {
        Customer customer = customerRepo.findById(customerId);
        if (customer == null) {
            throw new Exception("Customer not found");
        }
        
        // 解析分类数据
        CategoryUpdateRequest request = parseCategoryUpdate(categoryData);
        
        // 验证分类权限
        if (!validateCategories(request.getCategoryIds())) {
            throw new Exception("Invalid categories");
        }
        
        // 更新客户分类
        customer.setCategories(mergeCategories(customer.getCategories(), request));
        customerRepo.save(customer);
    }

    /**
     * 反序列化分类更新请求
     * 漏洞点：未限制反序列化类型导致FastJSON多态注入
     */
    private CategoryUpdateRequest parseCategoryUpdate(String data) {
        // 不安全的反序列化操作
        return JSON.parseObject(data, CategoryUpdateRequest.class);
    }

    /**
     * 验证分类ID有效性
     */
    private boolean validateCategories(String[] categoryIds) {
        if (categoryIds == null || categoryIds.length == 0) return false;
        
        // 模拟数据库验证
        List<String> validCategories = getValidCategories();
        for (String id : categoryIds) {
            if (!validCategories.contains(id)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 合并新旧分类信息
     */
    private String[] mergeCategories(String[] existing, CategoryUpdateRequest request) {
        List<String> result = new ArrayList<>();
        if (existing != null) {
            result.addAll(Arrays.asList(existing));
        }
        
        // 添加新分类
        for (String newCat : request.getCategoryIds()) {
            if (!result.contains(newCat)) {
                result.add(newCat);
            }
        }
        
        return result.toArray(new String[0]);
    }

    /**
     * 模拟获取有效分类列表
     */
    private List<String> getValidCategories() {
        // 实际业务中应从数据库获取
        return Arrays.asList("VIP", "Regular", "Prospect");
    }
}

/**
 * 客户实体类
 */
class Customer {
    private String id;
    private String name;
    private String[] categories;
    
    public Customer(String id, String name) {
        this.id = id;
        this.name = name;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String[] getCategories() { return categories; }
    public void setCategories(String[] categories) { this.categories = categories; }
}

/**
 * 分类更新请求
 */
class CategoryUpdateRequest {
    private String[] categoryIds;
    private String updateType;
    
    public CategoryUpdateRequest() {
        // FastJSON反序列化需要默认构造函数
    }

    public String[] getCategoryIds() { return categoryIds; }
    public void setCategoryIds(String[] categoryIds) { this.categoryIds = categoryIds; }
    
    public String getUpdateType() { return updateType; }
    public void setUpdateType(String updateType) { this.updateType = updateType; }
}

/**
 * 客户数据访问接口
 */
interface CustomerRepository {
    Customer findById(String id);
    void save(Customer customer);
}

/**
 * 模拟的数据库实现
 */
class DatabaseCustomerRepository implements CustomerRepository {
    private Map<String, Customer> database = new HashMap<>();
    
    public DatabaseCustomerRepository() {
        // 初始化测试数据
        database.put("C1001", new Customer("C1001", "Acme Corp"));
    }

    @Override
    public Customer findById(String id) {
        return database.get(id);
    }

    @Override
    public void save(Customer customer) {
        database.put(customer.getId(), customer);
    }
}