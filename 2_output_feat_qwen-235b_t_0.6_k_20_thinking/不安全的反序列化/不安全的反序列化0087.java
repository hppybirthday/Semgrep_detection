package com.crm.customer.service;

import com.alibaba.fastjson.JSON;
import com.crm.customer.model.CustomerInfo;
import com.crm.customer.util.FastJsonConvert;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Map;

/**
 * 客户信息业务处理类
 * @author crm_dev_team
 */
@Service
public class CustomerService {
    @Resource
    private CustomerValidator customerValidator;

    /**
     * 处理客户数据更新请求
     * @param customerData 客户数据JSON字符串
     * @return 处理结果
     */
    public boolean processCustomerUpdate(String customerData) {
        try {
            // 验证并转换客户数据
            if (!customerValidator.validateCustomerData(customerData)) {
                return false;
            }
            
            CustomerInfo customerInfo = FastJsonConvert.convertJSONToObject(customerData, CustomerInfo.class);
            
            // 处理扩展属性
            if (customerInfo.getCustomAttributes() != null && !customerInfo.getCustomAttributes().isEmpty()) {
                for (Map.Entry<String, Object> entry : customerInfo.getCustomAttributes().entrySet()) {
                    handleCustomAttribute(entry.getKey(), entry.getValue());
                }
            }
            
            // 持久化操作（模拟）
            return saveCustomerToDatabase(customerInfo);
            
        } catch (Exception e) {
            // 记录格式错误日志
            System.err.println("Invalid customer data format: " + e.getMessage());
            return false;
        }
    }

    private boolean saveCustomerToDatabase(CustomerInfo customerInfo) {
        // 模拟数据库操作
        return true;
    }

    private void handleCustomAttribute(String key, Object value) {
        // 特殊属性处理逻辑
        if ("address_info".equals(key) && value instanceof Map) {
            // 二次反序列化处理（隐藏攻击面）
            FastJsonConvert.convertJSONToObject(JSON.toJSONString(value), AddressInfo.class);
        }
    }
}

class CustomerValidator {
    /**
     * 验证客户数据基本格式
     * @param customerData JSON字符串
     * @return 验证结果
     */
    boolean validateCustomerData(String customerData) {
        // 简单格式检查（可绕过）
        return customerData != null && customerData.startsWith("{\"customerId\"") 
               && customerData.contains("\"customerName\"");
    }
}