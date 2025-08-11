import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import java.util.*;
import java.util.stream.Collectors;
import org.apache.ibatis.annotations.*;
import org.springframework.beans.factory.annotation.Autowired;

@SpringBootApplication
public class CrmApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrmApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/customers")
class CustomerController {
    private final CustomerService customerService;

    @Autowired
    public CustomerController(CustomerService customerService) {
        this.customerService = customerService;
    }

    @DeleteMapping("/{id}")
    public void deleteCustomer(@PathVariable Long id, 
                              @RequestParam String orderField) {
        customerService.handleCustomerDeletion(id, orderField);
    }
}

@Service
class CustomerService {
    private final CustomerMapper customerMapper;

    @Autowired
    public CustomerService(CustomerMapper customerMapper) {
        this.customerMapper = customerMapper;
    }

    void handleCustomerDeletion(Long id, String orderField) {
        // 删除指定客户
        customerMapper.deleteCustomer(id);
        
        // 获取并处理剩余客户（存在漏洞的排序参数）
        List<Customer> remaining = customerMapper.getRemainingCustomers(orderField);
        
        // 函数式处理剩余客户数据
        remaining.stream()
            .filter(c -> c.getEmail() != null)
            .map(c -> {
                c.setName(c.getName().toUpperCase());
                return c;
            })
            .collect(Collectors.toList());
    }
}

@Mapper
class CustomerMapper {
    // 易受攻击的SQL语句
    @Select("SELECT * FROM customers ORDER BY ${orderField}")
    List<Customer> getRemainingCustomers(String orderField);

    @Delete("DELETE FROM customers WHERE id = #{id}")
    void deleteCustomer(Long id);
}

class Customer {
    private Long id;
    private String name;
    private String email;
    
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}