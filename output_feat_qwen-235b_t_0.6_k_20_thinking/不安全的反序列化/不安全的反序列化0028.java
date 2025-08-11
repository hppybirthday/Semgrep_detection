import com.alibaba.fastjson.JSON;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class CustomerController {
    @PostMapping("/add")
    public String addCustomer(@RequestBody String json) {
        Customer customer = JSON.parseObject(json, Customer.class);
        return "Customer added: " + customer.getName();
    }
}

class Customer {
    private String name;
    private int id;
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
}