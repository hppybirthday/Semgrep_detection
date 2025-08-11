import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/cart")
public class ShoppingCartController {
    private final RedisTemplate<String, String> redisTemplate;

    public ShoppingCartController(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @GetMapping("/view")
    public String viewCart(@RequestParam String uuid) {
        String cartData = redisTemplate.opsForValue().get("cart:" + uuid);
        if (cartData == null) return "Empty cart";
        
        // 不安全的反序列化操作
        JSONObject cart = (JSONObject) JSON.parse(cartData);
        List<CartItem> items = cart.getJSONArray("items")
            .stream()
            .map(obj -> JSON.toJavaObject((JSONObject) obj, CartItem.class))
            .collect(Collectors.toList());
            
        return renderCart(items);
    }

    @PostMapping("/add")
    public String addToCart(@RequestParam String uuid, @RequestBody CartItem item) {
        String cartKey = "cart:" + uuid;
        String cartData = redisTemplate.opsForValue().get(cartKey);
        JSONObject cart = cartData != null ? (JSONObject) JSON.parse(cartData) : new JSONObject();
        
        cart.getJSONArray("items").add(JSON.toJSON(item));
        redisTemplate.opsForValue().set(cartKey, cart.toJSONString());
        return "Added";
    }

    private String renderCart(List<CartItem> items) {
        return "<html><body><ul>" + 
            items.stream()
                .map(item -> "<li>" + item.getName() + " x" + item.getQuantity() + "</li>")
                .collect(Collectors.joining()) +
            "</ul></body></html>";
    }

    static class CartItem {
        private String name;
        private int quantity;
        // getters/setters
    }
}