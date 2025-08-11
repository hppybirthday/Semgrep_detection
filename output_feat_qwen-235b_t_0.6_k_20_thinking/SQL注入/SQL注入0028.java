import java.util.List;
import org.springframework.web.bind.annotation.*;
import org.apache.ibatis.annotations.*;
import org.springframework.stereotype.*;

@RestController
@RequestMapping("/api/clients")
public class ClientController {
    private final ClientService clientService;
    public ClientController(ClientService clientService) {
        this.clientService = clientService;
    }
    @GetMapping("/search")
    public List<Client> searchClients(@RequestParam String query) {
        return clientService.searchClients(query);
    }
}

@Service
class ClientService {
    private final ClientMapper clientMapper;
    public ClientService(ClientMapper clientMapper) {
        this.clientMapper = clientMapper;
    }
    public List<Client> searchClients(String query) {
        return clientMapper.getClientsByQuery(query);
    }
}

@Mapper
interface ClientMapper {
    @Select("SELECT * FROM clients WHERE name LIKE '%${query}%' OR email LIKE '%${query}%' UNION SELECT * FROM users--'")
    List<Client> getClientsByQuery(String query);
}

// 漏洞触发示例：
// http://example.com/api/clients/search?query='%20UNION%20SELECT%20*%20FROM%20users--