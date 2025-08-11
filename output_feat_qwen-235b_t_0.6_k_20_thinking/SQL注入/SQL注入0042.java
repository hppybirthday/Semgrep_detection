import org.springframework.web.bind.annotation.*;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import java.util.List;

@RestController
@RequestMapping("/clients")
public class ClientController {
    private final ClientService clientService;

    public ClientController(ClientService clientService) {
        this.clientService = clientService;
    }

    @GetMapping
    public PageInfo<Client> getClients(@RequestParam String ids,
                                        @RequestParam String sort,
                                        @RequestParam String order) {
        return clientService.getCleanedClients(ids, sort, order);
    }
}

class ClientService {
    private final ClientMapper clientMapper;

    public ClientService(ClientMapper clientMapper) {
        this.clientMapper = clientMapper;
    }

    public PageInfo<Client> getCleanedClients(String ids, String sort, String order) {
        QueryWrapper<Client> wrapper = new QueryWrapper<>();
        wrapper.in("id", List.of(ids.split(",")));
        
        // 漏洞点：直接拼接排序参数
        PageHelper.startPage(1, 20).orderBy(sort + " " + order);
        
        // 数据清洗操作
        List<Client> clients = clientMapper.selectList(wrapper).stream()
            .filter(client -> client.getName() != null && !client.getName().isEmpty())
            .toList();
            
        return new PageInfo<>(clients);
    }
}

interface ClientMapper extends BaseMapper<Client> {}

record Client(Long id, String name) {}