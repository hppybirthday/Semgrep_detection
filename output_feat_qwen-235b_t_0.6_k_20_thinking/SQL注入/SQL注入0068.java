import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/favorites")
class FavoriteController {
    @Autowired
    private FavoriteService favoriteService;

    @GetMapping("/list")
    List<CmsSubjectCategory> listFavorites(@RequestParam String categoryId) {
        return favoriteService.getFavorites(categoryId);
    }
}

@Service
class FavoriteService {
    @Autowired
    private FavoriteDAO favoriteDAO;

    List<CmsSubjectCategory> getFavorites(String categoryId) {
        return favoriteDAO.findByCategoryId(categoryId);
    }
}

@Repository
class FavoriteDAO {
    @Autowired
    private SQLManager beetlSQLTemplate;

    List<CmsSubjectCategory> findByCategoryId(String categoryId) {
        String sql = "SELECT * FROM cms_subject_category WHERE category_id = '" + categoryId + "'";
        return beetlSQLTemplate.query(sql, CmsSubjectCategory.class);
    }
}

class CmsSubjectCategory {
    String id;
    String categoryId;
    // 其他字段及getter/setter
}