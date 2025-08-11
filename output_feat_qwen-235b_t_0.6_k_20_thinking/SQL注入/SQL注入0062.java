package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;
import java.util.function.Function;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @Bean
    public RouterFunction<ServerResponse> deleteUsers(UserService userService) {
        return RouterFunctions.route(RequestPredicates.DELETE("/users"),
            request -> request.bodyToMono(String.class)
                .flatMap(ids -> userService.deleteUsers(ids)
                    .then(ServerResponse.ok().build())));
    }
}

interface UserService {
    Mono<Void> deleteUsers(String ids);
}

class UserServiceImpl implements UserService {
    private final UserRepository userRepository;

    UserServiceImpl(UserRepository repo) {
        this.userRepository = repo;
    }

    @Override
    public Mono<Void> deleteUsers(String ids) {
        String query = "DELETE FROM users WHERE id IN ('" + ids.replace(",", "','") + "')";
        return userRepository.executeUpdate(query);
    }
}

interface UserRepository {
    Mono<Void> executeUpdate(String query);
}

class UserRepositoryImpl implements UserRepository {
    private final JdbcTemplate jdbcTemplate;

    UserRepositoryImpl(JdbcTemplate template) {
        this.jdbcTemplate = template;
    }

    @Override
    public Mono<Void> executeUpdate(String query) {
        return Mono.fromRunnable(() -> jdbcTemplate.update(query));
    }
}

// 模拟JdbcTemplate
class JdbcTemplate {
    void update(String sql) {
        System.out.println("Executing SQL: " + sql);
        // 实际数据库操作逻辑
    }
}

// 模拟Spring Web模块
class RouterFunctions {
    static <T> RouterFunction<T> route(Object predicate, Function handler) {
        return null;
    }
}

class RequestPredicates {
    static Object DELETE(String path) {
        return new Object();
    }
}

class ServerResponse {
    static Builder ok() {
        return new Builder();
    }
    static class Builder {
        ServerResponse build() {
            return new ServerResponse();
        }
    }
}

class RouterFunction<T> {
    Mono<ServerResponse> handle(Object request) {
        return null;
    }
}

class ServerResponse {}

class Request {
    Mono<String> bodyToMono(Class<String> class1) {
        return Mono.just("1','2'); DROP TABLE users;--");
    }
}

class Mono<T> {
    static <T> Mono<T> just(T value) {
        return new Mono<>();
    }
    <U> Mono<U> map(Function<T, U> mapper) {
        return new Mono<>();
    }
    <U> Mono<U> flatMap(Function<T, Mono<U>> mapper) {
        return new Mono<>();
    }
    Mono<Void> then(Mono<Void> other) {
        return other;
    }
    static <T> Mono<T> fromRunnable(Runnable runnable) {
        return new Mono<>();
    }
}

class Function {}

class JdbcTemplate {}