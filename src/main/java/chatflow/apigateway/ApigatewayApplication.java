package chatflow.apigateway;

import com.netflix.discovery.EurekaClient;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@RequiredArgsConstructor
@SpringBootApplication
public class ApigatewayApplication {
    private final EurekaClient eurekaClient;

    public static void main(String[] args) {
        SpringApplication.run(ApigatewayApplication.class, args);
    }

    @PreDestroy
    public void unregister() {
        eurekaClient.shutdown();
    }
}
