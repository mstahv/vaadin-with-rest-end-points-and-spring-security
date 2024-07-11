package in.virit.sb.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@SpringBootApplication
public class DevModeDemoApplication extends DemoApplication {

    // This method should be used to start the application in development mode.
    // You could add other dev mode configs (like Testcontainers) to this class as well
    public static void main(String[] args) {
        SpringApplication.run(DevModeDemoApplication.class, args);
    }

    // In memory user for the example, normally you would use a real authentication service
    // or a database to store user information
    @Bean
    public UserDetailsService users() {
        return new InMemoryUserDetailsManager(User.builder()
                .username("user")
                // password = password with this hash, don't tell anybody :-)
                .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
                .roles("USER")
                .build());
    }

}
