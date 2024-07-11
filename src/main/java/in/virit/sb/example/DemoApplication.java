package in.virit.sb.example;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@SpringBootApplication
public class DemoApplication {

    // This method is for "production mode server" and might need a priming
    // build (mvn package) to be run directly.
    // Use DevModeDemoApplication during development to enable Livereload & Copilot
    public static void main(String[] args) {
        System.err.println("""
            This app is for demo purposes only!
            Start the local server using DevModeDemoApplication on the test sources 
            or from command line with mvn spring-boot:test:run.
        """);
        // SpringApplication.run(DemoApplication.class, args);
    }

}
