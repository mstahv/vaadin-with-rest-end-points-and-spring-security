package in.virit.sb.example.security;

import com.vaadin.flow.spring.security.VaadinWebSecurity;
import in.virit.sb.example.views.LoginView;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@Configuration
// Inheriting VaadinWebSecurity will take care of most configurations Spring Security for Vaadin with defaults
public class SecurityConfig extends VaadinWebSecurity {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        // Defining our Vaadin Flow based login view for the application
        setLoginView(http, LoginView.class);
    }

    // Additional security configuration for the "private" REST API
    @Bean
    @Order(10)
    SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        System.err.println("Configuring private API security");
        return http
                .securityMatcher("/api/private/**")
                // Ignoring CSRF for the private API, expected to be used by other services, not
                // directly by browser clients
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/private/**"))
                .authorizeHttpRequests(auth -> {
                    auth.anyRequest().authenticated();
                })
                // so session management/cookie is not needed
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(withDefaults())
                .build();
    }


    // Then open anything for the public API for the application
    @Order(20)
    @Bean
    SecurityFilterChain configurePublicApi(HttpSecurity http) throws Exception {
         http
                 .securityMatcher(AntPathRequestMatcher.antMatcher("/api/public/**"))
                 .authorizeRequests(authz -> authz.anyRequest().permitAll());
        return http.build();
    }

}