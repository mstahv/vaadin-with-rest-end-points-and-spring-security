package in.virit.sb.example.security;

import in.virit.sb.example.views.LoginView;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.vaadin.flow.spring.security.AuthenticationContext;
import com.vaadin.flow.spring.security.VaadinAdvancedSecurityConfigurer;
import com.vaadin.flow.spring.security.VaadinInternalSecurityConfigurer;

@EnableWebSecurity
@Configuration
@Import(VaadinInternalSecurityConfigurer.class)
public class SecurityConfig {

    @Bean
    AuthenticationContext authenticationContext() {
        return new AuthenticationContext();
    }

    // Additional security configuration for the "private" REST API
    @Bean
    @Order(10)
    SecurityFilterChain apiSecurityFilterChain(HttpSecurity http)
            throws Exception {
        System.err.println("Configuring private API security");
        return http.securityMatcher("/api/private/**")
                // Ignoring CSRF for the private API, expected to be used by
                // other services, not
                // directly by browser clients
                .csrf(csrf -> csrf.ignoringRequestMatchers(
                        AntPathRequestMatcher.antMatcher("/api/private/**")))
                .authorizeHttpRequests(auth -> {
                    auth.anyRequest().authenticated();
                })
                // so session management/cookie is not needed
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // HttpStatusEntryPoint only sets status code, Location header
                // to login page makes no sense here
                .httpBasic(cfg -> cfg.authenticationEntryPoint(
                        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .build();
    }

    // Then open anything for the public API for the application
    @Order(20)
    @Bean
    SecurityFilterChain configurePublicApi(HttpSecurity http) throws Exception {
        http.securityMatcher(AntPathRequestMatcher.antMatcher("/api/public/**"))
                .authorizeHttpRequests(authz -> authz.anyRequest().permitAll());
        return http.build();
    }

    @Order(30)
    @Bean
    SecurityFilterChain vaadinSecurityConfig(HttpSecurity http)
            throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                AntPathRequestMatcher.antMatcher("/images/**"))
                        .permitAll())
                .with(VaadinInternalSecurityConfigurer.vaadin(),
                        vaadin -> vaadin.secureAnyRequest(
                                AuthorizeHttpRequestsConfigurer.AuthorizedUrl::authenticated))
                .with(VaadinAdvancedSecurityConfigurer.vaadinAdvanced(),
                        vaadinCfg -> vaadinCfg.loginView(LoginView.class)
                                .enableAccessControl(true)
                                .authenticationSuccessUrl("/").logoutUrl("/"))
                .build();
    }

}