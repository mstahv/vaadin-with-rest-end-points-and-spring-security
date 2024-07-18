package com.vaadin.flow.spring.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.DelegatingAccessDeniedHandler;
import org.springframework.security.web.access.RequestMatcherDelegatingAccessDeniedHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.vaadin.flow.spring.VaadinConfigurationProperties;

import static com.vaadin.flow.spring.security.VaadinWebSecurity.getDefaultHttpSecurityPermitMatcher;
import static com.vaadin.flow.spring.security.VaadinWebSecurity.getDefaultWebSecurityIgnoreMatcher;

//@Import({ VaadinAwareSecurityContextHolderStrategyConfiguration.class,
//        RequestUtil.class })
//@Configuration
// @ConditionalOnClass // TODO
public class VaadinInternalSecurityConfigurer extends
        AbstractHttpConfigurer<VaadinInternalSecurityConfigurer, HttpSecurity> {

    private Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizedUrl> anyRequestCustomizer;

    public static VaadinInternalSecurityConfigurer vaadin() {
        return new VaadinInternalSecurityConfigurer();
    }

    public VaadinInternalSecurityConfigurer secureAnyRequest(
            Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizedUrl> customizer) {
        anyRequestCustomizer = customizer;
        return this;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        ApplicationContext context = http
                .getSharedObject(ApplicationContext.class);
        RequestUtil requestUtil = context.getBean(RequestUtil.class);
        http.setSharedObject(RequestUtil.class, requestUtil);

        VaadinConfigurationProperties configurationProperties = context
                .getBean(VaadinConfigurationProperties.class);

        // Respond with 401 Unauthorized HTTP status code for unauthorized
        // requests for protected Hilla endpoints, so that the response could
        // be handled on the client side using e.g. `InvalidSessionMiddleware`.
        http.exceptionHandling(cfg -> cfg
                .accessDeniedHandler(createAccessDeniedHandler(requestUtil))
                .defaultAuthenticationEntryPointFor(
                        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                        requestUtil::isEndpointRequest));

        // Vaadin has its own CSRF protection.
        // Spring CSRF is not compatible with Vaadin internal requests
        http.csrf(cfg -> cfg.ignoringRequestMatchers(
                requestUtil::isFrameworkInternalRequest));

        http.authorizeHttpRequests(urlRegistry -> {
            // Vaadin internal requests must always be allowed to allow public
            // Flow pages and/or login page implemented using Flow.
            urlRegistry.requestMatchers(requestUtil::isFrameworkInternalRequest)
                    .permitAll();
            // Public endpoints are OK to access
            urlRegistry.requestMatchers(requestUtil::isAnonymousEndpoint)
                    .permitAll();
            // Checks for known Hilla views
            urlRegistry.requestMatchers(requestUtil::isAllowedHillaView)
                    .permitAll();
            // Public routes are OK to access
            urlRegistry.requestMatchers(requestUtil::isAnonymousRoute)
                    .permitAll();
            urlRegistry
                    .requestMatchers(getDefaultHttpSecurityPermitMatcher(
                            configurationProperties.getUrlMapping()))
                    .permitAll();
            // matcher for Vaadin static (public) resources
            urlRegistry
                    .requestMatchers(getDefaultWebSecurityIgnoreMatcher(
                            configurationProperties.getUrlMapping()))
                    .permitAll();
            // matcher for custom PWA icons and favicon
            urlRegistry.requestMatchers(requestUtil::isCustomWebIcon)
                    .permitAll();

            if (anyRequestCustomizer != null) {
                anyRequestCustomizer.customize(urlRegistry.anyRequest());
            }
        });
    }

    private AccessDeniedHandler createAccessDeniedHandler(
            RequestUtil requestUtil) {
        final AccessDeniedHandler defaultHandler = new AccessDeniedHandlerImpl();

        final AccessDeniedHandler http401UnauthorizedHandler = new Http401UnauthorizedAccessDeniedHandler();

        final LinkedHashMap<Class<? extends AccessDeniedException>, AccessDeniedHandler> exceptionHandlers = new LinkedHashMap<>();
        exceptionHandlers.put(CsrfException.class, http401UnauthorizedHandler);

        final LinkedHashMap<RequestMatcher, AccessDeniedHandler> matcherHandlers = new LinkedHashMap<>();
        matcherHandlers.put(requestUtil::isEndpointRequest,
                new DelegatingAccessDeniedHandler(exceptionHandlers,
                        new AccessDeniedHandlerImpl()));

        return new RequestMatcherDelegatingAccessDeniedHandler(matcherHandlers,
                defaultHandler);
    }

    private static class Http401UnauthorizedAccessDeniedHandler
            implements AccessDeniedHandler {
        @Override
        public void handle(HttpServletRequest request,
                HttpServletResponse response,
                AccessDeniedException accessDeniedException)
                throws IOException, ServletException {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
        }
    }

}
