package com.vaadin.flow.spring.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.DelegatingAccessDeniedHandler;
import org.springframework.security.web.access.RequestMatcherDelegatingAccessDeniedHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.context.WebApplicationContext;

import com.vaadin.flow.component.Component;
import com.vaadin.flow.internal.AnnotationReader;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.internal.RouteUtil;
import com.vaadin.flow.server.VaadinServletContext;
import com.vaadin.flow.server.auth.NavigationAccessControl;
import com.vaadin.flow.spring.VaadinConfigurationProperties;

import static com.vaadin.flow.spring.security.VaadinWebSecurity.getDefaultHttpSecurityPermitMatcher;
import static com.vaadin.flow.spring.security.VaadinWebSecurity.getDefaultWebSecurityIgnoreMatcher;

public class VaadinSecurityConfigurer
        extends AbstractHttpConfigurer<VaadinSecurityConfigurer, HttpSecurity> {

    private Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizedUrl> anyRequestCustomizer;
    VaadinSavedRequestAwareAuthenticationSuccessHandler vaadinSavedRequestAwareAuthenticationSuccessHandler = new VaadinSavedRequestAwareAuthenticationSuccessHandler();

    @Value("#{servletContext.contextPath}")
    private String servletContextPath;

    private VaadinConfigurationProperties vaadinConfigurationProperties;
    private RequestUtil requestUtil;

    private String loginPath;
    private Class<? extends Component> loginViewClass;
    private String logoutUrl;
    private boolean enableAccessControl = true;
    private String defaultAuthenticationSuccessUrl = "/";
    private Boolean invalidateSessionOnLogout;
    private List<LogoutHandler> logoutHandlers;

    public static VaadinSecurityConfigurer vaadin() {
        return new VaadinSecurityConfigurer();
    }

    public VaadinSecurityConfigurer secureAnyRequest(
            Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizedUrl> customizer) {
        anyRequestCustomizer = customizer;
        return this;
    }

    public VaadinSecurityConfigurer loginView(
            Class<? extends Component> loginViewClass) {
        this.loginViewClass = loginViewClass;
        return this;
    }

    public VaadinSecurityConfigurer loginView(String hillaLoginViewPath) {
        loginPath = hillaLoginViewPath;
        return this;
    }

    public VaadinSecurityConfigurer logoutUrl(String logoutUrl) {
        this.logoutUrl = logoutUrl;
        return this;
    }

    public VaadinSecurityConfigurer addLogoutHandler(
            LogoutHandler logoutHandler) {
        if (logoutHandlers == null) {
            logoutHandlers = new ArrayList<>();
        }
        logoutHandlers.add(logoutHandler);
        return this;
    }

    public VaadinSecurityConfigurer enableAccessControl(
            boolean enableAccessControl) {
        this.enableAccessControl = enableAccessControl;
        return this;
    }

    public VaadinSecurityConfigurer oauth2LoginPage(String loginPage) {
        // TODO
        return this;
    }

    public VaadinSecurityConfigurer invalidateSessionOnLogout() {
        this.invalidateSessionOnLogout = true;
        return this;
    }

    // TODO: can be extended with a
    // VaadinAuthenticationSuccessHandlerConfigurer that can be fine tuned
    public VaadinSecurityConfigurer authenticationSuccessUrl(
            String defaultAuthenticationSuccessUrl) {
        this.defaultAuthenticationSuccessUrl = defaultAuthenticationSuccessUrl;
        return this;
    }

    @Override
    public void setBuilder(HttpSecurity http) {
        super.setBuilder(http);
        ApplicationContext context = http
                .getSharedObject(ApplicationContext.class);
        requestUtil = context.getBean(RequestUtil.class);
        vaadinConfigurationProperties = context
                .getBean(VaadinConfigurationProperties.class);
        try {
            applyDefaultHttpRequestAuthorization(http);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        ApplicationContext context = http
                .getSharedObject(ApplicationContext.class);
        // RequestUtil requestUtil = context.getBean(RequestUtil.class);
        http.setSharedObject(RequestUtil.class, requestUtil);

        // initRequiredConfiguration(http, requestUtil,
        // configurationProperties);
        initRequiredConfiguration(http);

        String computedAuthenticationSuccessUrl = computeAuthenticationSuccessUrl(
                requestUtil);
        if (computedAuthenticationSuccessUrl != null) {
            vaadinSavedRequestAwareAuthenticationSuccessHandler
                    .setDefaultTargetUrl(computedAuthenticationSuccessUrl);
        }
        String computedLoginPath = computeLoginPath(context, requestUtil);
        if (computedLoginPath != null) {

            VaadinDefaultRequestCache vaadinDefaultRequestCache = context
                    .getBean(VaadinDefaultRequestCache.class);
            http.requestCache(
                    cfg -> cfg.requestCache(vaadinDefaultRequestCache));

            http.formLogin(formLogin -> {
                formLogin.loginPage(computedLoginPath).permitAll();
                formLogin.successHandler(
                        vaadinSavedRequestAwareAuthenticationSuccessHandler);
            });
            http.csrf(cfg -> cfg.ignoringRequestMatchers(
                    new AntPathRequestMatcher(computedLoginPath)));

            configureLogout(http, getLogoutUrl());
            http.exceptionHandling(
                    cfg -> cfg.defaultAuthenticationEntryPointFor(
                            new LoginUrlAuthenticationEntryPoint(
                                    computedLoginPath),
                            AnyRequestMatcher.INSTANCE));

            http.logout(cfg -> {
                if (invalidateSessionOnLogout != null) {
                    cfg.invalidateHttpSession(invalidateSessionOnLogout);
                }
                if (logoutHandlers != null) {
                    logoutHandlers.forEach(cfg::addLogoutHandler);
                }
            });
        }
        NavigationAccessControl accessControl = context
                .getBean(NavigationAccessControl.class);

        if (enableAccessControl) {
            if (this.loginViewClass != null) {
                accessControl.setLoginView(loginViewClass);
            } else {
                accessControl.setLoginView(computedLoginPath);
            }

            context.getBeanProvider(VaadinRolePrefixHolder.class).ifAvailable(
                    bean -> http.setSharedObject(VaadinRolePrefixHolder.class,
                            bean));
            context.getBeanProvider(AuthenticationContext.class).ifAvailable(
                    bean -> http.setSharedObject(AuthenticationContext.class,
                            bean));
        } else {
            accessControl.setEnabled(false);
        }

    }

    private void initRequiredConfiguration(HttpSecurity http) throws Exception {
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
            if (anyRequestCustomizer != null) {
                anyRequestCustomizer.customize(urlRegistry.anyRequest());
            }
        });
    }

    private void initRequiredConfigurationOri(HttpSecurity http,
            RequestUtil requestUtil,
            VaadinConfigurationProperties configurationProperties)
            throws Exception {
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

    private void applyDefaultHttpRequestAuthorization(HttpSecurity http)
            throws Exception {
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
                            vaadinConfigurationProperties.getUrlMapping()))
                    .permitAll();
            // matcher for Vaadin static (public) resources
            urlRegistry
                    .requestMatchers(getDefaultWebSecurityIgnoreMatcher(
                            vaadinConfigurationProperties.getUrlMapping()))
                    .permitAll();
            // matcher for custom PWA icons and favicon
            urlRegistry.requestMatchers(requestUtil::isCustomWebIcon)
                    .permitAll();
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

    private String computeAuthenticationSuccessUrl(RequestUtil requestUtil) {
        String url = this.defaultAuthenticationSuccessUrl;
        if (url == null) {
            url = requestUtil.applyUrlMapping("/");
        }
        return url;
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        RequestCache requestCache = builder.getSharedObject(RequestCache.class);
        if (requestCache != null) {
            vaadinSavedRequestAwareAuthenticationSuccessHandler
                    .setRequestCache(requestCache);
        }
        if (enableAccessControl) {
            // TODO: role prefix from SecurityContextHolderAwareRequestFilter
            // VaadinRolePrefixHolder vaadinRolePrefixHolder = builder
            // .getSharedObject(VaadinRolePrefixHolder.class);
            // ServletApiConfigurer servletApiConfigurer = builder
            // .getConfigurer(ServletApiConfigurer.class);
            AuthenticationContext authContext = builder
                    .getSharedObject(AuthenticationContext.class);
            if (authContext != null) {
                LogoutConfigurer<?> logoutConfigurer = builder
                        .getConfigurer(LogoutConfigurer.class);
                authContext.setLogoutHandlers(
                        logoutConfigurer.getLogoutSuccessHandler(),
                        logoutConfigurer.getLogoutHandlers());

            }
        }
    }

    private String getLogoutUrl() {
        if (logoutUrl != null) {
            return logoutUrl;
        }
        return servletContextPath.startsWith("/") ? servletContextPath
                : "/" + servletContextPath;
    }

    private String computeLoginPath(ApplicationContext applicationContext,
            RequestUtil requestUtil) {
        String loginPath = this.loginPath;
        if (loginViewClass != null) {
            Optional<Route> route = AnnotationReader
                    .getAnnotationFor(loginViewClass, Route.class);

            if (route.isEmpty()) {
                throw new IllegalArgumentException(
                        "Unable find a @Route annotation on the login view "
                                + loginViewClass.getName());
            }

            /*
             * TODO if (!(applicationContext instanceof WebApplicationContext))
             * { throw new RuntimeException(
             * "VaadinWebSecurity cannot be used without WebApplicationContext."
             * ); }
             */

            VaadinServletContext vaadinServletContext = new VaadinServletContext(
                    ((WebApplicationContext) applicationContext)
                            .getServletContext());
            loginPath = RouteUtil.getRoutePath(vaadinServletContext,
                    loginViewClass);
            if (!loginPath.startsWith("/")) {
                loginPath = "/" + loginPath;
            }
        }
        if (loginPath != null) {
            loginPath = requestUtil.applyUrlMapping(loginPath);
        }
        return loginPath;
    }

    private void configureLogout(HttpSecurity http, String logoutSuccessUrl)
            throws Exception {
        SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
        logoutSuccessHandler.setDefaultTargetUrl(logoutSuccessUrl);
        logoutSuccessHandler.setRedirectStrategy(new UidlRedirectStrategy());
        http.logout(cfg -> cfg.logoutSuccessHandler(logoutSuccessHandler));
    }

}
