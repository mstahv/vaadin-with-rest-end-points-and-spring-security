package com.vaadin.flow.spring.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.web.context.WebApplicationContext;

import com.vaadin.flow.component.Component;
import com.vaadin.flow.internal.AnnotationReader;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.internal.RouteUtil;
import com.vaadin.flow.server.VaadinServletContext;
import com.vaadin.flow.server.auth.NavigationAccessControl;

/**
 * https://docs.spring.io/spring-security/reference/servlet/configuration/java.html#jc-custom-dsls
 */
public class VaadinAdvancedSecurityConfigurer extends
        AbstractHttpConfigurer<VaadinAdvancedSecurityConfigurer, HttpSecurity> {

    VaadinSavedRequestAwareAuthenticationSuccessHandler vaadinSavedRequestAwareAuthenticationSuccessHandler = new VaadinSavedRequestAwareAuthenticationSuccessHandler();

    @Value("#{servletContext.contextPath}")
    private String servletContextPath;

    private String loginPath;
    private Class<? extends Component> loginViewClass;
    private String logoutUrl;
    private boolean enableAccessControl = true;
    private String defaultAuthenticationSuccessUrl = "/";
    private Boolean invalidateSessionOnLogout;
    private List<LogoutHandler> logoutHandlers;

    public static VaadinAdvancedSecurityConfigurer vaadinAdvanced() {
        return new VaadinAdvancedSecurityConfigurer();
    }

    public VaadinAdvancedSecurityConfigurer loginView(
            Class<? extends Component> loginViewClass) {
        this.loginViewClass = loginViewClass;
        return this;
    }

    public VaadinAdvancedSecurityConfigurer loginView(
            String hillaLoginViewPath) {
        loginPath = hillaLoginViewPath;
        return this;
    }

    public VaadinAdvancedSecurityConfigurer logoutUrl(String logoutUrl) {
        this.logoutUrl = logoutUrl;
        return this;
    }

    public VaadinAdvancedSecurityConfigurer addLogoutHandler(
            LogoutHandler logoutHandler) {
        if (logoutHandlers == null) {
            logoutHandlers = new ArrayList<>();
        }
        logoutHandlers.add(logoutHandler);
        return this;
    }

    public VaadinAdvancedSecurityConfigurer enableAccessControl(
            boolean enableAccessControl) {
        this.enableAccessControl = enableAccessControl;
        return this;
    }

    public VaadinAdvancedSecurityConfigurer oauth2LoginPage(String loginPage) {
        // TODO
        return this;
    }

    public VaadinAdvancedSecurityConfigurer invalidateSessionOnLogout() {
        this.invalidateSessionOnLogout = true;
        return this;
    }

    // TODO: can be extended with a
    // VaadinAuthenticationSuccessHandlerConfigurer that can be fine tuned
    public VaadinAdvancedSecurityConfigurer authenticationSuccessUrl(
            String defaultAuthenticationSuccessUrl) {
        this.defaultAuthenticationSuccessUrl = defaultAuthenticationSuccessUrl;
        return this;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        ApplicationContext context = http
                .getSharedObject(ApplicationContext.class);
        RequestUtil requestUtil = context.getBean("requestUtil",
                RequestUtil.class);
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

    static void apply(HttpSecurity http,
            Customizer<VaadinAdvancedSecurityConfigurer> customizer)
            throws Exception {
        VaadinAdvancedSecurityConfigurer configurer = http
                .getConfigurer(VaadinAdvancedSecurityConfigurer.class);
        if (configurer == null) {
            configurer = new VaadinAdvancedSecurityConfigurer();
        }
        http.with(configurer, customizer);
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
