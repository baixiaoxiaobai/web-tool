
package com.tools.auth.server.oauth2;

import com.tools.auth.server.oauth2.client.RedisClientDetailsService;
import com.tools.auth.server.oauth2.code.RedisAuthorizationCodeServices;
import com.tools.auth.server.oauth2.token.store.RedisTemplateTokenStore;
import com.tools.common.core.utils.PermitUrlProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.code.RandomValueAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.sql.DataSource;

/**
 * 认证服务器
* @ClassName: 	OAuth2ServerConfig.java
* @Description: 该类的功能描述：
* @date: 		2019年5月6日
 */
@Configuration
public class OAuth2ServerConfig {

    @Resource
    private DataSource dataSource;
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 声明 ClientDetails实现
     */
    @Bean
    public RedisClientDetailsService redisClientDetailsService() {
        RedisClientDetailsService clientDetailsService = new RedisClientDetailsService(dataSource);
        clientDetailsService.setRedisTemplate(redisTemplate);
        return clientDetailsService;
    }


    @Bean
    public RandomValueAuthorizationCodeServices authorizationCodeServices() {
        RedisAuthorizationCodeServices redisAuthorizationCodeServices = new RedisAuthorizationCodeServices();
        redisAuthorizationCodeServices.setRedisTemplate(redisTemplate);
        return redisAuthorizationCodeServices;
    }

    /**
     * @author owen 624191343@qq.com
     * @version 创建时间：2017年11月12日 上午22:57:51 默认token存储在内存中
     * DefaultTokenServices默认处理
     */
    @Component
    @Configuration
    @EnableAuthorizationServer
    @AutoConfigureAfter(AuthorizationServerEndpointsConfigurer.class)
    public class UnieapAuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
        /**
         * 注入authenticationManager 来支持 password grant type
         */
        @Autowired
        private AuthenticationManager authenticationManager;

        @Autowired
        private UserDetailsService userDetailsService;
        @Autowired(required = false)
        private RedisTemplateTokenStore redisTokenStore;

        @Autowired(required = false)
        private JwtTokenStore jwtTokenStore;
        @Autowired(required = false)
        private JwtAccessTokenConverter jwtAccessTokenConverter;

        @Autowired
        private WebResponseExceptionTranslator webResponseExceptionTranslator;

        @Autowired
        private RedisClientDetailsService redisClientDetailsService;

        @Autowired(required = false)
        private RandomValueAuthorizationCodeServices authorizationCodeServices;

        /**
         * 配置身份认证器，配置认证方式，TokenStore，TokenGranter，OAuth2RequestFactory
         */
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

            if (jwtTokenStore != null) {
                endpoints.tokenStore(jwtTokenStore).authenticationManager(authenticationManager)
                        // 支持
                        .userDetailsService(userDetailsService);
                // password
                // grant
                // type;
            } else if (redisTokenStore != null) {
                endpoints.tokenStore(redisTokenStore).authenticationManager(authenticationManager)
                        // 支持
                        .userDetailsService(userDetailsService);
                // password
                // grant
                // type;
            }

            if (jwtAccessTokenConverter != null) {
                endpoints.accessTokenConverter(jwtAccessTokenConverter);
            }

            endpoints.authorizationCodeServices(authorizationCodeServices);

            endpoints.exceptionTranslator(webResponseExceptionTranslator);

        }

        /**
         * 配置应用名称 应用id
         * 配置OAuth2的客户端相关信息
         */
        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.withClientDetails(redisClientDetailsService);
            redisClientDetailsService.loadAllClientToCache();
        }

        /**
         * 对应于配置AuthorizationServer安全认证的相关信息，创建ClientCredentialsTokenEndpointFilter核心过滤器
         */
        @Override
        public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
            // url:/oauth/token_key,exposes
            security.tokenKeyAccess("permitAll()")
                    .checkTokenAccess("isAuthenticated()")
                    // allow check token
                    .allowFormAuthenticationForClients();

        }

    }
    
    
    /**
     * 资源服务器配置
    * @Description: 该函数的功能描述： 
    * @date: 		2019年5月6日
     */
    @Configuration
    @EnableResourceServer
    @EnableConfigurationProperties(PermitUrlProperties.class)
    public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    	//url白名单处理 application.yml中配置需要放权的url白名单
        @Autowired
        private PermitUrlProperties permitUrlProperties;

        
        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.requestMatcher(
                    /**
                     * 判断来源请求是否包含oauth2授权信息
                     */
                    new RequestMatcher() {
                        private AntPathMatcher antPathMatcher = new AntPathMatcher();

                        @Override
                        public boolean matches(HttpServletRequest request) {
	                          if (antPathMatcher.match("/oauth/user/**", request.getRequestURI())) {
	                        	  return true;
	                          }
                            return false;
                        }
                    }

            ).authorizeRequests().antMatchers(permitUrlProperties.getIgnored()).permitAll().anyRequest()
                    .authenticated();
        }

    }

}
