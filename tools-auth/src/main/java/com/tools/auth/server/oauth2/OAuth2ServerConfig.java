
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
 * ???????????????
* @ClassName: 	OAuth2ServerConfig.java
* @Description: ????????????????????????
* @date: 		2019???5???6???
 */
@Configuration
public class OAuth2ServerConfig {

    @Resource
    private DataSource dataSource;
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * ?????? ClientDetails??????
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
     * @version ???????????????2017???11???12??? ??????22:57:51 ??????token??????????????????
     * DefaultTokenServices????????????
     */
    @Component
    @Configuration
    @EnableAuthorizationServer
    @AutoConfigureAfter(AuthorizationServerEndpointsConfigurer.class)
    public class UnieapAuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
        /**
         * ??????authenticationManager ????????? password grant type
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
         * ?????????????????????????????????????????????TokenStore???TokenGranter???OAuth2RequestFactory
         */
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

            if (jwtTokenStore != null) {
                endpoints.tokenStore(jwtTokenStore).authenticationManager(authenticationManager)
                        // ??????
                        .userDetailsService(userDetailsService);
                // password
                // grant
                // type;
            } else if (redisTokenStore != null) {
                endpoints.tokenStore(redisTokenStore).authenticationManager(authenticationManager)
                        // ??????
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
         * ?????????????????? ??????id
         * ??????OAuth2????????????????????????
         */
        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.withClientDetails(redisClientDetailsService);
            redisClientDetailsService.loadAllClientToCache();
        }

        /**
         * ???????????????AuthorizationServer????????????????????????????????????ClientCredentialsTokenEndpointFilter???????????????
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
     * ?????????????????????
    * @Description: ??????????????????????????? 
    * @date: 		2019???5???6???
     */
    @Configuration
    @EnableResourceServer
    @EnableConfigurationProperties(PermitUrlProperties.class)
    public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    	//url??????????????? application.yml????????????????????????url?????????
        @Autowired
        private PermitUrlProperties permitUrlProperties;

        
        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.requestMatcher(
                    /**
                     * ??????????????????????????????oauth2????????????
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
