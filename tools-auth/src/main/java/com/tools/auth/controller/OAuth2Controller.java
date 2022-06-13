//package com.tools.auth.controller;
//
//import com.alibaba.fastjson.JSON;
//import com.alibaba.fastjson.JSONObject;
//import com.fasterxml.jackson.core.JsonProcessingException;
//import com.fasterxml.jackson.databind.ObjectMapper;
//import com.open.capacity.annotation.log.LogAnnotation;
//import com.open.capacity.commons.wrapper.WrapMapper;
//import com.open.capacity.commons.wrapper.Wrapper;
//import com.open.capacity.entity.user.User;
//import com.open.capacity.model.system.LoginAppUser;
//import com.open.capacity.server.oauth2.client.RedisClientDetailsService;
//import com.open.capacity.server.oauth2.feign.UserClient;
//import com.open.capacity.utils.SpringUtil;
//import com.open.capacity.utils.encrypt.PasswordEncorder;
//import com.open.capacity.utils.ip.IpUtil;
//import com.tools.common.core.utils.encrypt.PasswordEncorder;
//import io.swagger.annotations.Api;
//import io.swagger.annotations.ApiOperation;
//import lombok.extern.slf4j.Slf4j;
//import org.apache.commons.collections.MapUtils;
//import org.apache.commons.lang3.StringUtils;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.dao.DataAccessException;
//import org.springframework.data.redis.connection.RedisConnection;
//import org.springframework.data.redis.core.Cursor;
//import org.springframework.data.redis.core.RedisCallback;
//import org.springframework.data.redis.core.RedisTemplate;
//import org.springframework.data.redis.core.ScanOptions;
//import org.springframework.http.HttpStatus;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.oauth2.common.OAuth2AccessToken;
//import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
//import org.springframework.security.oauth2.provider.*;
//import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
//import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
//import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;
//import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
//import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
//import org.springframework.security.oauth2.provider.token.TokenStore;
//import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
//import org.springframework.web.bind.annotation.*;
//
//import javax.annotation.Resource;
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//import java.io.IOException;
//import java.util.*;
//
//
//
//
//@Slf4j
//@RestController
//public class OAuth2Controller {
//
//	private static final Logger logger = LoggerFactory.getLogger(OAuth2Controller.class);
//	@Resource
//	private ObjectMapper objectMapper; // springmvc启动时自动装配json处理类
//	@Autowired
//	private PasswordEncorder passwordEncorder;
//
//	@Autowired
//	private TokenStore tokenStore;
//
//	//feign
//	@Autowired
//    private UserClient userClient;
//
//	@Autowired
//	private RedisTemplate<String, Object> redisTemplate;
//
//	/**
//	* @Description:	用户名密码获取token-登录
//	* @date: 		2019年5月8日
//	 */
//	@PostMapping("/oauth/user/login")
//	@LogAnnotation(module="auth-server",recordRequestParam=false)
//	public Wrapper<Object> getUserTokenInfo(
//			@RequestBody String JsonMap,
//			HttpServletRequest request, HttpServletResponse response) {
//
//		String clientId = request.getHeader("client_id");
//		String clientSecret = request.getHeader("client_secret");
//
//		JSONObject jsonObj = JSON.parseObject(JsonMap);
//    	String username = jsonObj.getString("username");
//    	if(StringUtils.isBlank(username)) {
//    		return WrapMapper.error().message("账号不能为空！");
//    	}
//    	String password = jsonObj.getString("password");
//    	if(StringUtils.isBlank(password)) {
//    		return WrapMapper.error().message("密码不能为空！");
//    	}
//
//		try {
//
//			if (clientId == null || "".equals(clientId)) {
//				throw new UnapprovedClientAuthenticationException("请求头中无client_id信息");
//			}
//			if (clientSecret == null || "".equals(clientSecret)) {
//				throw new UnapprovedClientAuthenticationException("请求头中无client_secret信息");
//			}
//			RedisClientDetailsService clientDetailsService = SpringUtil.getBean(RedisClientDetailsService.class);
//
//			ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
//
//			if (clientDetails == null) {
//				throw new UnapprovedClientAuthenticationException("clientId对应的信息不存在");
//			} else if (!passwordEncorder.bCryptPasswordEncoder(clientSecret, clientDetails.getClientSecret())) {
//				//oauth_client_details表
//				throw new UnapprovedClientAuthenticationException("clientSecret不匹配");
//			}
//
//			TokenRequest tokenRequest = new TokenRequest(MapUtils.EMPTY_MAP, clientId, clientDetails.getScope(),
//					"customer");
//
//			OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);
//
//			UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
//
//			AuthenticationManager authenticationManager = SpringUtil.getBean(AuthenticationManager.class);
//
//			Authentication authentication = authenticationManager.authenticate(token);
//			SecurityContextHolder.getContext().setAuthentication(authentication);
//
//			OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, authentication);
//
//			AuthorizationServerTokenServices authorizationServerTokenServices = SpringUtil
//					.getBean("defaultAuthorizationServerTokenServices", AuthorizationServerTokenServices.class);
//
//			OAuth2AccessToken oAuth2AccessToken = authorizationServerTokenServices
//					.createAccessToken(oAuth2Authentication);
//
//			oAuth2Authentication.setAuthenticated(true);
//
//			//获取IP地址
//			Map<String, Object> map = new HashMap<>();
//			LoginAppUser loginUser = (LoginAppUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
//			System.out.println("loginUser"+JSON.toJSONString(loginUser));
//			map.put("userId", loginUser.getId());
//			map.put("userName", loginUser.getUserName());
//			String  ip = IpUtil.getIpAdrress(request);
//			if(ip.equals("0:0:0:0:0:0:0:1") || IpUtil.checkIp(ip)) {
//				map.put("ip", ip);
//				map.put("city", "内网IP-开发人员");
//			}else {
//				String city = jsonObj.getString("city");//城市
//		    	if(StringUtils.isNotBlank(city)) {
//		    		map.put("city", city);
//		    	}
//			}
//			String deviceType = jsonObj.getString("deviceType");//设备类型：0、web 1、android 2、ios
//			if(StringUtils.isNotBlank(deviceType)) {
//				map.put("deviceType", deviceType);
//			}else {
//				map.put("deviceType", "1");
//			}
//			String deviceId = jsonObj.getString("deviceId");//设备ID
//			if(StringUtils.isNotBlank(deviceId)) {
//				map.put("deviceId", deviceId);
//			}
//			System.out.println("ip地址："+map);
//			userClient.loginLog(JSON.toJSONString(map));//调用登录日志
//
//			return WrapMapper.ok().data(oAuth2AccessToken);
//		} catch (Exception e) {
//				return WrapMapper.error().message("登录异常！"+e.getMessage());
//		}
//	}
//
//	/**
//	* @return
//	 * @Description:	快捷登录注册
//	* 验证验证码
//	* 查询手机号码是否已注册
//	* 未注册、注册账号
//	* 返回token
//	* @date: 		2019年5月8日
//	 */
//	@PostMapping("/oauth/user/fast-login")
//	@LogAnnotation(module="auth-server",recordRequestParam=false)
//	public Wrapper<Object> fastLogin(
//			@RequestBody HashMap<String, String> jsonObj,
//			HttpServletRequest request, HttpServletResponse response) throws JsonProcessingException {
//
////		JSONObject jsonObj = JSON.parseObject(JsonMap);
//    	String mobile = jsonObj.getOrDefault("mobile", "");
//    	if(StringUtils.isBlank(mobile)) {
//    		return WrapMapper.error().message("手机不能为空！");
//    	}
//    	String code = jsonObj.getOrDefault("code", "");
//    	if(StringUtils.isBlank(code)) {
//    		return WrapMapper.error().message("验证码不能为空！");
//    	}
//    	if(redisTemplate.opsForValue().get(mobile) == null) {
//			return WrapMapper.error().message("请先获取验证码！");
//    	}
//    	if(!redisTemplate.opsForValue().get(mobile).equals(code)) {
//    		return WrapMapper.error().message("请输入正确的验证码！");
//    	}
//    	String openid = jsonObj.getOrDefault("openid", "");
//    	String type = jsonObj.getOrDefault("type", "");
//    	String avatar = jsonObj.getOrDefault("avatar", "");
//    	String city = jsonObj.getOrDefault("city", "");
//    	String sex = jsonObj.getOrDefault("sex", "");
//    	//推广人id
//    	String inviteUserId = jsonObj.getOrDefault("inviteUserId", "");
//
//		String clientId = request.getHeader("client_id");
//		String clientSecret = request.getHeader("client_secret");
//		if(StringUtils.isBlank(clientId)) {
//			clientId = "app";
//		}
//		if(StringUtils.isBlank(clientSecret)) {
//			clientSecret = "app";
//		}
//        //获取IP地址
//        String  ip = IpUtil.getIpAdrress(request);
//        String deviceType = jsonObj.getOrDefault("deviceType", "");//设备类型：0、web 1、android 2、ios
//        String deviceId = jsonObj.getOrDefault("deviceId", "");//设备ID
//
//		//通过 feign调用api-use接口
//		LoginAppUser loginAppUser = new LoginAppUser();
////		loginAppUser = userClient.findByUsername("wsx05");
//		loginAppUser = userClient.findUserByMobile(mobile);
//		System.out.println("findUserByMobile："+loginAppUser);
//
//		if(loginAppUser == null) {
//			User user = new User();
//			user.setMobile(mobile);
//			//兼容第三方第一次登录，创建用户并保存，保存openid
//			if(type.equals("qq") && StringUtils.isNotBlank(openid)) {
//				user.setQqOpenid(openid);
//			}else if(type.equals("wx") && StringUtils.isNotBlank(openid)){
//				user.setWxOpenid(openid);
//			}else if(type.equals("alipay") && StringUtils.isNotBlank(openid)){
//				user.setAlipayOpenid(openid);
//			}
//			if(StringUtils.isNotBlank(ip)){
//                user.setIP(ip);
//            }
//            if(StringUtils.isNotBlank(city)){
//                user.setIP(city);
//            }
//            if(StringUtils.isNotBlank(deviceId)){
//                user.setIP(deviceId);
//            }
//            if(StringUtils.isNotBlank(deviceType)){
//                user.setIP(deviceType);
//            }
//			if(StringUtils.isNotBlank(avatar)) {
//				user.setAvatar(avatar);
//			}
//			if(StringUtils.isNotBlank(city)) {
//				user.setCity(city);
//			}
//			if(StringUtils.isNotBlank(sex)) {
//				if(sex.equals("0")) {
//					user.setSex(0);
//				}
//				if(sex.equals("1")) {
//					user.setSex(1);
//				}
//			}
//			loginAppUser = userClient.fastRegister(user);
//			if(StringUtils.isBlank(loginAppUser.getId().toString())) {
//				return WrapMapper.error().message("注册失败！");
//			}
//			//注册成功-验证是否是推广人注册
//			if(inviteUserId!=null && loginAppUser.getId()!=null) {
//				userClient.loginToPartner(loginAppUser.getId(), inviteUserId);//调用user-center
//			}
//		}else {
//			try {
//				//绑定openid
//				if(type!=null && type.equals("qq") && StringUtils.isNotBlank(openid)) {
//					if(loginAppUser.getQqOpenid() == null || (loginAppUser.getQqOpenid()!=null && !loginAppUser.getQqOpenid().equals(openid))) {
//						//openid不一致或不存在，修改
//						User user = new User();
//						user.setId(loginAppUser.getId());
//						user.setWx(jsonObj.getOrDefault("qq", ""));
//						user.setQqOpenid(openid);
//						userClient.updateUserOpenid(user);
//					}
//				}else if(type!=null && type.equals("wx") && StringUtils.isNotBlank(openid)){
//					if(loginAppUser.getWxOpenid() == null || (loginAppUser.getWxOpenid() != null && !loginAppUser.getWxOpenid().equals(openid))) {
//						User user = new User();
//						user.setId(loginAppUser.getId());
//						user.setWx(jsonObj.getOrDefault("wx", ""));
//						user.setWxOpenid(openid);
//						userClient.updateUserOpenid(user);
//					}
//				}else if(type!=null && type.equals("alipay") && StringUtils.isNotBlank(openid)){
//					if(loginAppUser.getAlipayOpenid() == null || (loginAppUser.getAlipayOpenid() != null && !loginAppUser.getAlipayOpenid().equals(openid))) {
//						User user = new User();
//						user.setId(loginAppUser.getId());
//						user.setAlipayOpenid(openid);
//						userClient.updateUserOpenid(user);
//					}
//				}
//
//			} catch (Exception e) {
//				return WrapMapper.error().code("error").message("登录异常！"+e.getMessage());
//			}
//		}
//
//		try {
//			if (clientId == null || "".equals(clientId)) {
//				throw new UnapprovedClientAuthenticationException("请求头中无client_id信息");
//			}
//			if (clientSecret == null || "".equals(clientSecret)) {
//				throw new UnapprovedClientAuthenticationException("请求头中无client_secret信息");
//			}
//			//oauth_client_details表数据
//			RedisClientDetailsService clientDetailsService = SpringUtil.getBean(RedisClientDetailsService.class);
//
//			ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
//			if (clientDetails == null) {
//				throw new UnapprovedClientAuthenticationException("clientId对应的信息不存在");
//			} else if (!passwordEncorder.bCryptPasswordEncoder(clientSecret, clientDetails.getClientSecret())) {
//				throw new UnapprovedClientAuthenticationException("clientSecret不匹配");
//			}
//
//			TokenRequest tokenRequest = new TokenRequest(MapUtils.EMPTY_MAP, clientId, clientDetails.getScope(),
//					"customer");
//
//			OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);
//
//			UsernamePasswordAuthenticationToken userAuthentication = new UsernamePasswordAuthenticationToken(loginAppUser,null, loginAppUser.getAuthorities());
//
//
//			OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, userAuthentication);
//
//			AuthorizationServerTokenServices authorizationServerTokenServices = SpringUtil
//					.getBean("defaultAuthorizationServerTokenServices", AuthorizationServerTokenServices.class);
//
//			OAuth2AccessToken oAuth2AccessToken = authorizationServerTokenServices
//					.createAccessToken(oAuth2Authentication);
//
//			oAuth2Authentication.setAuthenticated(true);
//
//            //获取IP地址
//            Map<String, Object> map = new HashMap<>();
//            System.out.println("loginAppUser"+JSON.toJSONString(loginAppUser));
//            map.put("userId", loginAppUser.getId());
//            map.put("userName", loginAppUser.getUserName());
//            if(ip.equals("0:0:0:0:0:0:0:1") || IpUtil.checkIp(ip)) {
//                map.put("ip", ip);
//                map.put("city", "内网IP-开发人员");
//            }else {
//                if(StringUtils.isNotBlank(city)) {
//                    map.put("city", city);
//                }
//            }
//            if(StringUtils.isNotBlank(deviceType)) {
//                map.put("deviceType", deviceType);
//            }else {
//                map.put("deviceType", "1");
//            }
//            if(StringUtils.isNotBlank(deviceId)) {
//                map.put("deviceId", deviceId);
//            }
//            log.info("快捷登录-ip地址："+map);
//
//			userClient.loginLog(JSON.toJSONString(map));//调用登录日志
//
//			return WrapMapper.ok().code("success").data(oAuth2AccessToken);
//
//		} catch (Exception e) {
//			return WrapMapper.error().code("error").message("登录异常！"+e.getMessage());
//		}
//
//	}
//
//	/**
//	 * @Description:	第三方登录
//	 * 1.验证是否绑定，未绑定返回：请绑定
//	 * 2.已绑定：返回token
//	 * type：qq、wx、alipay
//	 * openid
//	* @date: 		2019年6月28日
//	 */
//	@ApiOperation("第三方登录")
//	@LogAnnotation(module="auth-server", recordRequestParam=false)
//	@RequestMapping("/oauth/third/login")
//	public Wrapper<Object> thirdLogin(@RequestBody String JsonMap, HttpServletRequest request){
//		JSONObject jsonObj = JSON.parseObject(JsonMap);
//		String openid = jsonObj.getString("openid");
//		String type = jsonObj.getString("type");
//		if(StringUtils.isBlank(type)) {
//			return WrapMapper.error().message("type参数不允许为空！");
//		}
//		if(StringUtils.isBlank(openid)) {
//			return WrapMapper.error().message("openid参数不允许为空！");
//		}
//        System.out.println(type);
//		LoginAppUser loginAppUser = new LoginAppUser();
//		if(type.equals("qq")) {
//
//			loginAppUser = userClient.findUserByQq(openid);
//
//		}else if(type.equals("wx")){
//
//			loginAppUser = userClient.findUserByWx(openid);
//
//		}else if(type.equals("alipay")){
//
//			loginAppUser = userClient.findUserByAlipay(openid);
//
//		}else {
//			return WrapMapper.error().message("参数异常！");
//		}
//		if(loginAppUser==null) {
//			return WrapMapper.error().code("noBindUser").message("请先绑定手机！");
//		}
//
//		//默认app
//		String clientId = "app";
//		String clientSecret = "app";
//
//		try {
//			if (clientId == null || "".equals(clientId)) {
//				throw new UnapprovedClientAuthenticationException("请求头中无client_id信息");
//			}
//			if (clientSecret == null || "".equals(clientSecret)) {
//				throw new UnapprovedClientAuthenticationException("请求头中无client_secret信息");
//			}
//			//oauth_client_details表数据
//			RedisClientDetailsService clientDetailsService = SpringUtil.getBean(RedisClientDetailsService.class);
//
//			ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
//			if (clientDetails == null) {
//				throw new UnapprovedClientAuthenticationException("clientId对应的信息不存在");
//			} else if (!passwordEncorder.bCryptPasswordEncoder(clientSecret, clientDetails.getClientSecret())) {
//				throw new UnapprovedClientAuthenticationException("clientSecret不匹配");
//			}
//
//			TokenRequest tokenRequest = new TokenRequest(MapUtils.EMPTY_MAP, clientId, clientDetails.getScope(),
//					"customer");
//
//			OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);
//
//			UsernamePasswordAuthenticationToken userAuthentication = new UsernamePasswordAuthenticationToken(loginAppUser,null, loginAppUser.getAuthorities());
//
//
//			OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, userAuthentication);
//
//			AuthorizationServerTokenServices authorizationServerTokenServices = SpringUtil
//					.getBean("defaultAuthorizationServerTokenServices", AuthorizationServerTokenServices.class);
//
//			OAuth2AccessToken oAuth2AccessToken = authorizationServerTokenServices
//					.createAccessToken(oAuth2Authentication);
//
//			oAuth2Authentication.setAuthenticated(true);
//
//			//获取IP地址
//			Map<String, Object> map = new HashMap<>();
//			System.out.println("loginAppUser"+JSON.toJSONString(loginAppUser));
//			map.put("userId", loginAppUser.getId());
//			map.put("userName", loginAppUser.getUserName());
//			String  ip = IpUtil.getIpAdrress(request);
//			if(ip.equals("0:0:0:0:0:0:0:1") || IpUtil.checkIp(ip)) {
//				map.put("ip", ip);
//				map.put("city", "内网IP-开发人员");
//			}else {
//				String city = jsonObj.getString("city");//城市
//		    	if(StringUtils.isNotBlank(city)) {
//		    		map.put("city", city);
//		    	}
//			}
//			String deviceType = jsonObj.getString("deviceType");//设备类型：0、web 1、android 2、ios
//			if(StringUtils.isNotBlank(deviceType)) {
//				map.put("deviceType", deviceType);
//			}else {
//				map.put("deviceType", "1");
//			}
//			String deviceId = jsonObj.getString("deviceId");//设备ID
//			if(StringUtils.isNotBlank(deviceId)) {
//				map.put("deviceId", deviceId);
//			}
//			log.info("第三方登录-ip地址："+map);
//			userClient.loginLog(JSON.toJSONString(map));//调用登录日志
//
//			return WrapMapper.ok().code("success").data(oAuth2AccessToken);
//
//		} catch (Exception e) {
//			return WrapMapper.error().code("error").message("登录异常！"+e.getMessage());
//		}
//
//	}
//
//
//	/**
//	 * @Description:	登录状态下修改密码-删除原accessToken，创建新accessToken并返回
//	* @date: 		2019年5月17日
//	 */
// 	@PostMapping(value = "/auth-anon/create-accessToken")
//    @LogAnnotation(module="auth-server",recordRequestParam=false)
//    public String createAccessToken(@RequestBody LoginAppUser loginAppUser) {
// 		System.out.println("来了老弟："+loginAppUser+":");
// 		//默认app
// 		String clientId = "app";
//		String clientSecret = "app";
//		try {
//			if (clientId == null || "".equals(clientId)) {
//				throw new UnapprovedClientAuthenticationException("请求头中无client_id信息");
//			}
//			if (clientSecret == null || "".equals(clientSecret)) {
//				throw new UnapprovedClientAuthenticationException("请求头中无client_secret信息");
//			}
//			//oauth_client_details表数据
//			RedisClientDetailsService clientDetailsService = SpringUtil.getBean(RedisClientDetailsService.class);
//			ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
//			if (clientDetails == null) {
//				throw new UnapprovedClientAuthenticationException("clientId对应的信息不存在");
//			} else if (!passwordEncorder.bCryptPasswordEncoder(clientSecret, clientDetails.getClientSecret())) {
//				throw new UnapprovedClientAuthenticationException("clientSecret不匹配");
//			}
//			TokenRequest tokenRequest = new TokenRequest(MapUtils.EMPTY_MAP, clientId, clientDetails.getScope(),
//					"customer");
//			OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);
//
//			UsernamePasswordAuthenticationToken userAuthentication = null;
//
//			//新密码！=null  && 新密码！=旧密码
//			if(loginAppUser.getNewPassword() != null && loginAppUser.getPassword() != loginAppUser.getNewPassword()) {
//
//				userAuthentication = new UsernamePasswordAuthenticationToken(loginAppUser,null, loginAppUser.getAuthorities());
//				//删除原access_token
//				OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, userAuthentication);
//				AuthorizationServerTokenServices authorizationServerTokenServices = SpringUtil
//						.getBean("defaultAuthorizationServerTokenServices", AuthorizationServerTokenServices.class);
//				OAuth2AccessToken oAuth2AccessToken = authorizationServerTokenServices
//						.createAccessToken(oAuth2Authentication);
//				oAuth2Authentication.setAuthenticated(true);
//				tokenStore.removeAccessToken(oAuth2AccessToken);
//				if (oAuth2AccessToken.getRefreshToken() != null) {
//					tokenStore.removeRefreshToken(oAuth2AccessToken.getRefreshToken());
//					System.out.println("accessToken:====="+oAuth2AccessToken.getRefreshToken());
//				}
//			}
//
//			//根据新密码-创建access_token
//			loginAppUser.setPassword(loginAppUser.getNewPassword());//新密码覆盖原密码
//			userAuthentication = new UsernamePasswordAuthenticationToken(loginAppUser,null, loginAppUser.getAuthorities());
//
//			OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, userAuthentication);
//			AuthorizationServerTokenServices authorizationServerTokenServices = SpringUtil
//					.getBean("defaultAuthorizationServerTokenServices", AuthorizationServerTokenServices.class);
//			OAuth2AccessToken oAuth2AccessToken = authorizationServerTokenServices
//					.createAccessToken(oAuth2Authentication);
//			oAuth2Authentication.setAuthenticated(true);
//			System.out.println("objectMapper.writeValueAsString(oAuth2AccessToken)======"+objectMapper.writeValueAsString(oAuth2AccessToken));
//			System.err.println("oAuth2AccessToken:"+oAuth2AccessToken);
//			return objectMapper.writeValueAsString(oAuth2AccessToken);
//
//		} catch (Exception e) {
//			return null;
//		}
// 	}
//
//
//	/**	根据账号（username）获取用户信息，再次获取access_token后清除，需要优化（不用查询用户信息、创建access_token，直接获取access_token）
//	 * @Description:	根据用户名清除access_token
//	* @date: 		2019年5月16日
//	 */
//    @PostMapping(value = "/auth-anon/remove-accessToken")
//    @LogAnnotation(module="auth-server",recordRequestParam=false)
//    public void removeAccessToken(@RequestBody LoginAppUser loginAppUser) {
//
//        System.out.println("来了老弟loginAppUser："+loginAppUser);
//		String clientId = "app";
//		String clientSecret = "app";
//
//		try {
//			if (clientId == null || "".equals(clientId)) {
//				throw new UnapprovedClientAuthenticationException("请求头中无client_id信息");
//			}
//			if (clientSecret == null || "".equals(clientSecret)) {
//				throw new UnapprovedClientAuthenticationException("请求头中无client_secret信息");
//			}
//			//oauth_client_details表数据
//			RedisClientDetailsService clientDetailsService = SpringUtil.getBean(RedisClientDetailsService.class);
//			ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
//			if (clientDetails == null) {
//				throw new UnapprovedClientAuthenticationException("clientId对应的信息不存在");
//			} else if (!passwordEncorder.bCryptPasswordEncoder(clientSecret, clientDetails.getClientSecret())) {
//				throw new UnapprovedClientAuthenticationException("clientSecret不匹配");
//			}
//			TokenRequest tokenRequest = new TokenRequest(MapUtils.EMPTY_MAP, clientId, clientDetails.getScope(),
//					"customer");
//			OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);
//			UsernamePasswordAuthenticationToken userAuthentication = new UsernamePasswordAuthenticationToken(loginAppUser,null, loginAppUser.getAuthorities());
//			OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, userAuthentication);
//			AuthorizationServerTokenServices authorizationServerTokenServices = SpringUtil
//					.getBean("defaultAuthorizationServerTokenServices", AuthorizationServerTokenServices.class);
//			OAuth2AccessToken oAuth2AccessToken = authorizationServerTokenServices
//					.createAccessToken(oAuth2Authentication);
//			oAuth2Authentication.setAuthenticated(true);
//			tokenStore.removeAccessToken(oAuth2AccessToken);
//			if (oAuth2AccessToken.getRefreshToken() != null) {
//				tokenStore.removeRefreshToken(oAuth2AccessToken.getRefreshToken());
//				System.out.println("accessToken:====="+oAuth2AccessToken.getRefreshToken());
//			}
//			System.out.println("objectMapper.writeValueAsString(oAuth2AccessToken)======"+objectMapper.writeValueAsString(oAuth2AccessToken));
//		} catch (Exception e) {
//		}
//
//    }
//
//    /**	根据账号密码登录获取access_token后再次清除，需要优化（不用再次登录，创建access_token，直接获取access_token）
//     * @Description:	根据username、password清除access_token
//    * @date: 		2019年5月16日
//     */
//    @GetMapping(value = "/auth-anon/remove-accessTokenOnUserName")
//    @LogAnnotation(module="auth-server",recordRequestParam=false)
//    public void removeAccessTokenOnUsername(@RequestParam("username") String username, @RequestParam("password") String password) {
//        System.out.println("来了老弟："+username);
//        String JsonMap = "";
//		String clientId = "app";
//		String clientSecret = "app";
//		username = "wsx05";
//
//		if (clientId == null || "".equals(clientId)) {
//			throw new UnapprovedClientAuthenticationException("请求头中无client_id信息");
//		}
//		if (clientSecret == null || "".equals(clientSecret)) {
//			throw new UnapprovedClientAuthenticationException("请求头中无client_secret信息");
//		}
//		RedisClientDetailsService clientDetailsService = SpringUtil.getBean(RedisClientDetailsService.class);
//		ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
//		if (clientDetails == null) {
//			throw new UnapprovedClientAuthenticationException("clientId对应的信息不存在");
//		} else if (!passwordEncorder.bCryptPasswordEncoder(clientSecret, clientDetails.getClientSecret())) {
//			//oauth_client_details表
//			throw new UnapprovedClientAuthenticationException("clientSecret不匹配");
//		}
//		TokenRequest tokenRequest = new TokenRequest(MapUtils.EMPTY_MAP, clientId, clientDetails.getScope(),
//				"customer");
//		OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);
//		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
//		AuthenticationManager authenticationManager = SpringUtil.getBean(AuthenticationManager.class);
//		Authentication authentication = authenticationManager.authenticate(token);
//		SecurityContextHolder.getContext().setAuthentication(authentication);
//		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, authentication);
//		AuthorizationServerTokenServices authorizationServerTokenServices = SpringUtil
//				.getBean("defaultAuthorizationServerTokenServices", AuthorizationServerTokenServices.class);
//		OAuth2AccessToken oAuth2AccessToken = authorizationServerTokenServices
//				.createAccessToken(oAuth2Authentication);
//		oAuth2Authentication.setAuthenticated(true);
//
//		//清除access_token
//		tokenStore.removeAccessToken(oAuth2AccessToken);
//		//清除refresh_token
//		tokenStore.removeRefreshToken(oAuth2AccessToken.getRefreshToken());
//    }
//
//
////	@ApiOperation(value = "clientId获取token")
//	@PostMapping("/oauth/client/token")
//	@LogAnnotation(module = "auth-server", recordRequestParam = false)
//	public void getClientTokenInfo(HttpServletRequest request, HttpServletResponse response) {
//
//		String clientId = request.getHeader("client_id");
//		String clientSecret = request.getHeader("client_secret");
//		try {
//
//			if (clientId == null || "".equals(clientId)) {
//				throw new UnapprovedClientAuthenticationException("请求参数中无clientId信息");
//			}
//
//			if (clientSecret == null || "".equals(clientSecret)) {
//				throw new UnapprovedClientAuthenticationException("请求参数中无clientSecret信息");
//			}
//
//			RedisClientDetailsService clientDetailsService = SpringUtil.getBean(RedisClientDetailsService.class);
//
//			ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
//
//			if (clientDetails == null) {
//				throw new UnapprovedClientAuthenticationException("clientId对应的信息不存在");
//			} else if (!passwordEncorder.bCryptPasswordEncoder(clientSecret, clientDetails.getClientSecret())) {
//				throw new UnapprovedClientAuthenticationException("clientSecret不匹配");
//			}
//
//			Map<String, String> map = new HashMap<>();
//			map.put("client_secret", clientSecret);
//			map.put("client_id", clientId);
//			map.put("grant_type", "client_credentials");
//			TokenRequest tokenRequest = new TokenRequest(map, clientId, clientDetails.getScope(), "client_credentials");
//
//			OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);
//
//			AuthorizationServerTokenServices authorizationServerTokenServices = SpringUtil
//					.getBean("defaultAuthorizationServerTokenServices", AuthorizationServerTokenServices.class);
//			OAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);
//			ClientCredentialsTokenGranter clientCredentialsTokenGranter = new ClientCredentialsTokenGranter(
//					authorizationServerTokenServices, clientDetailsService, requestFactory);
//
//			clientCredentialsTokenGranter.setAllowRefresh(true);
//			OAuth2AccessToken oAuth2AccessToken = clientCredentialsTokenGranter.grant("client_credentials",
//					tokenRequest);
//
//			response.setContentType("application/json;charset=UTF-8");
//			response.getWriter().write(objectMapper.writeValueAsString(oAuth2AccessToken));
//			response.getWriter().flush();
//			response.getWriter().close();
//
//		} catch (Exception e) {
//
//			response.setStatus(HttpStatus.UNAUTHORIZED.value());
//			response.setContentType("application/json;charset=UTF-8");
//			Map<String, String> rsp = new HashMap<>();
//			rsp.put("resp_code", HttpStatus.UNAUTHORIZED.value() + "");
//			rsp.put("resp_msg", e.getMessage());
//
//			try {
//				response.getWriter().write(objectMapper.writeValueAsString(rsp));
//				response.getWriter().flush();
//				response.getWriter().close();
//			} catch (JsonProcessingException e1) {
//				// TODO Auto-generated catch block
//				e1.printStackTrace();
//			} catch (IOException e1) {
//				// TODO Auto-generated catch block
//				e1.printStackTrace();
//			}
//
//		}
//	}
//
////	@ApiOperation(value = "access_token刷新token")
//	@PostMapping(value = "/oauth/refresh/token", params = "access_token")
//	public Wrapper<Object> refreshTokenInfo(@RequestBody String JsonMap, HttpServletRequest request, HttpServletResponse response) {
//		JSONObject jsonObj = JSON.parseObject(JsonMap);
//    	String access_token = jsonObj.getString("access_token");
//    	if(StringUtils.isBlank(access_token)) {
//    		return WrapMapper.error().message("access_token不能为空！");
//    	}
//
//		// 拿到当前用户信息
//		try {
//			Authentication user = SecurityContextHolder.getContext().getAuthentication();
//
//			if (user != null) {
//				if (user instanceof OAuth2Authentication) {
//					Authentication athentication = (Authentication) user;
//					OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) athentication.getDetails();
//				}
//
//			}
//			OAuth2AccessToken accessToken = tokenStore.readAccessToken(access_token);
//			OAuth2Authentication auth = (OAuth2Authentication) user;
//			RedisClientDetailsService clientDetailsService = SpringUtil.getBean(RedisClientDetailsService.class);
//
//			ClientDetails clientDetails = clientDetailsService
//					.loadClientByClientId(auth.getOAuth2Request().getClientId());
//
//			AuthorizationServerTokenServices authorizationServerTokenServices = SpringUtil
//					.getBean("defaultAuthorizationServerTokenServices", AuthorizationServerTokenServices.class);
//			OAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);
//
//			RefreshTokenGranter refreshTokenGranter = new RefreshTokenGranter(authorizationServerTokenServices,
//					clientDetailsService, requestFactory);
//
//			Map<String, String> map = new HashMap<>();
//			map.put("grant_type", "refresh_token");
//			map.put("refresh_token", accessToken.getRefreshToken().getValue());
//			TokenRequest tokenRequest = new TokenRequest(map, auth.getOAuth2Request().getClientId(),
//					auth.getOAuth2Request().getScope(), "refresh_token");
//
//			OAuth2AccessToken oAuth2AccessToken = refreshTokenGranter.grant("refresh_token", tokenRequest);
//			tokenStore.removeAccessToken(accessToken);
//			return WrapMapper.ok().data(oAuth2AccessToken);
//		} catch (Exception e) {
//			return WrapMapper.error().code("error").message("刷新access_token异常！"+e.getMessage());
//		}
//
//	}
//
//	/**
//	 * 移除access_token和refresh_token
//	 *
//	 * @param access_token
//	 */
////	@ApiOperation(value = "移除token")
//	@PostMapping(value = "/oauth/remove/token", params = "access_token")
//	public void removeToken(String access_token) {
//
//		// 拿到当前用户信息
//		Authentication user = SecurityContextHolder.getContext().getAuthentication();
//
//		if (user != null) {
//			if (user instanceof OAuth2Authentication) {
//				Authentication athentication = (Authentication) user;
//				OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) athentication.getDetails();
//			}
//
//		}
//		OAuth2AccessToken accessToken = tokenStore.readAccessToken(access_token);
//		if (accessToken != null) {
//			// 移除access_token
//			tokenStore.removeAccessToken(accessToken);
//
//			// 移除refresh_token
//			if (accessToken.getRefreshToken() != null) {
//				tokenStore.removeRefreshToken(accessToken.getRefreshToken());
//			}
//
//		}
//	}
//
////	@ApiOperation(value = "获取token信息")
//	@PostMapping(value = "/oauth/get/token", params = "access_token")
//	public OAuth2AccessToken getTokenInfo(String access_token) {
//
//		// 拿到当前用户信息
//		Authentication user = SecurityContextHolder.getContext().getAuthentication();
//
//		if (user != null) {
//			if (user instanceof OAuth2Authentication) {
//				Authentication athentication = (Authentication) user;
//				OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) athentication.getDetails();
//			}
//
//		}
//		OAuth2AccessToken accessToken = tokenStore.readAccessToken(access_token);
//
//		return accessToken;
//
//	}
//
//	/**
//	 * 当前登陆用户信息
//	 * security获取当前登录用户的方法是SecurityContextHolder.getContext().getAuthentication()
//	 * 这里的实现类是org.springframework.security.oauth2.provider.OAuth2Authentication
//	 *
//	 * @return
//	 */
////	@ApiOperation(value = "当前登陆用户信息")
//	@RequestMapping(value = { "/oauth/userinfo" }, produces = "application/json") // 获取用户信息。/auth/user
//	public Wrapper getCurrentUserDetail() {
//		Map<String, Object> userInfo = new HashMap<>();
//		userInfo.put("user", SecurityContextHolder.getContext().getAuthentication().getPrincipal());
//		logger.debug("认证详细信息:" + SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
//
//
//		userInfo.put("resp_code", "200");
//
//		logger.info("返回信息:{}", userInfo);
//
//
//		return WrapMapper.ok().message("认证详细信息:{}").data(SecurityContextHolder.getContext().getAuthentication().getPrincipal());
//	}
//
////	@ApiOperation(value = "token列表")
//	@PostMapping("/oauth/token/list")
//	public Wrapper<Object> getUserTokenInfo(@RequestParam Map<String, Object> params)
//			throws Exception {
//		List<HashMap<String, String>> list = new ArrayList<>();
//
//		Set<String> keys = redisTemplate.keys("access:" + "*") ;
////        Object key1 = keys.toArray()[0];
////        Object token1 = redisTemplate.opsForValue().get(key1);
//		//根据分页参数获取对应数据
//	//	List<String> pages = findKeysForPage("access:" + "*", MapUtils.getInteger(params, "page"),MapUtils.getInteger(params, "limit"));
//
//		for (Object key: keys.toArray()) {
////			String key = page;
////			String accessToken = StringUtils.substringAfter(key, "access:");
////			OAuth2AccessToken token = tokenStore.readAccessToken(accessToken);
//            OAuth2AccessToken token = (OAuth2AccessToken)redisTemplate.opsForValue().get(key);
//			HashMap<String, String> map = new HashMap<String, String>();
//
//			try {
//				map.put("token_type", token.getTokenType());
//				map.put("token_value", token.getValue());
//				map.put("expires_in", token.getExpiresIn()+"");
//			} catch (Exception e) {
//
//			}
//
//
//			OAuth2Authentication oAuth2Auth = tokenStore.readAuthentication(token);
//			Authentication authentication = oAuth2Auth.getUserAuthentication();
//
//			map.put("client_id", oAuth2Auth.getOAuth2Request().getClientId());
//			map.put("grant_type", oAuth2Auth.getOAuth2Request().getGrantType());
//
//			if (authentication instanceof UsernamePasswordAuthenticationToken) {
//				UsernamePasswordAuthenticationToken authenticationToken = (UsernamePasswordAuthenticationToken) authentication;
//
//				if(authenticationToken.getPrincipal() instanceof LoginAppUser ){
//					LoginAppUser user = (LoginAppUser) authenticationToken.getPrincipal();
//					map.put("user_id", user.getId()+"");
//					map.put("user_name", user.getUsername()+"");
////					map.put("user_head_imgurl", user.getHeadImgUrl()+"");
//				}
//
//
//			}else if (authentication instanceof PreAuthenticatedAuthenticationToken ){
//				//刷新token方式
//				PreAuthenticatedAuthenticationToken authenticationToken = (PreAuthenticatedAuthenticationToken) authentication;
//				if(authenticationToken.getPrincipal() instanceof LoginAppUser ){
//					LoginAppUser user = (LoginAppUser) authenticationToken.getPrincipal();
//					map.put("user_id", user.getId()+"");
//					map.put("user_name", user.getUsername()+"");
////					map.put("user_head_imgurl", user.getHeadImgUrl()+"");
//				}
//
//			}
//			list.add(map);
//
//		}
//
//
//
////		return PageResult.<HashMap<String, String>>builder().data(list).code(0).count((long) keys.size()).build();
//		return WrapMapper.ok().data(list);
//
//	}
//
//	public List<String> findKeysForPage(String patternKey, int pageNum, int pageSize) {
//
//		Set<String> execute = redisTemplate.execute(new RedisCallback<Set<String>>() {
//
//			@Override
//			public Set<String> doInRedis(RedisConnection connection) throws DataAccessException {
//
//				Set<String> binaryKeys = new HashSet<>();
//
//				Cursor<byte[]> cursor = connection
//						.scan(new ScanOptions.ScanOptionsBuilder().match(patternKey).count(1000).build());
//				int tmpIndex = 0;
//				int startIndex = (pageNum - 1) * pageSize;
//				int end = pageNum * pageSize;
//				while (cursor.hasNext()) {
//					if (tmpIndex >= startIndex && tmpIndex < end) {
//						binaryKeys.add(new String(cursor.next()));
//						tmpIndex++;
//						continue;
//					}
//
//					// 获取到满足条件的数据后,就可以退出了
//					if (tmpIndex >= end) {
//						break;
//					}
//
//					tmpIndex++;
//					cursor.next();
//				}
//				connection.close();
//				return binaryKeys;
//			}
//		});
//
//		List<String> result = new ArrayList<String>(pageSize);
//		result.addAll(execute);
//		return result;
//	}
//
//}
