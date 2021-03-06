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
//	private ObjectMapper objectMapper; // springmvc?????????????????????json?????????
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
//	* @Description:	?????????????????????token-??????
//	* @date: 		2019???5???8???
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
//    		return WrapMapper.error().message("?????????????????????");
//    	}
//    	String password = jsonObj.getString("password");
//    	if(StringUtils.isBlank(password)) {
//    		return WrapMapper.error().message("?????????????????????");
//    	}
//
//		try {
//
//			if (clientId == null || "".equals(clientId)) {
//				throw new UnapprovedClientAuthenticationException("???????????????client_id??????");
//			}
//			if (clientSecret == null || "".equals(clientSecret)) {
//				throw new UnapprovedClientAuthenticationException("???????????????client_secret??????");
//			}
//			RedisClientDetailsService clientDetailsService = SpringUtil.getBean(RedisClientDetailsService.class);
//
//			ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
//
//			if (clientDetails == null) {
//				throw new UnapprovedClientAuthenticationException("clientId????????????????????????");
//			} else if (!passwordEncorder.bCryptPasswordEncoder(clientSecret, clientDetails.getClientSecret())) {
//				//oauth_client_details???
//				throw new UnapprovedClientAuthenticationException("clientSecret?????????");
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
//			//??????IP??????
//			Map<String, Object> map = new HashMap<>();
//			LoginAppUser loginUser = (LoginAppUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
//			System.out.println("loginUser"+JSON.toJSONString(loginUser));
//			map.put("userId", loginUser.getId());
//			map.put("userName", loginUser.getUserName());
//			String  ip = IpUtil.getIpAdrress(request);
//			if(ip.equals("0:0:0:0:0:0:0:1") || IpUtil.checkIp(ip)) {
//				map.put("ip", ip);
//				map.put("city", "??????IP-????????????");
//			}else {
//				String city = jsonObj.getString("city");//??????
//		    	if(StringUtils.isNotBlank(city)) {
//		    		map.put("city", city);
//		    	}
//			}
//			String deviceType = jsonObj.getString("deviceType");//???????????????0???web 1???android 2???ios
//			if(StringUtils.isNotBlank(deviceType)) {
//				map.put("deviceType", deviceType);
//			}else {
//				map.put("deviceType", "1");
//			}
//			String deviceId = jsonObj.getString("deviceId");//??????ID
//			if(StringUtils.isNotBlank(deviceId)) {
//				map.put("deviceId", deviceId);
//			}
//			System.out.println("ip?????????"+map);
//			userClient.loginLog(JSON.toJSONString(map));//??????????????????
//
//			return WrapMapper.ok().data(oAuth2AccessToken);
//		} catch (Exception e) {
//				return WrapMapper.error().message("???????????????"+e.getMessage());
//		}
//	}
//
//	/**
//	* @return
//	 * @Description:	??????????????????
//	* ???????????????
//	* ?????????????????????????????????
//	* ????????????????????????
//	* ??????token
//	* @date: 		2019???5???8???
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
//    		return WrapMapper.error().message("?????????????????????");
//    	}
//    	String code = jsonObj.getOrDefault("code", "");
//    	if(StringUtils.isBlank(code)) {
//    		return WrapMapper.error().message("????????????????????????");
//    	}
//    	if(redisTemplate.opsForValue().get(mobile) == null) {
//			return WrapMapper.error().message("????????????????????????");
//    	}
//    	if(!redisTemplate.opsForValue().get(mobile).equals(code)) {
//    		return WrapMapper.error().message("??????????????????????????????");
//    	}
//    	String openid = jsonObj.getOrDefault("openid", "");
//    	String type = jsonObj.getOrDefault("type", "");
//    	String avatar = jsonObj.getOrDefault("avatar", "");
//    	String city = jsonObj.getOrDefault("city", "");
//    	String sex = jsonObj.getOrDefault("sex", "");
//    	//?????????id
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
//        //??????IP??????
//        String  ip = IpUtil.getIpAdrress(request);
//        String deviceType = jsonObj.getOrDefault("deviceType", "");//???????????????0???web 1???android 2???ios
//        String deviceId = jsonObj.getOrDefault("deviceId", "");//??????ID
//
//		//?????? feign??????api-use??????
//		LoginAppUser loginAppUser = new LoginAppUser();
////		loginAppUser = userClient.findByUsername("wsx05");
//		loginAppUser = userClient.findUserByMobile(mobile);
//		System.out.println("findUserByMobile???"+loginAppUser);
//
//		if(loginAppUser == null) {
//			User user = new User();
//			user.setMobile(mobile);
//			//???????????????????????????????????????????????????????????????openid
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
//				return WrapMapper.error().message("???????????????");
//			}
//			//????????????-??????????????????????????????
//			if(inviteUserId!=null && loginAppUser.getId()!=null) {
//				userClient.loginToPartner(loginAppUser.getId(), inviteUserId);//??????user-center
//			}
//		}else {
//			try {
//				//??????openid
//				if(type!=null && type.equals("qq") && StringUtils.isNotBlank(openid)) {
//					if(loginAppUser.getQqOpenid() == null || (loginAppUser.getQqOpenid()!=null && !loginAppUser.getQqOpenid().equals(openid))) {
//						//openid??????????????????????????????
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
//				return WrapMapper.error().code("error").message("???????????????"+e.getMessage());
//			}
//		}
//
//		try {
//			if (clientId == null || "".equals(clientId)) {
//				throw new UnapprovedClientAuthenticationException("???????????????client_id??????");
//			}
//			if (clientSecret == null || "".equals(clientSecret)) {
//				throw new UnapprovedClientAuthenticationException("???????????????client_secret??????");
//			}
//			//oauth_client_details?????????
//			RedisClientDetailsService clientDetailsService = SpringUtil.getBean(RedisClientDetailsService.class);
//
//			ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
//			if (clientDetails == null) {
//				throw new UnapprovedClientAuthenticationException("clientId????????????????????????");
//			} else if (!passwordEncorder.bCryptPasswordEncoder(clientSecret, clientDetails.getClientSecret())) {
//				throw new UnapprovedClientAuthenticationException("clientSecret?????????");
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
//            //??????IP??????
//            Map<String, Object> map = new HashMap<>();
//            System.out.println("loginAppUser"+JSON.toJSONString(loginAppUser));
//            map.put("userId", loginAppUser.getId());
//            map.put("userName", loginAppUser.getUserName());
//            if(ip.equals("0:0:0:0:0:0:0:1") || IpUtil.checkIp(ip)) {
//                map.put("ip", ip);
//                map.put("city", "??????IP-????????????");
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
//            log.info("????????????-ip?????????"+map);
//
//			userClient.loginLog(JSON.toJSONString(map));//??????????????????
//
//			return WrapMapper.ok().code("success").data(oAuth2AccessToken);
//
//		} catch (Exception e) {
//			return WrapMapper.error().code("error").message("???????????????"+e.getMessage());
//		}
//
//	}
//
//	/**
//	 * @Description:	???????????????
//	 * 1.????????????????????????????????????????????????
//	 * 2.??????????????????token
//	 * type???qq???wx???alipay
//	 * openid
//	* @date: 		2019???6???28???
//	 */
//	@ApiOperation("???????????????")
//	@LogAnnotation(module="auth-server", recordRequestParam=false)
//	@RequestMapping("/oauth/third/login")
//	public Wrapper<Object> thirdLogin(@RequestBody String JsonMap, HttpServletRequest request){
//		JSONObject jsonObj = JSON.parseObject(JsonMap);
//		String openid = jsonObj.getString("openid");
//		String type = jsonObj.getString("type");
//		if(StringUtils.isBlank(type)) {
//			return WrapMapper.error().message("type????????????????????????");
//		}
//		if(StringUtils.isBlank(openid)) {
//			return WrapMapper.error().message("openid????????????????????????");
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
//			return WrapMapper.error().message("???????????????");
//		}
//		if(loginAppUser==null) {
//			return WrapMapper.error().code("noBindUser").message("?????????????????????");
//		}
//
//		//??????app
//		String clientId = "app";
//		String clientSecret = "app";
//
//		try {
//			if (clientId == null || "".equals(clientId)) {
//				throw new UnapprovedClientAuthenticationException("???????????????client_id??????");
//			}
//			if (clientSecret == null || "".equals(clientSecret)) {
//				throw new UnapprovedClientAuthenticationException("???????????????client_secret??????");
//			}
//			//oauth_client_details?????????
//			RedisClientDetailsService clientDetailsService = SpringUtil.getBean(RedisClientDetailsService.class);
//
//			ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
//			if (clientDetails == null) {
//				throw new UnapprovedClientAuthenticationException("clientId????????????????????????");
//			} else if (!passwordEncorder.bCryptPasswordEncoder(clientSecret, clientDetails.getClientSecret())) {
//				throw new UnapprovedClientAuthenticationException("clientSecret?????????");
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
//			//??????IP??????
//			Map<String, Object> map = new HashMap<>();
//			System.out.println("loginAppUser"+JSON.toJSONString(loginAppUser));
//			map.put("userId", loginAppUser.getId());
//			map.put("userName", loginAppUser.getUserName());
//			String  ip = IpUtil.getIpAdrress(request);
//			if(ip.equals("0:0:0:0:0:0:0:1") || IpUtil.checkIp(ip)) {
//				map.put("ip", ip);
//				map.put("city", "??????IP-????????????");
//			}else {
//				String city = jsonObj.getString("city");//??????
//		    	if(StringUtils.isNotBlank(city)) {
//		    		map.put("city", city);
//		    	}
//			}
//			String deviceType = jsonObj.getString("deviceType");//???????????????0???web 1???android 2???ios
//			if(StringUtils.isNotBlank(deviceType)) {
//				map.put("deviceType", deviceType);
//			}else {
//				map.put("deviceType", "1");
//			}
//			String deviceId = jsonObj.getString("deviceId");//??????ID
//			if(StringUtils.isNotBlank(deviceId)) {
//				map.put("deviceId", deviceId);
//			}
//			log.info("???????????????-ip?????????"+map);
//			userClient.loginLog(JSON.toJSONString(map));//??????????????????
//
//			return WrapMapper.ok().code("success").data(oAuth2AccessToken);
//
//		} catch (Exception e) {
//			return WrapMapper.error().code("error").message("???????????????"+e.getMessage());
//		}
//
//	}
//
//
//	/**
//	 * @Description:	???????????????????????????-?????????accessToken????????????accessToken?????????
//	* @date: 		2019???5???17???
//	 */
// 	@PostMapping(value = "/auth-anon/create-accessToken")
//    @LogAnnotation(module="auth-server",recordRequestParam=false)
//    public String createAccessToken(@RequestBody LoginAppUser loginAppUser) {
// 		System.out.println("???????????????"+loginAppUser+":");
// 		//??????app
// 		String clientId = "app";
//		String clientSecret = "app";
//		try {
//			if (clientId == null || "".equals(clientId)) {
//				throw new UnapprovedClientAuthenticationException("???????????????client_id??????");
//			}
//			if (clientSecret == null || "".equals(clientSecret)) {
//				throw new UnapprovedClientAuthenticationException("???????????????client_secret??????");
//			}
//			//oauth_client_details?????????
//			RedisClientDetailsService clientDetailsService = SpringUtil.getBean(RedisClientDetailsService.class);
//			ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
//			if (clientDetails == null) {
//				throw new UnapprovedClientAuthenticationException("clientId????????????????????????");
//			} else if (!passwordEncorder.bCryptPasswordEncoder(clientSecret, clientDetails.getClientSecret())) {
//				throw new UnapprovedClientAuthenticationException("clientSecret?????????");
//			}
//			TokenRequest tokenRequest = new TokenRequest(MapUtils.EMPTY_MAP, clientId, clientDetails.getScope(),
//					"customer");
//			OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);
//
//			UsernamePasswordAuthenticationToken userAuthentication = null;
//
//			//????????????=null  && ????????????=?????????
//			if(loginAppUser.getNewPassword() != null && loginAppUser.getPassword() != loginAppUser.getNewPassword()) {
//
//				userAuthentication = new UsernamePasswordAuthenticationToken(loginAppUser,null, loginAppUser.getAuthorities());
//				//?????????access_token
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
//			//???????????????-??????access_token
//			loginAppUser.setPassword(loginAppUser.getNewPassword());//????????????????????????
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
//	/**	???????????????username????????????????????????????????????access_token????????????????????????????????????????????????????????????access_token???????????????access_token???
//	 * @Description:	?????????????????????access_token
//	* @date: 		2019???5???16???
//	 */
//    @PostMapping(value = "/auth-anon/remove-accessToken")
//    @LogAnnotation(module="auth-server",recordRequestParam=false)
//    public void removeAccessToken(@RequestBody LoginAppUser loginAppUser) {
//
//        System.out.println("????????????loginAppUser???"+loginAppUser);
//		String clientId = "app";
//		String clientSecret = "app";
//
//		try {
//			if (clientId == null || "".equals(clientId)) {
//				throw new UnapprovedClientAuthenticationException("???????????????client_id??????");
//			}
//			if (clientSecret == null || "".equals(clientSecret)) {
//				throw new UnapprovedClientAuthenticationException("???????????????client_secret??????");
//			}
//			//oauth_client_details?????????
//			RedisClientDetailsService clientDetailsService = SpringUtil.getBean(RedisClientDetailsService.class);
//			ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
//			if (clientDetails == null) {
//				throw new UnapprovedClientAuthenticationException("clientId????????????????????????");
//			} else if (!passwordEncorder.bCryptPasswordEncoder(clientSecret, clientDetails.getClientSecret())) {
//				throw new UnapprovedClientAuthenticationException("clientSecret?????????");
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
//    /**	??????????????????????????????access_token????????????????????????????????????????????????????????????access_token???????????????access_token???
//     * @Description:	??????username???password??????access_token
//    * @date: 		2019???5???16???
//     */
//    @GetMapping(value = "/auth-anon/remove-accessTokenOnUserName")
//    @LogAnnotation(module="auth-server",recordRequestParam=false)
//    public void removeAccessTokenOnUsername(@RequestParam("username") String username, @RequestParam("password") String password) {
//        System.out.println("???????????????"+username);
//        String JsonMap = "";
//		String clientId = "app";
//		String clientSecret = "app";
//		username = "wsx05";
//
//		if (clientId == null || "".equals(clientId)) {
//			throw new UnapprovedClientAuthenticationException("???????????????client_id??????");
//		}
//		if (clientSecret == null || "".equals(clientSecret)) {
//			throw new UnapprovedClientAuthenticationException("???????????????client_secret??????");
//		}
//		RedisClientDetailsService clientDetailsService = SpringUtil.getBean(RedisClientDetailsService.class);
//		ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
//		if (clientDetails == null) {
//			throw new UnapprovedClientAuthenticationException("clientId????????????????????????");
//		} else if (!passwordEncorder.bCryptPasswordEncoder(clientSecret, clientDetails.getClientSecret())) {
//			//oauth_client_details???
//			throw new UnapprovedClientAuthenticationException("clientSecret?????????");
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
//		//??????access_token
//		tokenStore.removeAccessToken(oAuth2AccessToken);
//		//??????refresh_token
//		tokenStore.removeRefreshToken(oAuth2AccessToken.getRefreshToken());
//    }
//
//
////	@ApiOperation(value = "clientId??????token")
//	@PostMapping("/oauth/client/token")
//	@LogAnnotation(module = "auth-server", recordRequestParam = false)
//	public void getClientTokenInfo(HttpServletRequest request, HttpServletResponse response) {
//
//		String clientId = request.getHeader("client_id");
//		String clientSecret = request.getHeader("client_secret");
//		try {
//
//			if (clientId == null || "".equals(clientId)) {
//				throw new UnapprovedClientAuthenticationException("??????????????????clientId??????");
//			}
//
//			if (clientSecret == null || "".equals(clientSecret)) {
//				throw new UnapprovedClientAuthenticationException("??????????????????clientSecret??????");
//			}
//
//			RedisClientDetailsService clientDetailsService = SpringUtil.getBean(RedisClientDetailsService.class);
//
//			ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
//
//			if (clientDetails == null) {
//				throw new UnapprovedClientAuthenticationException("clientId????????????????????????");
//			} else if (!passwordEncorder.bCryptPasswordEncoder(clientSecret, clientDetails.getClientSecret())) {
//				throw new UnapprovedClientAuthenticationException("clientSecret?????????");
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
////	@ApiOperation(value = "access_token??????token")
//	@PostMapping(value = "/oauth/refresh/token", params = "access_token")
//	public Wrapper<Object> refreshTokenInfo(@RequestBody String JsonMap, HttpServletRequest request, HttpServletResponse response) {
//		JSONObject jsonObj = JSON.parseObject(JsonMap);
//    	String access_token = jsonObj.getString("access_token");
//    	if(StringUtils.isBlank(access_token)) {
//    		return WrapMapper.error().message("access_token???????????????");
//    	}
//
//		// ????????????????????????
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
//			return WrapMapper.error().code("error").message("??????access_token?????????"+e.getMessage());
//		}
//
//	}
//
//	/**
//	 * ??????access_token???refresh_token
//	 *
//	 * @param access_token
//	 */
////	@ApiOperation(value = "??????token")
//	@PostMapping(value = "/oauth/remove/token", params = "access_token")
//	public void removeToken(String access_token) {
//
//		// ????????????????????????
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
//			// ??????access_token
//			tokenStore.removeAccessToken(accessToken);
//
//			// ??????refresh_token
//			if (accessToken.getRefreshToken() != null) {
//				tokenStore.removeRefreshToken(accessToken.getRefreshToken());
//			}
//
//		}
//	}
//
////	@ApiOperation(value = "??????token??????")
//	@PostMapping(value = "/oauth/get/token", params = "access_token")
//	public OAuth2AccessToken getTokenInfo(String access_token) {
//
//		// ????????????????????????
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
//	 * ????????????????????????
//	 * security????????????????????????????????????SecurityContextHolder.getContext().getAuthentication()
//	 * ?????????????????????org.springframework.security.oauth2.provider.OAuth2Authentication
//	 *
//	 * @return
//	 */
////	@ApiOperation(value = "????????????????????????")
//	@RequestMapping(value = { "/oauth/userinfo" }, produces = "application/json") // ?????????????????????/auth/user
//	public Wrapper getCurrentUserDetail() {
//		Map<String, Object> userInfo = new HashMap<>();
//		userInfo.put("user", SecurityContextHolder.getContext().getAuthentication().getPrincipal());
//		logger.debug("??????????????????:" + SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
//
//
//		userInfo.put("resp_code", "200");
//
//		logger.info("????????????:{}", userInfo);
//
//
//		return WrapMapper.ok().message("??????????????????:{}").data(SecurityContextHolder.getContext().getAuthentication().getPrincipal());
//	}
//
////	@ApiOperation(value = "token??????")
//	@PostMapping("/oauth/token/list")
//	public Wrapper<Object> getUserTokenInfo(@RequestParam Map<String, Object> params)
//			throws Exception {
//		List<HashMap<String, String>> list = new ArrayList<>();
//
//		Set<String> keys = redisTemplate.keys("access:" + "*") ;
////        Object key1 = keys.toArray()[0];
////        Object token1 = redisTemplate.opsForValue().get(key1);
//		//????????????????????????????????????
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
//				//??????token??????
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
//					// ?????????????????????????????????,??????????????????
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
