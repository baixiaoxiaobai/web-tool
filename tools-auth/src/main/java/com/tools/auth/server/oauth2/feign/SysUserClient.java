package com.tools.auth.server.oauth2.feign;

import com.tools.common.core.model.SecurityUser;
import com.tools.common.core.model.SysUser;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

/**
* 调用用户中心中的userdetail对象，用户oauth中的登录
* 获取的用户与页面输入的密码 进行BCryptPasswordEncoder匹配
* 基于密码模式的方式需要先启动用户中心，通过feigin调用
* user-center微服务名
 */
@FeignClient("user-center")
public interface SysUserClient {

	/**
	 * feign rpc访问远程/users-anon/login接口
	 * http://127.0.0.1:9200/api-user/users-anon/login?username=admin
	 * @param username
	 * @return
	 */
    @GetMapping(value = "/user-anon/login", params = "username")
    SecurityUser findByUsername(@RequestParam("username") String username);

    /**
     * @Description:	根据手机号码获取用户
    * @date: 		2019年5月10日
     */
    @GetMapping(value = "/user-anon/find-mobile", params = "mobile")
    SecurityUser findUserByMobile(@RequestParam("mobile") String mobile);

    /**
     * @Description:	快捷注册
    * @date: 		2019年5月10日
     */
//    @GetMapping(value = "/user-anon/fast-register", params = "mobile")
//    LoginAppUser fastRegister(@RequestParam("mobile") String mobile);
    @PostMapping(value = "/user-anon/fast-register")
    SecurityUser fastRegister(@RequestBody SysUser user);

    /**
     * @Description:	登录日志
    * @date: 		2019年6月28日
     */
	@PostMapping(value = "/user-anon/login-log")
	String loginLog(@RequestBody String JsonMap);

	/**
	 * @Description:	根据QQ openid查询
	* @date: 		2019年6月28日
	 */
	@RequestMapping(value = "/user-anon/findUserByQq", params = "openid")
    SecurityUser findUserByQq(@RequestParam("openid") String openid);

	/**
	 * @Description:	根据WX openid查询
	* @date: 		2019年6月28日
	 */
	@RequestMapping(value = "/user-anon/findUserByWx", params = "openid")
    SecurityUser findUserByWx(@RequestParam("openid") String openid);

	/**
	 * @Description:	根据ALIPAY openid查询
	* @date: 		2019年6月28日
	 */
	@RequestMapping(value = "/user-anon/findUserByAlipay", params = "openid")
    SecurityUser findUserByAlipay(@RequestParam("openid") String openid);

	/**
	 * @Description:	修改用户
	* @date: 		2019年6月28日
	 */
	@RequestMapping(value = "/user-anon/updateUserOpenid")
	void updateUserOpenid(@RequestBody SysUser user);

	/**
	 * @Description:	新用户注册、推广人
	* @date: 		2019年7月15日
	 */
	@RequestMapping(value = "/user-anon/loginToPartner")
	void loginToPartner(@RequestParam(value = "userId") Long userId,@RequestParam(value = "inviteUserId") String inviteUserId);

}
