package com.weibo.zel.entity.util;

import org.apache.http.client.HttpClient;

/**
 * Loginpojo entity. @author MyEclipse Persistence Tools
 */
public class LoginPojo implements java.io.Serializable {
	private Integer id;
	private String uid;
	private String username;
	private String password;
	private HttpClient httpClient;
	private String type;
	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public HttpClient getHttpClient() {
		return httpClient;
	}

	public void setHttpClient(HttpClient httpClient) {
		this.httpClient = httpClient;
	}

	/**
	 * status=1 无法获得cookie，一般是指无法登陆 status=2 可以获得cookie status=3
	 * 可以获得cookie,但无法获得accessToken status=4 帐号可以获得accessToken,即一切正常的帐号
	 */
	private String status;
	private String cookie;

	public String getCookie() {
		return cookie;
	}

	public void setCookie(String cookie) {
		this.cookie = cookie;
	}

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	private String accessToken;

	// Constructors

	/** default constructor */
	public LoginPojo() {
	}

	/** minimal constructor */
	public LoginPojo(Integer id) {
		this.id = id;
	}

	public LoginPojo(String username,String password){
		this.username=username;
		this.password=password;
	}
	
	/** full constructor */
	public LoginPojo(Integer id,String uid, String username, String password,
			String status,String type) {
		this.id = id;
		this.uid = uid;
		this.username = username;
		this.password = password;
		this.status = status;
		this.type=type;
	}

	public Integer getId() {
		return this.id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getUid() {
		return this.uid;
	}

	public void setUid(String uid) {
		this.uid = uid;
	}

	public String getUsername() {
		return this.username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return this.password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getStatus() {
		return this.status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

}