package com.weibo.zel.entity.util;

public class ProxyPojo {
	private String ip;
	private boolean authEnable;

	public boolean isAuthEnable() {
		return authEnable;
	}

	public void setAuthEnable(boolean authEnable) {
		this.authEnable = authEnable;
	}

	public String getIp() {
		return ip;
	}

	public void setIp(String ip) {
		this.ip = ip;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	private String username;
	private int port;

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	private String password;

	//无认证
	public ProxyPojo(String ip, int port) {
		this.ip = ip;
		this.port = port;
	}
	//有认证
	public ProxyPojo(String ip, int port, String username, String password) {
		this.ip = ip;
		this.port = port;
		this.username = username;
		this.password = password;
	}

}
