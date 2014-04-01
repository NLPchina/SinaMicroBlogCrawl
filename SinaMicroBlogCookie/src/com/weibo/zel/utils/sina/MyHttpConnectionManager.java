package com.weibo.zel.utils.sina;

import org.apache.http.client.params.ClientPNames;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnManagerParams;
import org.apache.http.conn.params.ConnPerRouteBean;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;

public class MyHttpConnectionManager {
	// 对链接超过时的设置
	public static HttpParams httpParams;
	public static ClientConnectionManager connectionManager;

	// 数据设置
	// 最大链接数
	public static int max_connection = Integer.parseInt(ReadSpiderConfig
			.getValue("max_connections"));
	// 获取链接的最大等待时间
	public static int wait_connection_timeout = Integer
			.parseInt(ReadSpiderConfig.getValue("wait_connection_timeout"));
	// 连接超时时间
	public static int connection_timeout = Integer.parseInt(ReadSpiderConfig
			.getValue("connection_timeout"));
	// 读取超时
	public static int read_timeout = Integer.parseInt(ReadSpiderConfig
			.getValue("read_timeout"));

	// 取得DefaultHttpClient
	public static DefaultHttpClient defaultClient;
	static {
		httpParams = new BasicHttpParams();
		// HttpConnectionParams.
		ConnManagerParams.setMaxTotalConnections(httpParams, max_connection);
		ConnManagerParams.setTimeout(httpParams, wait_connection_timeout);
		//每个路由的最大链接个数,标志对同一站点的并发请求
		ConnPerRouteBean connPerRoute = new ConnPerRouteBean(100);
		ConnManagerParams.setMaxConnectionsPerRoute(httpParams, connPerRoute);
		
		HttpConnectionParams.setConnectionTimeout(httpParams,
				connection_timeout);
		HttpConnectionParams.setSoTimeout(httpParams, read_timeout);
		SchemeRegistry registry = new SchemeRegistry();
		registry.register(new Scheme("http", PlainSocketFactory
				.getSocketFactory(), 80));

		registry.register(new Scheme("https", SSLSocketFactory
				.getSocketFactory(), 443));

		connectionManager = new ThreadSafeClientConnManager(httpParams,
				registry);
		// httpParams.setParameter(ClientPNames.HANDLE_REDIRECTS,false);
		defaultClient = new DefaultHttpClient(connectionManager, httpParams);
	}

	public static DefaultHttpClient getHttpClient() {
		return defaultClient;
	}

	public static DefaultHttpClient getNewHttpClient() {
//		SchemeRegistry registry = new SchemeRegistry();
//		registry.register(new Scheme("http", PlainSocketFactory
//				.getSocketFactory(), 80));
//
//		registry.register(new Scheme("https", SSLSocketFactory
//				.getSocketFactory(), 443));
//		connectionManager = new ThreadSafeClientConnManager(httpParams,
//				registry);
//		DefaultHttpClient new_defaultClient = new DefaultHttpClient(
//				connectionManager, httpParams);
//		return new_defaultClient;
		return defaultClient;
	}

	// 设置是否重由httpclient自动管理跳转
	public static void setHandleRedirect(DefaultHttpClient defaultClient,
			boolean isAuto) {
		if (isAuto) {
			defaultClient.getParams().setParameter(
					ClientPNames.HANDLE_REDIRECTS, true);
		} else {
			defaultClient.getParams().setParameter(
					ClientPNames.HANDLE_REDIRECTS, false);
		}
	}

	public static void main(String[] args) {
		// System.out.println("static---"+getHttpClient());
		// System.out.println("new----"+getNewHttpClient());
	}
}
