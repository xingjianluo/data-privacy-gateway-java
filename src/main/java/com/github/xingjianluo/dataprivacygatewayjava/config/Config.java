package com.github.xingjianluo.dataprivacygatewayjava.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/** 启用配置属性绑定与定时任务（审计留存清理）。 */
@Configuration
@EnableConfigurationProperties(GatewayProperties.class)
@EnableScheduling
public class Config {
}
