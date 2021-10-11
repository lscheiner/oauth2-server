package br.com.scheiner.oauth.main;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@ComponentScan(basePackages = {"br.com.scheiner"})
@EnableJpaRepositories("br.com.scheiner.repository")
@EntityScan("br.com.scheiner.entity")  
public class OauthAuthServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(OauthAuthServerApplication.class);
	}

}
