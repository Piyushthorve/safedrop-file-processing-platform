package com.cloudProject.cloudP;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@SpringBootApplication
public class CloudPApplication {

	public static void main(String[] args) {
		SpringApplication.run(CloudPApplication.class, args);
	}

}
