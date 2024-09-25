SPRING SECURITY 

Spring Boot Version
<version>3.3.4</version>

Mavan dependency

                <dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt</artifactId>
			<version>0.12.5</version>
		</dependency>
                <dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>

 @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


Database 
 --- MySQL
Java version 
  ---17

 Role 
	 INSERT INTO `secu`.`role` (`id`, `role_name`) VALUES ('1', 'USER');
	 INSERT INTO `secu`.`role` (`id`, `role_name`) VALUES ('2', 'ADMIN');

API----
1)  Create User 
  http://localhost:7777/auth/register

 Input json
  
{
    "userName": "testq",
    "password": "testq",
    "email": "testq@gmail.com",
    "role": {
        "id": 1,
        "roleName": "User"
    }
}

2) login User

http://localhost:7777/auth/login

Input Json

{
    "password":"testq",
    "email":"testq@gmail.com"
}
