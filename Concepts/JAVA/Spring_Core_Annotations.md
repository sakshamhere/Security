https://www.youtube.com/watch?v=If1Lw4pLLEo

- Dependency Injection

XML Based Configuration:

> The core thing to understand is that when we use dependency injection, we change things in a xml and not change java souce code evrytime, so we dont need to compile code everyttime, we can simply save the change in xml file and things will work

to do this we use "getBean", for which 2 Interface are available in spring, 
1. BeanFactory
2. ApplicationContext

Beans provide us directly the object of class we mention

Bean Propery and Constructor-arg


Annotation Based Configuration:
@Component
To achive dependency injection we use @Component in class for which we want xml to provide object for.
When using @Component we are not writing id in beans , in this case the default name will be the name of class only in small case

@Autowired
@Configuration // name giiven will be decapitalised by default
@Configuration("your provided name")
@Bean
@ComponentScan(baspackage="")
@Primary
@Qualifier //Qualifer overites primary, its preferred over primary means

Java Configuration

So if we are creating a small app then Beanfactory can be used but if we are using Big enterprise level or web application then we prefer Application Context

- Maven
1. Project
2. Group Id - com.doshi
3. Artifact Id - demo
4. Package - com.doshi.demo.web

- Spring IOC
- Spring Dependency Injection
 