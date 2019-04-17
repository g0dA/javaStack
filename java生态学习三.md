# 初识Spring Boot
> 没用过任何java的框架做过web开发，因此要问Sping Boot的优劣到底在哪，我也说不上，自己封装了`tomcat`，开箱即用？

## 入口
`Spring Boot`程序的入口并非业务代码中的定义了`main函数`的类，而是`Spring Boot`自己定义的`JarLauncher`类，这个也就是`MANIFEST.MF`中的`Main-Class`。而业务中的`main函数`则是通过`getMainClass()`在`MANIFEST.MF`查找`Start-Class`找到然后通过反射调用的。
```
    public void run() throws Exception {
        Class mainClass = Thread.currentThread().getContextClassLoader().loadClass(this.mainClassName);
        Method mainMethod = mainClass.getDeclaredMethod("main", new Class[]{String[].class});
        mainMethod.invoke((Object)null, new Object[]{this.args});
    }
```
用`IDEA`创建`Spring Boot`项目会默认生成一个入口类
```
@SpringBootApplication
public class DemoApplication {
 public static void main(String[] args) {
  SpringApplication.run(DemoApplication.class, args);
 }
}
```
其中`Spring Boot`被人喜欢的就是自动化配置，而这点光是从入口类上就可见一斑。
`@SpringBootApplication`注解类中会调用到`Sping Boot`的核心注解类`@EnableAutoConfiguration`，此类可以帮助`Spring Boot`应用将所有符合条件的`@Configuration`都加载到当前应用创建并使用的`IoC`容器中。
而`@EnableAutoConfiguration`依靠的也是`AutoConfigurationImportSelector`和`SpringFactoriesLoader`才能产生此效果。
落实到具体的配置文件是如下代码，这会被`SpringFactoriesLoader.loadFactoryNames`调用。
```
public static final String
    FACTORIES_RESOURCE_LOCATION = "META-INF/spring.factories";
```
> 再通俗说就是把`spring.factories`中需要自动配置的类的全名全都放入了`ImportSelector`，然后用时即取。

## 控制层
怎么称呼呢？路由？大概就是这么个意思。
```
@RestController
@EnableAutoConfiguration
public class hello {
    @RequestMapping(value = {"/hello","/say"},method = RequestMethod.GET)
    public String say(){
        return "hello,this is a demo";
    }
}
```
`@RestController`注解类负责格式化错误输出成`json`，其实还是封装了一层`@Controller`，而且默认的解析框架是`jackson`
`@RequestMapping`是一个用来处理地址映射的注解类，有六个参数，常用其中三个。
```
@RequestMapping(value = {"/hello","/say"},method = {RequestMethod.GET},headers = {})
```
上面是比较标准的写法，实际如果是单独路径的话(多路径是或关系)，可以简化写法
```
@RequestMapping("/hello");
```
`@PathVariable`URL变量设置，这样访问`/hello/1`就可以得到结果了。
```
    @RequestMapping(value = {"/hello/{id}"},method = {RequestMethod.GET})
    public String say(@PathVariable("id") Integer id){
        if(id==1) {
            return "hello,this is a demo";
        }else {
            return "id=1";
        }
    }
```
`@RequestParam`参数设置，就是`get`的传参
```
    @RequestMapping(value = {"/hello/{id}"},method = {RequestMethod.GET})
    public String say(@PathVariable("id") Integer id, @RequestParam Integer aa,@RequestParam String name){
        if(id==1) {
            return "hello,this is a demo and id:"+aa+"and name:"+name;
        }else {
            return "id=1";
        }
    }
```
> 如果没传入的话可以使用`required=false`+`defaultValue=value`作为`@RequestParam`的参数来设置默认。

## 模块
如果说`auto-configuration`是亮点的话，那`actuator`就不逊于它，这是`Spring Boot`的自省和监控模块，可以对整个应用进行配置查看和相关功能统计等。
开启所有的`endpoint`
```
management.endpoints.web.exposure.include=*
```
至于安全问题，看一圈，有但是很比较难说，还是配置不当吧。

# 参考资料
* [Spring Boot项目的真实程序入口](https://blog.csdn.net/Fly2Leo/article/details/78612604)
* [看源码，我为什么建议你先从 SpringBoot 开始](https://www.xttblog.com/?p=4016)
* [@Controller和@RestController的区别？](https://blog.csdn.net/gg12365gg/article/details/51345601)
* [springboot之@RequestMapping](https://blog.csdn.net/weixin_36775115/article/details/79541981)
* [顶(0) 踩(0)
SpringBoot应用监控Actuator使用的安全隐患](https://xz.aliyun.com/t/2233)

