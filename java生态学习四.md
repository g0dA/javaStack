# Spring Boot连接mysql
`Spring Boot`连接`mysql`可以用`jdbcTemplate`，这是整合好的工具包，特别的方便。不过也踩了个坑。

## 配置
想要用到连接，就先配置好，就和python的导入模块一样
```
  <dependency>
   <groupId>mysql</groupId>
   <artifactId>mysql-connector-java</artifactId>
  </dependency>
  <dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-jdbc</artifactId>
  </dependency>
```
`application.properties`中添加连接`mysql`的配置
```
spring.datasource.url=jdbc:mysql://127.0.0.1:3306/test
spring.datasource.username=root
spring.datasource.password=password
spring.datasource.driver-class-name=com.mysql.jdbc.Driver
spring.datasource.max-idle=10
spring.datasource.max-wait=10000
spring.datasource.min-idle=5
spring.datasource.initial-size=5
```
用`jdbc`连接到具体的某一个库名。
> 运行起来可能会爆个小错误，Loading class `com.mysql.jdbc.Driver'. This is deprecated. The new driver class is `com.mysql.cj.jdbc.Driver'. The driver is automatically registered via the SPI and manual loading of the driver class is generally unnecessary.这个不影响项目的运行，就是说`com.mysql.jdbc.Driver`不用了，改用`com.mysql.cj.jdbc.Driver`了，自己改了也行

这就结束了，其余什么都不用配，然而代码里面，还是需要有个注意的。因为是使用的`JdbcTemplate`，不是直接就能用的，要先预定义下
```
@Resource
    private JdbcTemplate jdbcTemplate;
```
我一开始直接就调用`JdbcTemplate.queryForList`疯狂出错。查询函数有多个，我选用的是`queryForList`因为会返回一个`LIst`。当然也可以写`query`，然后需要传入自定义的函数。
## demo
一个demo
```
package com.example.demo;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.List;
import java.util.Map;

@RestController
@EnableAutoConfiguration
public class hello {

    @Resource
    private JdbcTemplate jdbcTemplate;
    //输出指定年份所有的信息
    @RequestMapping(value = {"/hello"},method = {RequestMethod.GET})
    public String say(@RequestParam(value = "year",required = false,defaultValue = "0") Integer year){
        if(year==0) {
            return "请输入正确的年份";
        }else {
            String sql = "select * from sales where year="+year;
            List<Map<String,Object>> list =jdbcTemplate.queryForList(sql);

            return list.toString();
        }
    }
}
```
`mybatis`本质上还是对`jdbc`的封装，它的优势在于：
1. 集中管理
所有的`sql`都在同一个`xml`文件中，方便管理
2. 动态生成sql
可以在`xml`中写条件判断，从而生成不同的`sql语句`
```
<select id="getCountByInfo" parameterType="User" resultType="int">
        select count(*) from user
        <where>
            <if test="nickname!=null">
                and nickname = #{nickname} 
            </if>
            <if test="email!=null">
                and email = #{email} 
            </if>
        </where>
</select>
```
劣势在于相比于`jdbc`更慢，因为`jdbc`更底层。
