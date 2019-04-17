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
    public String say(@RequestParam(value = "year",required = false,defaultValue = "0") String year){

        if(year=="0") {
            return "请输入正确的年份";
        }else {
            String sql = "select * from sales where year="+year;
            List<Map<String,Object>> list =jdbcTemplate.queryForList(sql);

            return list.toString();
        }
    }

}
