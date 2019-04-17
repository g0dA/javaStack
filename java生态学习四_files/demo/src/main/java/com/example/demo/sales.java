package com.example.demo;


public class sales {

    private Integer year;
    private String country;
    private String product;
    private Integer profit;

    //必须有无参的构造函数，不染数据库会报错
    public sales(){


    }

    public Integer getYear() {
        return year;
    }

    public Integer getProfit() {
        return profit;
    }

    public String getCountry() {
        return country;
    }

    public String getProduct() {
        return product;
    }
}
