# 私服仓库

架设在局域网中的特殊远程仓库，目的是代理与部署第三方构建。

特点：
    1. 有则直接下载
    2. 没有则通过代理下载到私服，再下载
    
**Nexus**

> maven仓库管理软件

仓库概念：
1. 代理仓库`proxy`
2. 宿主仓库`hosted`
3. 虚拟仓库`virtual`
4. 仓库组`group`

> 仓库组是一种特殊的仓库概念，请求仓库组即可请求仓库组下管理的仓库

格式：
1. maven1
2. maven2(现在都是这个)

> maven2与maven1最大的区别在于提速与简化配置

策略属性：
1. Release(发布版本)
2. Snapshot(快照版本)

# 构建

> `Android studio`默认支持`Gradle`，属于一个`client`
**project**

一个`Gradle`是由一个或者多个`project`组成，而每个`project`又包含了许多可构建组成的部分，通过`Gradle`的`build-by-convention`具体定义一个`project`的用途。

`project`由一个个`task`组成，每一个`task`代表一个构建执行过程中的原子性操作，如编译，打包，生成javadoc，发布到仓库这样具体的操作。


**task**
`gradle`是由一个个任务(`task`)完成的，基类是`DefaultTask`(必须继承)，存在一个生命周期:
`初始化阶段` -- `配置阶段` -- `执行阶段`

`配置阶段`的代码在执行任何`task`时候都会跟着执行，需要执行的操作在`task`都是一个个`action`，然后组成了一个队列，通过`doFirst`或者是`doLast`来决定`action`在队列中的执行顺序。

排列方式，如下伪代码的顺序是`2`，`1`，`1`，`2`
```
doLast 1
doFirst 1
doFirst 2
doLast 2
```

因为`task`对于`action`的执行是顺序的，而`doLast`和`doFirst`是首位部插入，先插入的自然比后插入的靠中心位置。

**Gradle构建方式**

![gradle获取依赖](./java一/gradle.jpg)

在`build.gradle`中声明项目依赖`3.0`版本的`common-lang3`，`Gradle`就会检查本地存储库中是否有该依赖库，如果没有就通过网络的`Gradle Repository`下载到本地，然后自动声明`classpath`

`gradle`和`maven`相比来说，`maven`是基于`XML`的配置，而`gradle`是采用了`Groovy`这种特殊语言做到了配置可编程。而且在配置上`gradle`对`maven`而言做到了沿用与简化，并且还提供了`动态版本依赖`，通过在`版本号`后
添加`+`来实现动态的版本管理。

关于`依赖冲突`的解决，`Maven`和`Gradle`进行依赖管理时都是采用的`传递性依赖`，但是如果多个依赖指向同一个依赖的不同版本就会引起依赖冲突，对于这点`Gradle`已经做到了较好的展示方式。


