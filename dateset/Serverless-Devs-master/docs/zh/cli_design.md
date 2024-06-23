---
title: 命令行设计规范
description: 'Serverless Devs 命令行设计规范'
position: 10
category: '概述'
---

# 命令行设计规范

Serverless Devs 作为 Serverless 领域的开发者工具，其输出的标准化和规范化会在一定程度上对用户体验有比较明显的影响。

本文档将会通过一些文字和案例，对Serverless Devs的命令行工具输出，进行规范化升级。

## 规范详情

输出格式的规范目标是：

- 更清晰
- 更简约
- 不影响功能实用

基于以上三个原则，我们可以通过正常输出的形式、异常输出的形式等分别进行举例说明

### 基本输出

基本输出的形式，整体上包括两个部分：

1. 项目执行阶段

项目执行阶段主要包括一个基本格式:

```
⌛ Steps for process
====================
```

采用重写机制，不断的更新输出内容，每个项目执行完成可以输出相对应的结果，示例：

```
⌛ Steps for process
====================
✔ Pre-action completed (10s)
```

2. 结果输出阶段

项目执行阶段主要包括一个基本格式:

```
🚀 Result for process
====================
```

具体的项目输出采用`Yaml`的格式进行输出，输出时，项目名称要加下划线，如果没有输出则直接结束项目，示例：

```
🚀 Result for process
====================
✔ MyProject deployed (11s)
fc-deploy-test:
  region: cn-hangzhou
  service:
    name: fc-deploy-service
    memorySize: 128
```

#### 单项目输出示例

![render1629447409205](https://user-images.githubusercontent.com/21079031/130204631-174a5af5-5550-4e7f-bc3b-d6d23681ce61.gif)


#### 多项目输出示例

![render1629448703505](https://user-images.githubusercontent.com/21079031/130206222-8674550e-2ecf-4e19-9dac-d81a8ab11b02.gif)


### 调试模式

当用户使用`--debug`进入到调试模式，则会打印非常详细的信息在控制台，但是这些信息将会以灰色形式打印出来，以保持整体的层次感：

![render1629448900851](https://user-images.githubusercontent.com/21079031/130206327-b25c444f-d336-4dc3-8dfe-39a5329e4b13.gif)



### 错误输出

当执行出现错误时，Serverless Devs要做到感知并输出相对应的内容：

```
⌛ Steps for process
====================
✔ MyProject pre-action completed (10s)
✖ MyProject failed to deploy:

Error Message: 
t[r] is not a function

Env:   darwin, node v15.14.0
Docs:  https://github.com/serverless-devs/docs
Bugs:  https://github.com/Serverless-Devs/Serverless-Devs/issues
Logs:  ~/demo/demo/demo/s.log
```

动态效果为：

![render1629447327225](https://user-images.githubusercontent.com/21079031/130204744-be670d4b-0c1a-4128-aafe-3e8871b3ef58.gif)

