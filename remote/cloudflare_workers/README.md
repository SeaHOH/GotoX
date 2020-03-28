0.4 测试版，支持基本的 HTTP 方法和 WebSocket。

此代理采用中间人方法实现代理，正常使用需要安装自签证书，运行 GotoX 并设置好代理，访问 http://gotox.go 安装证书。

CloudFlare Workers 虽然没有直接暴露 IP，但也属于非匿名，它发出的请求包含一个哈希标记，可用于查询服务器记录。

手动部署方法：  
https://github.com/SeaHOH/GotoX/wiki/简易部署教程：CloudFlare-Workers
