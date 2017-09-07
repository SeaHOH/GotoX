# GoProxy GAE Server
- 这算是增加冗余吧。相比原版作了以下修改：
    - 上传程序
        - 增加应用密码设置，省去手工修改。
        - 增加失败重试机制，省去重启时间，自动（默认 `max_retry = 1`） + 手动。
        - 除标题 GoProxy 字样外其它描述都改为适应 GotoX。
    - GAE 应用
        - 支持不同的 debug 级别（0-2）。
        - 不修改的代理请求的 `Accept-Encoding` 头域。
        - 扩大检查 `Content-Encoding` 头域的匹配范围。
        - 修改首页版本检测时获取的链接到本仓库。

# 使用
- Windows 用户：
    - 已安装 Python2，直接双击 `uploader.py` 运行即可；
    - 或者访问[发布页面](https://github.com/SeaHOH/GotoX/releases)下载包含便携 Python2 的发布版，然后双击 `uploader.bat` 运行。
- Linux/Mac 用户：
    - 直接在此文件夹运行命令 `python uploader.py` 即可。
