@echo off
chcp 65001 >nul
cd /d "%~dp0"

rem 端口：改成你在阿里云安全组里放行的那个
if "%PORT%"=="" set PORT=5003
rem 访问密钥：留空=不校验；建议设一个，客户端「访问密钥」填同样的值
if "%SYNC_API_KEY%"=="" set SYNC_API_KEY=

where node >nul 2>nul
if errorlevel 1 (
  echo [x] 未检测到 Node.js，请先安装 Node 18+ : https://nodejs.org/zh-cn/download
  pause & exit /b 1
)

echo 启动中... 端口 %PORT%
echo 浏览器打开 http://127.0.0.1:%PORT% 即可使用，其它终端用 http://服务器公网IP:%PORT%
echo 按 Ctrl+C 停止
node server.js
pause
