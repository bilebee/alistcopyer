@echo off
chcp 65001
REM 一键打包脚本

pyinstaller --onefile --noconsole  alistcpy.py

echo 打包完成！可执行文件位于 dist 文件夹
pause