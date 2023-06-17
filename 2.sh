omz reload
pwncli misc setgdb -g
cd $HOME/Desktop/pwn_env
# 安装decomp2dbg
git clone https://github.com/mahaloz/decomp2dbg.git
cd decomp2dbg 
# 记得拷贝文件
# cp -r ./decompilers/d2d_ida/* /path/to/ida/plugins/
pip3 install . && \
cp d2d.py ~/.d2d.py && echo "source ~/.d2d.py" >> ~/.gdbinit
