#!/bin/bash
install_path=$HOME/Desktop/pwn_env

repos=(gef Pwngdb pwndbg pwntools pwncli peda decomp2dbg deploy_pwn_template )
for repo in ${repos[@]}
do
cd ${install_path}/${repo} && git pull && echo "update ${repo} end!"
done

cd $install_path/pwndbg && ./setup.sh
