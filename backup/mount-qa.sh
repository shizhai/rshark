#!/bin/bash

#================================================================
#       Copyright (C) 2023 All rights reserved.
#       
#       文件名称：wifi-alive.sh
#       创 建 者：shizhai(ysprogram@163.com)
#       创建日期：2023年04月12日
#       描    述：
#
#================================================================

# script dir
SCRIPT_PATH=$(dirname $0)

#tmp dir
TEMP_DIR=$SCRIPT_PATH/tmp
mkdir -p $TEMP_DIR

#remote parent dir
mkdir -p remote

#percent usage limit
pulimit=60

# disk run out of mem, we should clean some old files
clr_file=$TEMP_DIR/clr_file.tmp
> $clr_file

function search_mount()
{
	new_mount=0
	while read line
	do
		if [ -n "$(echo $line | grep '^#')" ];then continue;fi

		client=$(echo $line | tr -d ' ' | tr -d '\n');
		user=$(echo $client | awk -F! '{print $1}')
		passwd=$(echo $client | awk -F! '{print $2}')
		port=$(echo $client | awk -F! '{print $3}')
		ip=$(echo $client | awk -F! '{print $4}')
		remote_path=$(echo $client | awk -F! '{print $5}')
        local_root=$(echo $client | awk -F! '{print $6}')
        reverse=$(echo $client | awk -F! '{print $7}')

		#echo "line:${line}"
		#echo "client:${client}"
		#echo "user:${user}"
		#echo "passwd:${passwd}"
		#echo "ip:${ip}"
		#echo "remote_path:${remote_path}"
		#echo "stores:${local_root}"

		ping -w 1 -c 1 $ip >/dev/null
		if [ $? -ne 0 ];then
			continue;
		fi

		local_path=${local_root}/$ip

		exist_mount=$(sudo df -h | grep "${local_path}")

		if [ "" != "${exist_mount}" ];then
			consumed=$(echo $exist_mount | awk '{print $5}' | awk -F% '{print $1}')
			if [ $consumed -gt ${pulimit} ];then
				echo $client >> $clr_file
			fi

			continue;
		fi

		#echo "mount $user@$ip:$remote_path to $local_path"

		sudo umount ${local_root}/$ip >/dev/null 2>&1

        if [ $reverse -gt 0 ];then
            continue;
        fi

		rm -rf ${local_path}
		mkdir -p ${local_path}

		new_mount=1

		if [ -z "$passwd" ];then
			#sshfs -o allow_other,reconnect,ServerAliveInterval=15,ServerAliveCountMax=3 $user@$ip:$remote_path $local_path
			sshfs -o allow_other,ConnectTimeout=3,ConnectionAttempts=1,ServerAliveInterval=5,ServerAliveCountMax=3,StrictHostKeyChecking=no,UserKnownHostsFile=/dev/null $user@$ip:$remote_path $local_path
		else
			#sshfs -o allow_other,reconnect,ServerAliveInterval=15,ServerAliveCountMax=3,password_stdin $user@$ip:$remote_path $local_path <<< "$passwd"
			sshfs -o allow_other,ConnectTimeout=3,ConnectionAttempts=1,ServerAliveInterval=5,ServerAliveCountMax=3,StrictHostKeyChecking=no,UserKnownHostsFile=/dev/null,password_stdin $user@$ip:$remote_path $local_path <<< \"$passwd\"
		fi
	done < ${SCRIPT_PATH}/clients

	if [ $new_mount -eq 1 ];then
		docker restart filebrowser
	fi
}

asrd=$(ps xua | grep asrd | grep -v grep  | wc -l)

if [ $asrd -gt 0 ];then
    for pid in `ps aux | grep asrd | grep -v grep | awk '{print $2}' | tr '\n' ' '`
    do
        echo "kill $pid"
        kill -9 $pid
    done
fi


while true;do
	search_mount

	# clear timeout file
	while read line;do
		echo $line
	done < $clr_file

	> $clr_file

    asrd=$(ps xua | grep asrd | grep -v grep  | wc -l)
    if [ $asrd -eq 0 ];then
        echo "start asrd"
        asrd -c ${SCRIPT_PATH}/clients &
    fi

	sleep 10
done
