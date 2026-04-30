#!/bin/sh
[ $# -ne 0 ] && { 
 echo "Usage: sh ffabcdef-2026-0427-1837-aaa140429035.sh ";
 exit 1;
}
# 获取当前路径

pathname=`pwd`


echo "touch /tmp/nsfocus_mod_tmp;">/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "chmod 777 /tmp/nsfocus_mod_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "if [ -f \"/etc/grub.conf\" ];then">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "    grub_mod=\`ls -l /etc/grub.conf | grep 'l[r-][w-][x-]'\`;">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "    if [ -z \"\$grub_mod\" ];then">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "        grub_mod=\`ls -l /etc/grub.conf\`;">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "        chmod --reference=/etc/grub.conf /tmp/nsfocus_mod_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "    else">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "        grub_mod=\`ls -l /boot/grub/grub.conf\`;">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "        chmod --reference=/boot/grub/grub.conf /tmp/nsfocus_mod_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "    fi">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "elif [ -f \"/boot/grub/grub.conf\" ];then">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "    grub_mod=\`ls -l /boot/grub/grub.conf\`;">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "    chmod --reference=/boot/grub/grub.conf /tmp/nsfocus_mod_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "elif [ -f \"/etc/lilo.conf\" ];then">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "    grub_mod=\`ls -l /etc/lilo.conf\`;">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "    chmod --reference=/etc/lilo.conf /tmp/nsfocus_mod_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "elif [ -f \"/etc/grub2.cfg\" ];then">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "    grub_mod=\`ls -l /etc/grub2.cfg | grep 'l[r-][w-][x-]'\`;">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "    if [ -z \"\$grub_mod\" ];then">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "        grub_mod=\`ls -l /etc/grub2.cfg\`;">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "        chmod --reference=/etc/grub2.cfg /tmp/nsfocus_mod_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "    else">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "        grub_mod=\`ls -l /boot/grub2/grub.cfg\`;">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "        chmod --reference=/boot/grub2/grub.cfg /tmp/nsfocus_mod_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "    fi">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "fi">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
sh /tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo '#!/bin/bash'>/tmp/NSF{nsf_tm}_Emptypassword
echo "arry_list1=(`cat /etc/shadow | awk 'BEGIN{FS=\":\"}{if($2==\"\")print $1};'`)">>/tmp/NSF{nsf_tm}_Emptypassword
echo "arry_list2=(`cat /etc/passwd | awk 'BEGIN{FS=\":\"}{if($7==\"/sbin/nologin\")print $1};'`)">>/tmp/NSF{nsf_tm}_Emptypassword
echo 'declare -a diff_list'>>/tmp/NSF{nsf_tm}_Emptypassword
echo 't=0'>>/tmp/NSF{nsf_tm}_Emptypassword
echo 'flag=0'>>/tmp/NSF{nsf_tm}_Emptypassword
echo 'for list1_num in "${arry_list1[@]}"'>>/tmp/NSF{nsf_tm}_Emptypassword
echo 'do'>>/tmp/NSF{nsf_tm}_Emptypassword
echo '    for list2_num in "${arry_list2[@]}"'>>/tmp/NSF{nsf_tm}_Emptypassword
echo '    do'>>/tmp/NSF{nsf_tm}_Emptypassword
echo '        if [[ "${list1_num}" == "${list2_num}" ]]; then'>>/tmp/NSF{nsf_tm}_Emptypassword
echo '            flag=1'>>/tmp/NSF{nsf_tm}_Emptypassword
echo '           break'>>/tmp/NSF{nsf_tm}_Emptypassword
echo '        fi'>>/tmp/NSF{nsf_tm}_Emptypassword
echo '    done'>>/tmp/NSF{nsf_tm}_Emptypassword
echo '    if [[ $flag -eq 0 ]]; then'>>/tmp/NSF{nsf_tm}_Emptypassword
echo '        diff_list[t]=$list1_num'>>/tmp/NSF{nsf_tm}_Emptypassword
echo '        t=$((t+1))'>>/tmp/NSF{nsf_tm}_Emptypassword
echo '    else'>>/tmp/NSF{nsf_tm}_Emptypassword
echo '        flag=0'>>/tmp/NSF{nsf_tm}_Emptypassword
echo '    fi'>>/tmp/NSF{nsf_tm}_Emptypassword
echo 'done'>>/tmp/NSF{nsf_tm}_Emptypassword
echo 'echo ${diff_list[@]}'>>/tmp/NSF{nsf_tm}_Emptypassword

# 执行pl脚本
perl $pathname/ffabcdef-2026-0427-1837-aaa140429035.pl


#----------------------------------------------------------
#备注:
#产品名称:BVS
#模板名称:银河麒麟 配置规范_S1A1G1
#配置核查模板版本:V6.0R03F02.0007
#所属行业:等级保护2.0
#系统版本:V6.0R03F03SP07
#HASH:42F1-91D7-00CD-EE46
