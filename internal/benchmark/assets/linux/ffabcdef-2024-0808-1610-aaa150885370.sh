#!/bin/sh
[ $# -ne 0 ] && { 
 echo "Usage: sh ffabcdef-2024-0808-1610-aaa150885370.sh ";
 exit 1;
}
# 获取当前路径

pathname=`pwd`


echo "touch /tmp/nsfocus_mod_tmp;">/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "chmod 777 /tmp/nsfocus_mod_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
echo "if [ -f \"/etc/rc3.d\" ];then">>/tmp/NSF{nsf_tm}_nsfocus_grub_tmp
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
echo "touch /tmp/nsfocus_rc0_tmp;">/tmp/NSF{nsf_tm}_nsfocus_rc0_tmp
echo "touch /tmp/nsfocus_rc1_tmp;">/tmp/NSF{nsf_tm}_nsfocus_rc1_tmp
echo "touch /tmp/nsfocus_rc2_tmp;">/tmp/NSF{nsf_tm}_nsfocus_rc2_tmp
echo "touch /tmp/nsfocus_rc3_tmp;">/tmp/NSF{nsf_tm}_nsfocus_rc3_tmp
echo "touch /tmp/nsfocus_rc4_tmp;">/tmp/NSF{nsf_tm}_nsfocus_rc4_tmp
echo "touch /tmp/nsfocus_rc5_tmp;">/tmp/NSF{nsf_tm}_nsfocus_rc5_tmp
echo "touch /tmp/nsfocus_rc6_tmp;">/tmp/NSF{nsf_tm}_nsfocus_rc6_tmp
echo "if [ ! -h "/etc/rc0.d" ]; then">>/tmp/NSF{nsf_tm}_nsfocus_rc0_tmp
echo "        chmod --reference=/etc/rc0.d /tmp/nsfocus_rc0_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_rc0_tmp
echo "else">>/tmp/NSF{nsf_tm}_nsfocus_rc0_tmp
echo "        chmod --reference=/etc/rc.d/rc0.d /tmp/nsfocus_rc0_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_rc0_tmp
echo "fi">>/tmp/NSF{nsf_tm}_nsfocus_rc0_tmp
echo "if [ ! -h "/etc/rc1.d" ]; then">>/tmp/NSF{nsf_tm}_nsfocus_rc1_tmp
echo "        chmod --reference=/etc/rc1.d /tmp/nsfocus_rc1_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_rc1_tmp
echo "else">>/tmp/NSF{nsf_tm}_nsfocus_rc1_tmp
echo "        chmod --reference=/etc/rc.d/rc1.d /tmp/nsfocus_rc1_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_rc1_tmp
echo "fi">>/tmp/NSF{nsf_tm}_nsfocus_rc1_tmp
echo "if [ ! -h "/etc/rc2.d" ]; then">>/tmp/NSF{nsf_tm}_nsfocus_rc2_tmp
echo "        chmod --reference=/etc/rc2.d /tmp/nsfocus_rc2_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_rc2_tmp
echo "else">>/tmp/NSF{nsf_tm}_nsfocus_rc2_tmp
echo "        chmod --reference=/etc/rc.d/rc2.d /tmp/nsfocus_rc2_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_rc2_tmp
echo "fi">>/tmp/NSF{nsf_tm}_nsfocus_rc2_tmp
echo "if [ ! -h "/etc/rc3.d" ]; then">>/tmp/NSF{nsf_tm}_nsfocus_rc3_tmp
echo "        chmod --reference=/etc/rc3.d /tmp/nsfocus_rc3_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_rc3_tmp
echo "else">>/tmp/NSF{nsf_tm}_nsfocus_rc3_tmp
echo "        chmod --reference=/etc/rc.d/rc3.d /tmp/nsfocus_rc3_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_rc3_tmp
echo "fi">>/tmp/NSF{nsf_tm}_nsfocus_rc3_tmp
echo "if [ ! -h "/etc/rc4.d" ]; then">>/tmp/NSF{nsf_tm}_nsfocus_rc4_tmp
echo "        chmod --reference=/etc/rc4.d /tmp/nsfocus_rc4_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_rc4_tmp
echo "else">>/tmp/NSF{nsf_tm}_nsfocus_rc4_tmp
echo "        chmod --reference=/etc/rc.d/rc4.d /tmp/nsfocus_rc4_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_rc4_tmp
echo "fi">>/tmp/NSF{nsf_tm}_nsfocus_rc4_tmp
echo "if [ ! -h "/etc/rc5.d" ]; then">>/tmp/NSF{nsf_tm}_nsfocus_rc5_tmp
echo "        chmod --reference=/etc/rc5.d /tmp/nsfocus_rc5_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_rc5_tmp
echo "else">>/tmp/NSF{nsf_tm}_nsfocus_rc5_tmp
echo "        chmod --reference=/etc/rc.d/rc5.d /tmp/nsfocus_rc5_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_rc5_tmp
echo "fi">>/tmp/NSF{nsf_tm}_nsfocus_rc5_tmp
echo "if [ ! -h "/etc/rc6.d" ]; then">>/tmp/NSF{nsf_tm}_nsfocus_rc6_tmp
echo "        chmod --reference=/etc/rc6.d /tmp/nsfocus_rc6_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_rc6_tmp
echo "else">>/tmp/NSF{nsf_tm}_nsfocus_rc6_tmp
echo "        chmod --reference=/etc/rc.d/rc6.d /tmp/nsfocus_rc6_tmp;">>/tmp/NSF{nsf_tm}_nsfocus_rc6_tmp
echo "fi">>/tmp/NSF{nsf_tm}_nsfocus_rc6_tmp
sh /tmp/NSF{nsf_tm}_nsfocus_grub_tmp
sh /tmp/NSF{nsf_tm}_nsfocus_rc0_tmp
sh /tmp/NSF{nsf_tm}_nsfocus_rc1_tmp
sh /tmp/NSF{nsf_tm}_nsfocus_rc2_tmp
sh /tmp/NSF{nsf_tm}_nsfocus_rc3_tmp
sh /tmp/NSF{nsf_tm}_nsfocus_rc4_tmp
sh /tmp/NSF{nsf_tm}_nsfocus_rc5_tmp
sh /tmp/NSF{nsf_tm}_nsfocus_rc6_tmp

# 执行pl脚本
perl $pathname/ffabcdef-2024-0808-1610-aaa150885370.pl


#----------------------------------------------------------
#备注:
#产品名称:BVS
#模板名称:Linux 配置规范_S1A1G1
#配置核查模板版本:V6.0R03F02.0007
#所属行业:等级保护2.0
#系统版本:V6.0R03F03SP07
#HASH:42F1-91D7-00CD-EE46
