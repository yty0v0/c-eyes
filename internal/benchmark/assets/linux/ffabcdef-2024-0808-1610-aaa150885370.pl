#!env perl
#Author: autoCreated
my $para_num = "0";
# 配置模板创建时间
my $template_time = "2024-08-08 16:10:15";
my %para;
@array_pre_flag = ();
@array_appendix_flag = ();


# 处理检查项中的执行命令




# 处理附录检查项中的执行命令

$appendix_cmd{6} = "chkconfig --list | head -50";$appendix_cmd{3} = "cat  /etc/shadow 2>/dev/null | head -300";$appendix_cmd{11} = "lastb -100 2>/dev/null";$appendix_cmd{5} = "cat  /etc/securetty 2>/dev/null | head -300";$appendix_cmd{1} = "cat /etc/passwd 2>/dev/null | head -300";$appendix_cmd{4} = "if [ -f /etc/shadow ];then lsattr /etc/shadow 2>/dev/null;fi;
if [ -f /etc/gshadow ];then lsattr /etc/group 2>/dev/null;fi;
if [ -f /etc/passwd ];then lsattr /etc/passwd 2>/dev/null;fi";$appendix_cmd{20} = "cat /etc/ftpaccess 2>/dev/null | grep -v \"^[[:space:]]*#\" | head -300";$appendix_cmd{8} = "last -100 2>/dev/null";$appendix_cmd{14} = "netstat -anp 2>/dev/null | head -300";$appendix_cmd{19} = "cat /etc/ftpaccess 2>/dev/null | grep \"^[[:space:]]*banner[[:space:]]*\\/.*\" | awk '{print \$2}' | while read user; do cat \$user;done | grep -v \"^[[:space:]]*#\" | head -300";$appendix_cmd{21} = "rpm -qa | head -100";$appendix_cmd{13} = "rm -v /tmp/NSF{nsf_tm}_nsfocus_grub_tmp /tmp/NSF{nsf_tm}_Emptypassword";$appendix_cmd{15} = "ps -ef | grep -v \"\\.sh\" | grep -v \"\\.pl\"";$appendix_cmd{16} = "if [ -f /etc/vsftpd.conf ];then cat /etc/vsftpd.conf |grep -v ^#|grep ftpd_banner;elif [ -f /etc/vsftpd/vsftpd.conf ];then cat /etc/vsftpd/vsftpd.conf |grep -v ^#|grep ftpd_banner;fi";$appendix_cmd{2} = "cat  /etc/group 2>/dev/null | head -300";$appendix_cmd{9} = "if [ -f /etc/syslog.conf ];then cat /etc/syslog.conf | grep -v \"^[[:space:]]*#\" | head -300;elif [ -f /etc/syslog-ng/syslog-ng.conf ];then cat /etc/syslog-ng/syslog-ng.conf | grep -v \"^[[:space:]]*#\"  | head -300;elif [ -f /etc/rsyslog.conf ];then cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\"  | head -300;fi";$appendix_cmd{7} = "ifconfig -a 2>/dev/null";$appendix_cmd{0} = "uname -a 2>/dev/null";$appendix_cmd{12} = "(head -20 /var/log/syslog;head -20 /var/log/messages) 2>/dev/null";$appendix_cmd{17} = "cat /etc/vsftpd/chroot_list 2>/dev/null | grep \"^[[:space:]]*[^#]\" | head -300";$appendix_cmd{22} = "version=`lsb_release -a 2>/dev/null | grep \"Description\" | awk -F: '{print \$2}'`;if [ -n \"\$version\" ];then echo \$version;else if [ -z \"\$version\" ]; then echo \"\";else cat /etc/SuSE-release | grep -v \"VERSION\" | grep -v \"PATCHLEVEL\";fi;fi";$appendix_cmd{10} = "df -m 2>/dev/null";
push(@array_appendix_flag, 6);
push(@array_appendix_flag, 3);
push(@array_appendix_flag, 11);
push(@array_appendix_flag, 5);
push(@array_appendix_flag, 1);
push(@array_appendix_flag, 4);
push(@array_appendix_flag, 20);
push(@array_appendix_flag, 8);
push(@array_appendix_flag, 14);
push(@array_appendix_flag, 19);
push(@array_appendix_flag, 21);
push(@array_appendix_flag, 13);
push(@array_appendix_flag, 15);
push(@array_appendix_flag, 16);
push(@array_appendix_flag, 2);
push(@array_appendix_flag, 9);
push(@array_appendix_flag, 7);
push(@array_appendix_flag, 0);
push(@array_appendix_flag, 12);
push(@array_appendix_flag, 17);
push(@array_appendix_flag, 22);
push(@array_appendix_flag, 10);

$appendix_cmd1{6} = "chkconfig --list | head -50";$appendix_cmd1{3} = "cat  /etc/shadow 2>/dev/null | head -300";$appendix_cmd1{11} = "lastb -100 2>/dev/null";$appendix_cmd1{5} = "cat  /etc/securetty 2>/dev/null | head -300";$appendix_cmd1{1} = "cat /etc/passwd 2>/dev/null | head -300";$appendix_cmd1{4} = "if [ -f /etc/shadow ];then lsattr /etc/shadow 2>/dev/null;fi;
if [ -f /etc/gshadow ];then lsattr /etc/group 2>/dev/null;fi;
if [ -f /etc/passwd ];then lsattr /etc/passwd 2>/dev/null;fi";$appendix_cmd1{20} = "cat /etc/ftpaccess 2>/dev/null | grep -v \"^[[:space:]]*#\" | head -300";$appendix_cmd1{8} = "last -100 2>/dev/null";$appendix_cmd1{14} = "netstat -anp 2>/dev/null | head -300";$appendix_cmd1{19} = "cat /etc/ftpaccess 2>/dev/null | grep \"^[[:space:]]*banner[[:space:]]*\\/.*\" | awk '{print \$2}' | while read user; do cat \$user;done | grep -v \"^[[:space:]]*#\" | head -300";$appendix_cmd1{21} = "rpm -qa | head -100";$appendix_cmd1{13} = "rm -v /tmp/NSF{nsf_tm}_nsfocus_grub_tmp /tmp/NSF{nsf_tm}_Emptypassword";$appendix_cmd1{15} = "ps -ef | grep -v \"\\.sh\" | grep -v \"\\.pl\"";$appendix_cmd1{16} = "if [ -f /etc/vsftpd.conf ];then cat /etc/vsftpd.conf |grep -v ^#|grep ftpd_banner;elif [ -f /etc/vsftpd/vsftpd.conf ];then cat /etc/vsftpd/vsftpd.conf |grep -v ^#|grep ftpd_banner;fi";$appendix_cmd1{2} = "cat  /etc/group 2>/dev/null | head -300";$appendix_cmd1{9} = "if [ -f /etc/syslog.conf ];then cat /etc/syslog.conf | grep -v \"^[[:space:]]*#\" | head -300;elif [ -f /etc/syslog-ng/syslog-ng.conf ];then cat /etc/syslog-ng/syslog-ng.conf | grep -v \"^[[:space:]]*#\"  | head -300;elif [ -f /etc/rsyslog.conf ];then cat /etc/rsyslog.conf | grep -v \"^[[:space:]]*#\"  | head -300;fi";$appendix_cmd1{7} = "ifconfig -a 2>/dev/null";$appendix_cmd1{0} = "uname -a 2>/dev/null";$appendix_cmd1{12} = "(head -20 /var/log/syslog;head -20 /var/log/messages) 2>/dev/null";$appendix_cmd1{17} = "cat /etc/vsftpd/chroot_list 2>/dev/null | grep \"^[[:space:]]*[^#]\" | head -300";$appendix_cmd1{22} = "version=`lsb_release -a 2>/dev/null | grep \"Description\" | awk -F: '{print \$2}'`;if [ -n \"\$version\" ];then echo \$version;else if [ -z \"\$version\" ]; then echo \"\";else cat /etc/SuSE-release | grep -v \"VERSION\" | grep -v \"PATCHLEVEL\";fi;fi";$appendix_cmd1{10} = "df -m 2>/dev/null";
# 获取操作系统信息函数
sub get_os_info{
 my %os_info = (
 "hostname"=>"","osname"=>"","osversion"=>"");
 $os_info{"hostname"} = `uname -n`;
 $os_info{"osname"} = `uname -s`;
 $os_info{"osversion"} = `uname -r`;
foreach (%os_info){   chomp;}
return %os_info;}

# 执行命令存入xml文件
sub add_item{
 my ($string, $flag, $command, $value)= @_;
 $string .= "\t\t".'<item flag="'.$flag.'">'."\n";
 $string .= "\t\t\t".'<cmd info="'.$date.'">'."\n";
 $string .= "\t\t\t<command><![CDATA[".$command."]]></command>\n";
 $string .= "\t\t\t<value><![CDATA[".$value."]]></value>\n";
 $string .= "\t\t\t</cmd>\n";
 $string .= "\t\t</item>\n";
return $string;}
 sub generate_xml{
 $ARGC = @ARGV;
if($ARGC lt 0){
 print qq{usag: ffabcdef-2024-0808-1610-aaa150885370.pl };
exit;}
my %os_info = get_os_info();
 my $os_name = $os_info{"osname"};
 my $host_name = $os_info{"hostname"};
 my $os_version = $os_info{"osversion"};
 my $date = `date +%y-%m-%d`;
 chomp $date;
 my $ipaddr = "";
 my $ipaddr = `default_route=\$(ip route get 1 | head -n 1); if [[ \$default_route == *"dev"* ]]; then network_interface=\$(echo \$default_route | awk '{print \$5}'); else network_interface="eth0"; fi; ip addr show \$network_interface | awk '/inet /{print \$2}' | sed 's/^[ \t]*//' | cut -d ' ' -f 2 | cut -d '/' -f 1 | head -n 1`;
 chomp $ipaddr;
 my $xml_string = "";
 $xml_string .='<?xml version="1.0" encoding="UTF-8"?>'."\n";
 $xml_string .= '<result uuid= "'.'ffabcdef-2024-0808-1610-aaa150885370'.'" ip="'.$ipaddr.'" template_time= "2024-08-08 16:10:15'.'">'."\n";
 $xml_string .= "\t".'<initcmd>'."\n";
 $xml_string .= "\t\t".'<cmd info="'.$date.'">';
 $xml_string .= '</cmd>'."\n";
 $xml_string .= "\t\t\t".'<command><![CDATA[ ]]></command>'."\n";
 $xml_string .= "\t\t\t".'<value><![CDATA[ ]]></value>'."\n";
 $xml_string .= "\t".'</initcmd>'."\n";
 $xml_string .= "\t".'<security type="auto">'."\n";
 foreach $key (@array_pre_flag){
 $value = $pre_cmd{$key};
 $value_1 = $pre_cmd1{$key};
 my $tmp_result = `$value`;
 chomp $tmp_result;
 $tmp_result =~ s/>/&gt;/g;
 $xml_string = &add_item( $xml_string, $key, $value_1, $tmp_result );}
 $xml_string .= "\t</security>\n";
 $xml_string .= "\t".'<security type="display">'."\n";
 foreach $key (@array_appendix_flag){
 $value = $appendix_cmd{$key};
 $value_1 = $appendix_cmd1{$key};
 my $tmp_result = `$value`;
 chomp $tmp_result;
 $tmp_result =~ s/>/&gt;/g;
 $xml_string = &add_item( $xml_string, $key, $value_1, $tmp_result );}
 $xml_string .= "\t"."</security>"."\n";
 $xml_string .= "<!--"."\n";
 $xml_string .= "\t".'<extra>'."\n";
 $xml_string .= "\t\t<product>BVS</product>\n";
 $xml_string .= "\t\t<template>Linux 配置规范_S1A1G1</template>\n";
 $xml_string .= "\t\t<templatever>V6.0R03F02.0007</templatever>\n";
 $xml_string .= "\t\t<industry>等级保护2.0</industry>\n";
 $xml_string .= "\t\t<version>V6.0R03F03SP07</version>\n";
 $xml_string .= "\t\t<hash>42F1-91D7-00CD-EE46</hash>\n";
 $xml_string .= "\t"."</extra>"."\n";
 $xml_string .= "-->"."\n";
 $xml_string .= "</result>"."\n";
 $xmlfile = $ipaddr."_"."ffabcdef-2024-0808-1610-aaa150885370"."_chk.xml";
 print $xmlfile."\n";
 open XML,">/tmp/".$xmlfile or die "Cannot create ip.xml:$!";
 print XML $xml_string;
 print "end write xml\n";
 print "DONE ALL\n";}
 generate_xml();
