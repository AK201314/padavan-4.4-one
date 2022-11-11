#!/bin/bash
# copyright by hiboy
# 630281661 03/13/2022

action="$1"
http_port="80,8080,3128,8081,9080"
adbyby_process=$(pidof adbyby | awk '{ print $1 }')
wifidog_enable=$(nvram get wifidog_enable)
wifidog_Daemon=$(nvram get wifidog_Daemon)
wifidog_Hostname=$(nvram get wifidog_Hostname)
wifidog_HTTPPort=$(nvram get wifidog_HTTPPort)
wifidog_Path=$(nvram get wifidog_Path)
wifidog_id=$(nvram get wifidog_id)
wifidog_lanif=$(nvram get wifidog_lanif)
wifidog_wanif=$(nvram get wifidog_wanif)
wifidog_Port=$(nvram get wifidog_Port)
wifidog_Interval=$(nvram get wifidog_Interval)
wifidog_Timeout=$(nvram get wifidog_Timeout)
wifidog_MaxConn=$(nvram get wifidog_MaxConn)
wifidog_MACList=$(nvram get wifidog_MACList)
wifidog_ADBYBY=$(nvram get wifidog_ADBYBY)
wifidog_Log=$(nvram get wifidog_Log)
wifidog_Log_Level=$(nvram get wifidog_Log_Level)

storage_Path="/etc/storage"
wifidog_Bin="/usr/bin/wifidog"
wifidog_stop_Bin="/usr/bin/wdctl"
wifidog_Conf="$storage_Path/wifidog.conf"
TMPFILE="/tmp/wifidog_client.save"

#认证服务器
[ -z "$wifidog_HTTPPort" ] && wifidog_HTTPPort="80" && nvram set wifidog_HTTPPort="$wifidog_HTTPPort"
[ -z "$wifidog_Path" ] && wifidog_Path="/" && nvram set wifidog_Path="$wifidog_Path"

#高级设置
[ -z "$wifidog_id" ] && wifidog_id=$(/sbin/ifconfig br0  | sed -n '/HWaddr/ s/^.*HWaddr */HWADDR=/pg'  | awk -F"=" '{print $2}' |sed -n 's/://pg'| awk -F" " '{print $1}')  && nvram set wifidog_id="$wifidog_id"
[ -z "$wifidog_lanif" ] && wifidog_lanif="br0" && nvram set wifidog_lanif="$wifidog_lanif"
[ -z "$wifidog_wanif" ] && wifidog_wanif=$(nvram get wan0_ifname_t) && nvram set wifidog_wanif="$wifidog_wanif"
[ -z "$wifidog_Port" ] && wifidog_Port="2060" && nvram set wifidog_Port="$wifidog_Port"
[ -z "$wifidog_Interval" ] && wifidog_Interval="60" && nvram set wifidog_Interval="$wifidog_Interval"
[ -z "$wifidog_Timeout" ] && wifidog_Timeout="5" && nvram set wifidog_Timeout="$wifidog_Timeout"
[ -z "$wifidog_MaxConn" ] && wifidog_MaxConn="30" && nvram set wifidog_MaxConn="$wifidog_MaxConn"
[ -z "$wifidog_MACList" ] && wifidog_MACList="00:00:DE:AD:BE:AF" && nvram set wifidog_MACList="$wifidog_MACList"

if [ "$wifidog_ADBYBY" = 1 ] ; then
    adbyby_compatible=2
    [ -s /tmp/adbyby.save ] && adbyby_compatible=1
else
    adbyby_compatible=0
fi
if [ "$wifidog_Log" = 1 ] ; then
    case $wifidog_Log_Level in
        7)
            wifidog_Log_Level="LOG_DEBUG"
            ;;
        6)
            wifidog_Log_Level="LOG_INFO"
            ;;
        5)
            wifidog_Log_Level="LOG_NOTICE"
            ;;
        4)
            wifidog_Log_Level="LOG_WARNING"
            ;;
        3)
            wifidog_Log_Level="LOG_ERR"
            ;;
    esac
else
    wifidog_Log_Level=0
fi
Get_wifidog_conf () {
    # 将页面设置赋给WiFiDog官方的配置参数
    [ -s "$wifidog_Conf" ] && rm -f "$wifidog_Conf"
    cat > "$wifidog_Conf" <<-FWD
#WiFiDog 配置文件

#网关ID
GatewayID $wifidog_id

#内部网卡
GatewayInterface $wifidog_lanif

#外部网卡
ExternalInterface $wifidog_wanif 

#认证服务器
AuthServer {
Hostname $wifidog_Hostname
HTTPPort $wifidog_HTTPPort
Path $wifidog_Path
}

#守护进程
Daemon $wifidog_Daemon

#检查DNS状态(Check DNS health by querying IPs of these hosts)
PopularServers baidu.com,qq.com

#运行状态
HtmlMessageFile /www/wifidog-msg.html

#监听端口
GatewayPort $wifidog_Port

#心跳间隔时间
CheckInterval $wifidog_Interval

#心跳间隔次数
ClientTimeout $wifidog_Timeout

#HTTP最大连接数
HTTPDMaxConn $wifidog_MaxConn

#信任的MAC地址,加入信任列表将不用登录可访问
TrustedMACList $wifidog_MACList

#Adbyby兼容
AdbybyCompatible $adbyby_compatible

#日志等级
DebugLevel $wifidog_Log_Level

# 全局防火墙设置（适用于“封锁用户规则集”外的其他规则集）
# 53为dns解析端口，67为dhcp分配ip端口
FirewallRuleSet global {
}

# 新验证用户规则集（用于新用户验证其帐户时）
FirewallRuleSet validating-users {
    FirewallRule allow to 0.0.0.0/0
}

# 已认证用户规则集
FirewallRuleSet known-users {
    FirewallRule allow to 0.0.0.0/0
}

# 未认证用户规则集
FirewallRuleSet unknown-users {
    FirewallRule allow udp port 53
    FirewallRule allow tcp port 53
    FirewallRule allow udp port 67
    FirewallRule allow tcp port 67
}

# 认证服务器未连接时规则集
FirewallRuleSet auth-is-down {
    FirewallRule allow to 0.0.0.0/0
}


# 封锁用户规则集
FirewallRuleSet locked-users {
    FirewallRule block to 0.0.0.0/0
}

FWD
}

getIP() {
    _mac="$1"
    s=$(cat /proc/net/arp | grep -F "$_mac" | grep -F '0x2' | grep -F 'br-lan'| awk '{print $1}')
    echo "$s"
}

passAuthed() {
    HID=$(nvram get wifidog_id)
    if [ "$HID" = "" ]; then
        return
    fi
    
    AS_HOSTNAME_X=$(nvram get wifidog_Hostname)
    if [ "$AS_HOSTNAME_X" = "" ]; then
        return
    fi
    
    URL="http://$AS_HOSTNAME_X/as/s/getauthed/?&gw_id=$HID"
    rm -f "$TMPFILE" 2>/dev/null
    curl -m 10 -o "$TMPFILE" "$URL"
    
    cat "$TMPFILE" | while read LINE; do
        token=$(echo "$LINE" | cut -d ' ' -f 1)
        mac=$(echo "$LINE" | cut -d ' ' -f 2)
        ip=$(getIP "$mac")
        
        if [ "$ip" = "" ]; then
            ip=$(echo "$LINE" | cut -d ' ' -f 3)
        fi
        
        if [ "$ip" != "" ]; then
            wdctl auth "$mac" "$ip" "$token"
            logger -t "【WiFiDog】" "已认证设备：$mac $ip $token"
        fi
    done
    
    rm -f "$TMPFILE" 2>/dev/null    
}


Bin_start() {
    # 【】
    if [ "$wifidog_Log" = 1 ] ; then
        "$wifidog_Bin" -c "$wifidog_Conf" > /var/log/wifidog.log 2>&1 &
    else
        "$wifidog_Bin" -c "$wifidog_Conf" &
    fi
}

Start_wifidog () {
    logger -t "【WifiDog】" "生成配置文件…"
    Get_wifidog_conf
    logger -t "【WiFiDog】" "启动程序进程…"
    Bin_start
    sleep 5
    wifidog_process=$(pidof wifidog | awk '{ print $1 }')
    if [ "$wifidog_process"x = x ] ; then
        logger -t "【WiFiDog】" "wifidog 未成功运行，请检查设置"
        Stop_wifidog
    else
        [ "$adbyby_process"x != x ] && iptables -t nat -D PREROUTING -p tcp -m multiport --dport "$http_port" -j ADBYBY 2>/dev/null && iptables-save | grep -E "ADBYBY|^\*|^COMMIT" | sed -e "/WD/d;s/^-A \(OUTPUT\|PREROUTING\)/-I \1 1/" > /tmp/adbyby.save
        iptables-save | grep -E "WD_|^\*|^COMMIT" | sed -e "/ADBYBY/d;s/^-A \(FORWARD\|OUTPUT\|PREROUTING\)/-I \1 1/" > /tmp/wifidog.save
        iptables-save | grep -E "ADBYBY|^\*|^COMMIT" | sed -e "/:ADBYBY/d;/-A ADBYBY/d;/PREROUTING/d;s/^-A /-I /" > /tmp/adbyby_wifidog.save
        logger -t "【WiFiDog】" "wifidog 已启动"
        passAuthed
    fi
}

Stop_wifidog () {
    logger -t "【WiFiDog】" "结束程序进程…"
    "$wifidog_stop_Bin" stop
    logger -t "【WiFiDog】" "重置防火墙…"
    rm -f /tmp/wifidog.save
    rm -f /tmp/adbyby_wifidog.save
    rm -f /var/log/wifidog.log
    rm -rf /tmp/wifidog.sock
    rm -rf /tmp/wdctl.sock
    sleep 1
    if [ "$wifidog_enable" = 0 ] && [ "$adbyby_process"x != x ] ; then
        iptables -t nat -D PREROUTING -p tcp -m multiport --dport "$http_port" -j ADBYBY >/dev/null 2>&1
        iptables -t nat -I PREROUTING -p tcp -m multiport --dport "$http_port" -j ADBYBY >/dev/null 2>&1
        iptables-save | grep -E "ADBYBY|^\*|^COMMIT" | sed -e "s/^-A \(OUTPUT\|PREROUTING\)/-I \1 1/" > /tmp/adbyby.save
    fi
    killall wifidog wdctl >/dev/null 2>&1
    killall -9 wifidog wdctl >/dev/null 2>&1
    logger -t "【WiFiDog】" "wifidog 已关闭"
}

case $action in
    start)
        Start_wifidog
        ;;
    stop)
        Stop_wifidog
        ;;
    restart|reset)
        wifidog_process=$(pidof wifidog | awk '{print $1}')
        if [ "$wifidog_process"x = x ] ; then
            Bin_start
            echo "Wifidog not running! Started."
            sleep 5
            passAuthed
            exit 0
        else
            kill -9 "$wifidog_process"
            Bin_start
            echo "All Wifidogs killed and restarted"
            sleep 5
            passAuthed
            exit 0
        fi
        ;;
    *)
        echo "check"
        ;;
esac

