#! /bin/bash

# 以下示例展示一个设备连接到ip为192.168.200.218，端口为876的接入机
# 当前设备的id为25267，api_key为Bs04OCJioNgpmvjRphRak15j7Z8=
# 在下面的测试中，它将向设备id为45467的设备发送消息
# 在save data json测试中，测试用的数据流名称为temperature, 值为double类型的1.2

./edp.exe -i 192.168.200.218 -p 876 -s 25267 -a Bs04OCJioNgpmvjRphRak15j7Z8= -d 45523 -l temperature -v 1.2

# 设备通过加密方式与平台通信
# 注意编译时在Makefile中打开以下两项，然后编译才支持加密，需要安装openssl库
#CFLAGS+=-D_ENCRYPT -lcrypto
#CLIENT_OBJ += Openssl.o

#./edp.exe -i 192.168.200.218 -p 876 -s 25267 -a Bs04OCJioNgpmvjRphRak15j7Z8= -d 45523 -l temperature -v 1.2 -E
