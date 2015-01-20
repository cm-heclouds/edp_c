# edp_c

文件说明

    Common.h是公共定义部分

    cJSON.c 和 cJSON.h 是json库

    EdpKit.c 和 EdpKit.h 是edp协议封装

    Main.c 是demo程序 包括网络通信部分和接收发送edp包部分（包含了目前edp支持的全部协议）。
    例子包含发送心跳，以及设备与设备之间互发消息等等。
    通过Makefile_25267和Makefile_45523 可以代码分别编译成25267.exe和45523.exe。
    25267.exe的源设备是25267，目标设备是45523，45523.exe的源设备是45523，目标设备是25267。

使用说明
    
    将Common.h, cJSON.h, cJSON.c, EdpKit.h, EdpKit.c加入工程编译即可。
