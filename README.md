# edp_c

文件说明

    Common.h是公共定义部分

    cJSON.c 和 cJSON.h 是json库

    EdpKit.c 和 EdpKit.h 是edp协议封装，EdpKit.h有关于全部接口的注释

    Main.c 是demo程序 包括网络通信部分，它仅仅是一个使用EdpKit的例子。客户程序应该写自己的通信模块，把Common.h, cJSON.h, cJSON.c, EdpKit.h, EdpKit.c加入工程，直接调用EdpKit的函数。
    
    Openssl.c 和 Openssl.h 是用openssl库进行加密，如果需要加密功能且系统内已经安装openssl，在Makefile中取消以下两行注释
    #CFLAGS+=-D_ENCRYPT -lcrypto
    #CLIENT_OBJ += Openssl.o
