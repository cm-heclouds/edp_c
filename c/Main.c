#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <getopt.h>
#include <libgen.h>
#include "EdpKit.h"
#ifdef _ENCRYPT
#include "Openssl.h"
#endif
/*
 * [说明]
 * Main.c 是为了测试EdpKit而写的, 也是给客户展示如何使用EdpKit
 * Main.c 使用的是c & linux socket
 *
 * 测试包含了：
 *      打包EDP包并发送：连接设备云请求, 心跳请求, 转发数据, 存储json数据, 存储bin数据
 *      接收并解析EDP包：连接设备云请求响应, 心跳请求响应, 转发数据, 存储json数据, 存储bin数据
 *
 * [注意]
 * Main.c不属于我们EDP SDK的一部分, 客户程序应该根据自己的系统写类似Main.c的代码
 * 客户程序应该只包含Common.h, cJSON.* 和 EdpKit.*, 而不应该包含Main.c
 * 
 * 加解密是利用openssl库实现的，如果有openssl库，则可以直接利用Openssl.*文件中提供
 * 的函数实现加解密。否则应该自己实现Openssl.h中的函数。
 * 如果需要加密功能，请参考Makefile中的说明，取消相应行的注释。
 */

/*----------------------------错误码-----------------------------------------*/
#define ERR_CREATE_SOCKET   -1 
#define ERR_HOSTBYNAME      -2 
#define ERR_CONNECT         -3 
#define ERR_SEND            -4
#define ERR_TIMEOUT         -5
#define ERR_RECV            -6
/*---------------统一linux和windows上的Socket api----------------------------*/
#ifndef htonll
#ifdef _BIG_ENDIAN
#define htonll(x)   (x)
#define ntohll(x)   (x)
#else
#define htonll(x)   ((((uint64)htonl(x)) << 32) + htonl(x >> 32))
#define ntohll(x)   ((((uint64)ntohl(x)) << 32) + ntohl(x >> 32))
#endif
#endif
/* linux程序需要定义_LINUX */
#ifdef _LINUX
#define Socket(a,b,c)          socket(a,b,c)
#define Connect(a,b,c)         connect(a,b,c)
#define Close(a)               close(a)
#define Read(a,b,c)            read(a,b,c)
#define Recv(a,b,c,d)          recv(a, (void *)b, c, d)
#define Select(a,b,c,d,e)      select(a,b,c,d,e)
#define Send(a,b,c,d)          send(a, (const int8 *)b, c, d)
#define Write(a,b,c)           write(a,b,c)
#define GetSockopt(a,b,c,d,e)  getsockopt((int)a,(int)b,(int)c,(void *)d,(socklen_t *)e)
#define SetSockopt(a,b,c,d,e)  setsockopt((int)a,(int)b,(int)c,(const void *)d,(int)e)
#define GetHostByName(a)       gethostbyname((const char *)a)
#endif

static int g_is_encrypt = 0;

/*
 * buffer按十六进制输出
 */
void hexdump(const unsigned char *buf, uint32 num)
{
    uint32 i = 0;
    for (; i < num; i++) 
    {
        printf("%02X ", buf[i]);
        if ((i+1)%8 == 0) 
            printf("\n");
    }
    printf("\n");
}
/* 
 * 函数名:  Open
 * 功能:    创建socket套接字并连接服务端
 * 参数:    addr    ip地址
 *          protno  端口号
 * 说明:    这里只是给出一个创建socket连接服务端的例子, 其他方式请查询相关socket api
 * 相关socket api:  
 *          socket, gethostbyname, connect
 * 返回值:  类型 (int32)
 *          <=0     创建socket失败
 *          >0      socket描述符
 */
int32 Open(const uint8 *addr, int16 portno)
{
    int32 sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    /* 创建socket套接字 */
    sockfd = Socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "ERROR opening socket\n");
        return ERR_CREATE_SOCKET; 
    }
    server = GetHostByName(addr);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        return ERR_HOSTBYNAME;
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
            (char *)&serv_addr.sin_addr.s_addr,
            server->h_length);
    serv_addr.sin_port = htons(portno);
    /* 客户端 建立与TCP服务器的连接 */
    if (Connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
    {
        fprintf(stderr, "ERROR connecting\n");
        return ERR_CONNECT;
    }
#ifdef _DEBUG
    printf("[%s] connect to server %s:%d succ!...\n", __func__, addr, portno);
#endif
    return sockfd;
}
/* 
 * 函数名:  DoSend
 * 功能:    将buffer中的len字节内容写入(发送)socket描述符sockfd, 成功时返回写的(发送的)字节数.
 * 参数:    sockfd  socket描述符 
 *          buffer  需发送的字节
 *          len     需发送的长度
 * 说明:    这里只是给出了一个发送数据的例子, 其他方式请查询相关socket api
 *          一般来说, 发送都需要循环发送, 是因为需要发送的字节数 > socket的写缓存区时, 一次send是发送不完的.
 * 相关socket api:  
 *          send
 * 返回值:  类型 (int32)
 *          <=0     发送失败
 *          >0      成功发送的字节数
 */
int32 DoSend(int32 sockfd, const char* buffer, uint32 len)
{
    int32 total  = 0;
    int32 n = 0;
    while (len != total)
    {
        /* 试着发送len - total个字节的数据 */
        n = Send(sockfd,buffer + total,len - total,MSG_NOSIGNAL);
        if (n <= 0)
        {
            fprintf(stderr, "ERROR writing to socket\n");
            return n;
        }
        /* 成功发送了n个字节的数据 */
        total += n;
    }
    /* wululu test print send bytes */
    hexdump(buffer, len);
    return total;
}
/* 
 * 函数名:  recv_thread_func
 * 功能:    接收线程函数
 * 参数:    arg     socket描述符
 * 说明:    这里只是给出了一个从socket接收数据的例子, 其他方式请查询相关socket api
 *          一般来说, 接收都需要循环接收, 是因为需要接收的字节数 > socket的读缓存区时, 一次recv是接收不完的.
 * 相关socket api:  
 *          recv
 * 返回值:  无
 */
void recv_thread_func(void* arg)
{
    int sockfd = *(int*)arg;
    int error = 0;
    int n, rtn;
    uint8 mtype, jsonorbin;
    char buffer[1024];
    RecvBuffer* recv_buf = NewBuffer();
    EdpPacket* pkg;
    
    char* src_devid;
    char* push_data;
    uint32 push_datalen;

    cJSON* save_json;
    char* save_json_str;

    cJSON* desc_json;
    char* desc_json_str;
    char* save_bin; 
    uint32 save_binlen;
    char* json_ack;

    char* cmdid;
    uint16 cmdid_len;
    char*  cmd_req;
    uint32 cmd_req_len;
    EdpPacket* send_pkg;
    char* ds_id;
    double dValue = 0;
    int iValue = 0;
    char* cValue = NULL;

#ifdef _DEBUG
    printf("[%s] recv thread start ...\n", __func__);
#endif

    while (error == 0)
    {
        /* 试着接收1024个字节的数据 */
        n = Recv(sockfd, buffer, 1024, MSG_NOSIGNAL);
        if (n <= 0)
            break;
        printf("recv from server, bytes: %d\n", n);
        /* wululu test print send bytes */
        hexdump(buffer, n);
        /* 成功接收了n个字节的数据 */
        WriteBytes(recv_buf, buffer, n);
        while (1)
        {
            /* 获取一个完成的EDP包 */
            if ((pkg = GetEdpPacket(recv_buf)) == 0)
            {
                printf("need more bytes...\n");
                break;
            }
            /* 获取这个EDP包的消息类型 */
            mtype = EdpPacketType(pkg);
#ifdef _ENCRYPT
	    if (mtype != ENCRYPTRESP){
		if (g_is_encrypt){
		    SymmDecrypt(pkg);
		}
	    }
#endif
            /* 根据这个EDP包的消息类型, 分别做EDP包解析 */
            switch(mtype)
            {
#ifdef _ENCRYPT
	    case ENCRYPTRESP:
		UnpackEncryptResp(pkg);
		break;
#endif
                case CONNRESP:
                    /* 解析EDP包 - 连接响应 */
                    rtn = UnpackConnectResp(pkg);
                    printf("recv connect resp, rtn: %d\n", rtn);
                    break;
                case PUSHDATA:
                    /* 解析EDP包 - 数据转发 */
                    UnpackPushdata(pkg, &src_devid, &push_data, &push_datalen);
                    printf("recv push data, src_devid: %s, push_data: %s, len: %d\n", 
                            src_devid, push_data, push_datalen);
                    free(src_devid);
                    free(push_data);
                    break;
	    case SAVEDATA:
                    /* 解析EDP包 - 数据存储 */
                    if (UnpackSavedata(pkg, &src_devid, &jsonorbin) == 0)
                    {
                        if (jsonorbin == kTypeFullJson 
			    || jsonorbin == kTypeSimpleJsonWithoutTime
			    || jsonorbin == kTypeSimpleJsonWithTime) 
			    {
				printf("json type is %d\n", jsonorbin);
				/* 解析EDP包 - json数据存储 */ 
                            /* UnpackSavedataJson(pkg, &save_json); */
                            /* save_json_str=cJSON_Print(save_json); */
                            /* printf("recv save data json, src_devid: %s, json: %s\n", */
                            /*     src_devid, save_json_str); */
                            /* free(save_json_str); */
                            /* cJSON_Delete(save_json); */

				/* UnpackSavedataInt(jsonorbin, pkg, &ds_id, &iValue); */
				/* printf("ds_id = %s\nvalue= %d\n", ds_id, iValue); */

				UnpackSavedataDouble(jsonorbin, pkg, &ds_id, &dValue);
				printf("ds_id = %s\nvalue = %f\n", ds_id, dValue);

				/* UnpackSavedataString(jsonorbin, pkg, &ds_id, &cValue); */
				/* printf("ds_id = %s\nvalue = %s\n", ds_id, cValue); */
				/* free(cValue); */

				free(ds_id);
				
                        }
                        else if (jsonorbin == kTypeBin)
                        {/* 解析EDP包 - bin数据存储 */
                            UnpackSavedataBin(pkg, &desc_json, (uint8**)&save_bin, &save_binlen);
                            desc_json_str=cJSON_Print(desc_json);
                            printf("recv save data bin, src_devid: %s, desc json: %s, bin: %s, binlen: %d\n", 
                                    src_devid, desc_json_str, save_bin, save_binlen);
                            free(desc_json_str);
                            cJSON_Delete(desc_json);
                            free(save_bin);
                        }
			else if (jsonorbin == kTypeString){
			    char* simple_str = NULL;
			    UnpackSavedataSimpleString(pkg, &simple_str);
			    
			    printf("%s\n", simple_str);
			    free(simple_str);
			}
                        free(src_devid);
                    }else{
			printf("error\n");
		    }
                    break;
	    case SAVEACK:
		json_ack = NULL;
		UnpackSavedataAck(pkg, &json_ack);
		printf("save json ack = %s\n", json_ack);
		free(json_ack);
		break;
	    case CMDREQ:
		if (UnpackCmdReq(pkg, &cmdid, &cmdid_len, 
				 &cmd_req, &cmd_req_len) == 0){
		    /* 
		     * 用户按照自己的需求处理并返回，响应消息体可以为空，此处假设返回2个字符"ok"。
		     * 处理完后需要释放
		     */
		    char cmd_resp[] = "ok";
		    unsigned cmd_resp_len = strlen(cmd_resp);
		    send_pkg = PacketCmdResp(cmdid, cmdid_len,
					     cmd_resp, cmd_resp_len);
#ifdef _ENCRYPT
		    if (g_is_encrypt){
			SymmEncrypt(send_pkg);
		    }
#endif
		    DoSend(sockfd, send_pkg->_data, send_pkg->_write_pos);
		    DeleteBuffer(&send_pkg);
		    
		    free(cmdid);
		    free(cmd_req);
		}
		break;
                case PINGRESP:
                    /* 解析EDP包 - 心跳响应 */
                    UnpackPingResp(pkg); 
                    printf("recv ping resp\n");
                    break;
                default:
                    /* 未知消息类型 */
                    error = 1;
                    printf("recv failed...\n");
                    break;
            }
            DeleteBuffer(&pkg);
        }
    }
    DeleteBuffer(&recv_buf);

#ifdef _DEBUG
    printf("[%s] recv thread end ...\n", __func__);
#endif
}
void usage(char* name){
    printf("Usage:%s [options]\n", basename(name));
    printf("-h List help document\n");
    printf("-i The ip of the edpacc\n");
    printf("-p The port of the edpacc\n");
    printf("-s Assign the dev_id of the source\n");
    printf("-d Assign the dev_id of the destination\n");
    printf("-a Assign the API key of the source\n");
    printf("-l Assign the name of the datastream for test 'save json data'\n" );
    printf("-v Assign the value of the datastream for test 'save json data'\n");
    printf("-E Encrypt\n");
    exit(0);
}

int main(int argc, char *argv[])
{
    char opt;
    int sockfd, n, ret;
    pthread_t id_1;
    EdpPacket* send_pkg;
    char c;
    char push_data[] = {'a','b','c'};
	char text1[]="{\"name\": \"Jack\"}";
	 /* cJSON中文只支持unicode编码   */	
	char text2[]="{\"ds_id\": \"temperature\"}";	
    cJSON *save_json, *desc_json;
    char save_bin[] = {'c', 'b', 'a'};

    char* ip = NULL;
    char* port = NULL;
    char* src_dev = NULL;
    char* dst_dev = NULL;
    char* src_api_key = NULL;
    char* ds_for_send = NULL;
    double value_for_send = 0.0;
    char send_str[] = "temperature,2015-03-22 22:31:12,22.5;humidity,35%;pm2.5,89;1001";
    SaveDataType data_type;

    while ((opt = getopt(argc, argv, "hi:p:s:d:a:l:v:E")) != -1) {
	switch (opt){
	case 'i':
	    ip = optarg;
	    break;

	case 'p':
	    port = optarg;
	    break;

	case 's':
	    src_dev = optarg;
	    break;

	case 'd':
	    dst_dev = optarg;
	    break;
	    
	case 'a':
	    src_api_key = optarg;
	    break;

	case 'l':
	    ds_for_send = optarg;
	    break;

	case 'v':
	    value_for_send = atof(optarg);
	    break;

	case 'E':
#ifndef _ENCRYPT
	    printf("Sorry the option 'E' is not supported right now\n");
	    printf("Please check your compile flags, \n");
	    printf("uncomment this line 'CFLAGS+=-D_ENCRYPT -lcrypto'\n");
	    printf("and this line 'CLIENT_OBJ += Openssl.o'\n");
	    printf("and try it again\n");
	    exit(0);
#endif
	    g_is_encrypt = 1;
	    break;

	case 'h': 
	default:
	    usage(argv[0]);
	    return 0;
	}
    }
    
    if (!ip || !port || !src_dev || !dst_dev 
	|| !src_api_key || !ds_for_send){
	usage(argv[0]);
	return 0;
    }

    /* create a socket and connect to server */
    sockfd = Open(ip, atoi(port));
    if (sockfd < 0) 
        exit(0);
    
    /* create a recv thread */
    ret=pthread_create(&id_1,NULL,(void*)recv_thread_func, &sockfd);  

#ifdef _ENCRYPT
    if (g_is_encrypt){
	send_pkg = PacketEncryptReq(kTypeAes);
	/* 向设备云发送加密请求 */
	printf("send encrypt to server, bytes: %d\n", send_pkg->_write_pos);
	ret=DoSend(sockfd, (char*)send_pkg->_data, send_pkg->_write_pos);
	DeleteBuffer(&send_pkg);
	sleep(1);
    }
#endif

    /* connect to server */
    //    send_pkg = PacketConnect1(src_dev, "Bs04OCJioNgpmvjRphRak15j7Z8=");
    send_pkg = PacketConnect1(src_dev, src_api_key);
#ifdef _ENCRYPT
    if (g_is_encrypt){
	SymmEncrypt(send_pkg);
    }
#endif
    // send_pkg = PacketConnect2("433223", "{ \"SYS\" : \"0DEiuApATHgLurKNEl6vY4bLwbQ=\" }");
    // send_pkg = PacketConnect2("433223", "{ \"13982031959\" : \"888888\" }");

    /* 向设备云发送连接请求 */
    printf("send connect to server, bytes: %d\n", send_pkg->_write_pos);
    ret=DoSend(sockfd, send_pkg->_data, send_pkg->_write_pos);
    DeleteBuffer(&send_pkg);

    sleep(1);
    printf("\n[0] send ping\n[1] send push data\n[2] send save json\n[3] send save bin\n");
    printf("[4] send save json simple format without time\n");
    printf("[5] send save json simple format with time\n");
    printf("[6] send simple format (string) \n");

    /* 
     * 说明: 这里只是为了测试EdpKit而写的例子, 客户程序应该根据自己程序的需求写代码
     * 根据标准输入 做不同的处理 
     * 0 发送 心跳请求EDP包
     * 1 发送 转发数据请求EDP包
     * 2 发送 存储json数据EDP包
     * 3 发送 存储bin数据EDP包
     */
    char msg[][50] = {"send ping to server",
		      "send pushdata to server",
		      "send savedata full json to server",
		      "send savedata bin to server",
		      "send savedata simple json without time to server",
		      "send savedata simple json with time to server",
		      "send string split by simicolon"};
		      
    while (1)
    {
        c = getchar();
	switch (c){
	case '0':
	    send_pkg = PacketPing(); 
	    break;

	case '1':
	    send_pkg = PacketPushdata(dst_dev, push_data, sizeof(push_data)); 
	    break;

	case '2':
	case '4':
	case '5':
	    if (c == '2') data_type = kTypeFullJson;
	    if (c == '4') data_type = kTypeSimpleJsonWithoutTime;
	    if (c == '5') data_type = kTypeSimpleJsonWithTime;

	    // send_pkg = PacketSavedataInt(data_type, dst_dev, ds_for_send, 1234, 0, NULL);
	    send_pkg = PacketSavedataDouble(data_type, dst_dev, ds_for_send, value_for_send, 0, NULL);
	    // send_pkg = PacketSavedataString(data_type, dst_dev, ds_for_send, "test12345678", 0, NULL);
	    break;
	    
	case '3':
	    desc_json=cJSON_Parse(text2);
            send_pkg = PacketSavedataBin(dst_dev, desc_json, save_bin, sizeof(save_bin)); 
	    break;

	case '6':
	    send_pkg = PacketSavedataSimpleString(dst_dev, send_str);
	    break;

	default:
	    getchar();	/* 读取回车符，丢弃 */
	    printf("input error, please try again\n");
	    continue;
	}
#ifdef _ENCRYPT
	    if (g_is_encrypt){
		SymmEncrypt(send_pkg);
	    }
#endif
            printf("%s, bytes: %d\n", msg[c-'0'], send_pkg->_write_pos);
            DoSend(sockfd, send_pkg->_data, send_pkg->_write_pos);
            DeleteBuffer(&send_pkg);

	    getchar(); /* 读取回车符，丢弃 */
    }
    /* close socket */
    Close(sockfd);

    pthread_join(id_1,NULL);
    return 0;
}
