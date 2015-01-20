#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#include "EdpKit.h"

/*---------------------------------------------------------------------------*/
/* Error Code                                                                */
/*---------------------------------------------------------------------------*/
#define ERR_CREATE_SOCKET   -1 
#define ERR_HOSTBYNAME      -2 
#define ERR_CONNECT         -3 
#define ERR_SEND            -4
#define ERR_TIMEOUT         -5
#define ERR_RECV            -6
/*---------------------------------------------------------------------------*/
/* Socket Function                                                           */
/*---------------------------------------------------------------------------*/
#ifndef htonll
#ifdef _BIG_ENDIAN
#define htonll(x)   (x)
#define ntohll(x)   (x)
#else
#define htonll(x)   ((((uint64)htonl(x)) << 32) + htonl(x >> 32))
#define ntohll(x)   ((((uint64)ntohl(x)) << 32) + ntohl(x >> 32))
#endif
#endif

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

int32 Open(const uint8 *addr, int16 portno)
{
    int32 sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    /* create socket */
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

int32 DoSend(int32 sockfd, const char* buffer, uint32 len)
{
    int32 total  = 0;
    int32 n = 0;
    while (len != total)
    {
        n = Send(sockfd,buffer + total,len - total,MSG_NOSIGNAL);
        if (n <= 0)
        {
            fprintf(stderr, "ERROR writing to socket\n");
            return n;
        }
        total += n;
    }
    return total;
}

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

#ifdef _DEBUG
    printf("[%s] recv thread start ...\n", __func__);
#endif

    while (error == 0)
    {
        n = Recv(sockfd, buffer, 1024, MSG_NOSIGNAL);
        if (n <= 0)
            break;
        printf("recv from server, bytes: %d\n", n);
        WriteBytes(recv_buf, buffer, n);
        while (1)
        {
            if ((pkg = GetEdpPacket(recv_buf)) == 0)
            {
                printf("need more bytes...\n");
                break;
            }
            mtype = EdpPacketType(pkg);
            switch(mtype)
            {
                case CONNRESP:
                    rtn = UnpackConnectResp(pkg);
                    printf("recv connect resp, rtn: %d\n", rtn);
                    break;
                case PUSHDATA:
                    UnpackPushdata(pkg, &src_devid, &push_data, &push_datalen);
                    printf("recv push data, src_devid: %s, push_data: %s, len: %d\n", 
                            src_devid, push_data, push_datalen);
                    free(src_devid);
                    free(push_data);
                    break;
                case SAVEDATA:
                    if (UnpackSavedata(pkg, &src_devid, &jsonorbin) == 0)
                    {
                        if (jsonorbin == 0x01) 
                        {/* json */
                            UnpackSavedataJson(pkg, &save_json);
                            save_json_str=cJSON_Print(save_json);
                            printf("recv save data json, src_devid: %s, json: %s\n", 
                                src_devid, save_json_str);
                            free(save_json_str);
                            cJSON_Delete(save_json);
                        }
                        else if (jsonorbin == 0x02)
                        {/* bin */
                            UnpackSavedataBin(pkg, &desc_json, (uint8**)&save_bin, &save_binlen);
                            desc_json_str=cJSON_Print(desc_json);
                            printf("recv save data bin, src_devid: %s, desc json: %s, bin: %s, binlen: %d\n", 
                                    src_devid, desc_json_str, save_bin, save_binlen);
                            free(desc_json_str);
                            cJSON_Delete(desc_json);
                            free(save_bin);
                        }
                        free(src_devid);
                    }
                    break;
                case PINGRESP:
                    UnpackPingResp(pkg); 
                    printf("recv ping resp\n");
                    break;
                default:
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

int main(int argc, char *argv[])
{
    int sockfd, n, ret;
    pthread_t id_1;
    EdpPacket* send_pkg;
    char c;
    char push_data[] = {'a','b','c'};
	char text1[]="{\"name\": \"Jack\"}";	
	char text2[]="{\"ds_id\": \"1\"}";	
    cJSON *save_json, *desc_json;
    char save_bin[] = {'c', 'b', 'a'};

    if (argc < 3) {
        fprintf(stderr,"usage %s hostname port\n", argv[0]);
        exit(0);
    }

    /* create a socket and connect to server */
    sockfd = Open(argv[1], atoi(argv[2]));
    if (sockfd < 0) 
        exit(0);
    
    /* create a recv thread */
    ret=pthread_create(&id_1,NULL,(void*)recv_thread_func, &sockfd);  

    /* connect to server */
#ifdef _DEV1
    /* user: 433223 dev: 25267 */
    send_pkg = PacketConnect1("25267", "Bs04OCJioNgpmvjRphRak15j7Z8=");
    // send_pkg = PacketConnect2("433223", "{ \"SYS\" : \"0DEiuApATHgLurKNEl6vY4bLwbQ=\" }");
#else
    /* user: 433223 dev: 45523 */
    send_pkg = PacketConnect1("45523", "Bs04OCJioNgpmvjRphRak15j7Z8=");
    // send_pkg = PacketConnect2("433223", "{ \"13982031959\" : \"888888\" }");
#endif

    printf("send connect to server, bytes: %d\n", send_pkg->_write_pos);
    ret=DoSend(sockfd, send_pkg->_data, send_pkg->_write_pos);
    DeleteBuffer(&send_pkg);

    sleep(1);
    printf("\n[0] send ping\n[1] send push data\n[2] send save json\n[3] send save bin\n");

    while (1)
    {
        c = getchar();
        if (c == '0')
        {/* send ping */
            send_pkg = PacketPing(); 
            printf("send ping to server, bytes: %d\n", send_pkg->_write_pos);
            DoSend(sockfd, send_pkg->_data, send_pkg->_write_pos);
            DeleteBuffer(&send_pkg);
        }
        else if (c == '1')
        {/* push data */
#ifdef _DEV1
            send_pkg = PacketPushdata("45523", push_data, sizeof(push_data)); 
#else
            send_pkg = PacketPushdata("25267", push_data, sizeof(push_data)); 
#endif
            printf("send pushdata to server, bytes: %d\n", send_pkg->_write_pos);
            DoSend(sockfd, send_pkg->_data, send_pkg->_write_pos);
            DeleteBuffer(&send_pkg);
        }
        else if (c == '2')
        {/* save json data */
            save_json=cJSON_Parse(text1);
#ifdef _DEV1
            send_pkg = PacketSavedataJson("45523", save_json); 
#else
            send_pkg = PacketSavedataJson("25267", save_json); 
#endif
            cJSON_Delete(save_json);
            printf("send savedata json to server, bytes: %d\n", send_pkg->_write_pos);
            DoSend(sockfd, send_pkg->_data, send_pkg->_write_pos);
            DeleteBuffer(&send_pkg);
        }
        else if (c == '3')
        {/* save bin data */
            desc_json=cJSON_Parse(text2);
#ifdef _DEV1
            send_pkg = PacketSavedataBin("45523", desc_json, save_bin, sizeof(save_bin)); 
#else
            send_pkg = PacketSavedataBin("25267", desc_json, save_bin, sizeof(save_bin)); 
#endif
            cJSON_Delete(desc_json);
            printf("send savedata bin to server, bytes: %d\n", send_pkg->_write_pos);
            DoSend(sockfd, send_pkg->_data, send_pkg->_write_pos);
            DeleteBuffer(&send_pkg);
        }
    }
    /* close socket */
    Close(sockfd);

    pthread_join(id_1,NULL);
    return 0;
}
