#ifndef __EDP_KIT_H__
#define __EDP_KIT_H__

#include "Common.h"
#include "cJSON.h"

/*---------------------------------------------------------------------------*/
/* From pkg_kit.h                                                            */
/*---------------------------------------------------------------------------*/
#define MOSQ_MSB(A)         (uint8)((A & 0xFF00) >> 8)
#define MOSQ_LSB(A)         (uint8)(A & 0x00FF)
#define BUFFER_SIZE         (0x01<<20) 
/*---------------------------------------------------------------------------*/
/* From edp.h                                                                */ 
/*---------------------------------------------------------------------------*/
/* For version 3 of the EDP */
#define PROTOCOL_NAME       "EDP"
#define PROTOCOL_VERSION    1
/* Message types */
#define CONNREQ             0x10
#define CONNRESP            0x20
#define PUSHDATA            0x30
#define SAVEDATA            0x80
#define PINGREQ             0xC0
#define PINGRESP            0xD0
/* connect response code */
#define CONNRESP_ACCEPTED                       0
#define CONNRESP_REFUSED_PROTOCOL_INVALID       1
#define CONNRESP_REFUSED_BAD_DEVID              2
#define CONNRESP_REFUSED_SERVER_UNAVAILABLE     3
#define CONNRESP_REFUSED_BAD_USERID_PASSWORD    4
#define CONNRESP_REFUSED_NOT_AUTHORIZED         5
#define CONNRESP_REFUSED_INVALID_AUTHOR_CODE    6
#define CONNRESP_REFUSED_INVALID_ACTIVATE_CODE  7
#define CONNRESP_REFUSED_HAS_ACTIVATED          8
#define CONNRESP_REFUSED_DUP_AUTHEN             9
/* 4M */
#define EDP_MAX_PAYLOAD     (1<<22)
#define MAX_DEVID_LEN       23
/* datapoint type */
#define DP_TYPE_JSON        1
#define DP_TYPE_BINARY      2
/*---------------------------------------------------------------------------*/
/* ERROR CODE                                                                */ 
/*---------------------------------------------------------------------------*/
#define ERR_UNPACK_CONNRESP_REMAIN              -1000
#define ERR_UNPACK_CONNRESP_FLAG                -1001
#define ERR_UNPACK_CONNRESP_RTN                 -1002
#define ERR_UNPACK_PUSHD_REMAIN                 -1010
#define ERR_UNPACK_PUSHD_DEVID                  -1011
#define ERR_UNPACK_PUSHD_DATA                   -1012
#define ERR_UNPACK_SAVED_REMAIN                 -1020
#define ERR_UNPACK_SAVED_TANSFLAG               -1021
#define ERR_UNPACK_SAVED_DEVID                  -1022
#define ERR_UNPACK_SAVED_DATAFLAG               -1023
#define ERR_UNPACK_SAVED_JSON                   -1024
#define ERR_UNPACK_SAVED_PARSEJSON              -1025
#define ERR_UNPACK_SAVED_BIN_DESC               -1026
#define ERR_UNPACK_SAVED_PARSEDESC              -1027
#define ERR_UNPACK_SAVED_BINLEN                 -1028
#define ERR_UNPACK_SAVED_BINDATA                -1029
#define ERR_UNPACK_PING_REMAIN                  -1030
/*---------------------------------------------------------------------------*/
/* Combine Pkg and Buffer                                                    */ 
/*---------------------------------------------------------------------------*/
typedef struct Buffer
{
    uint8*  _data;
    uint32  _write_pos;
    uint32  _read_pos;
    uint32  _capacity;
}Buffer, SendBuffer, RecvBuffer, EdpPacket;

/*---------------------------------------------------------------------------*/
Buffer* NewBuffer();
void DeleteBuffer(Buffer** buf);
int32 CheckCapacity(Buffer* buf, uint32 len);
void ResetBuffer(Buffer* buf); 

/*---------------------------------------------------------------------------*/
int32 ReadByte(EdpPacket* pkg, uint8* val);
int32 ReadBytes(EdpPacket* pkg, uint8** val, uint32 count);
int32 ReadUint16(EdpPacket* pkg, uint16* val);
int32 ReadUint32(EdpPacket* pkg, uint32* val);
int32 ReadStr(EdpPacket* pkg, char** val);
int32 ReadRemainlen(EdpPacket* pkg, uint32* len_val);

int32 WriteByte(Buffer* buf, uint8 byte);
int32 WriteBytes(Buffer* buf, const void* bytes, uint32 count);
int32 WriteUint16(Buffer* buf, uint16 val);
int32 WriteUint32(Buffer* buf, uint32 val);
int32 WriteStr(Buffer* buf, const char *str, uint16 length);
int32 WriteRemainlen(Buffer* buf, uint32 len_val);

/* is the recv buffer has a complete edp packet? */
/*
 * @return =0 : coutinue to recv;
 *         >0 : completely;
 *         <0 : data error need close 
 */
int32 IsPkgComplete(const char* data, uint32 data_len);

/*---------------------------------------------------------------------------*/
/* APIs                                                                      */
/*---------------------------------------------------------------------------*/
/* connect1 (C->S): devid + apikey */
EdpPacket* PacketConnect1(const char* devid, const char* auth_key);
/* connect2 (C->S): userid + auth_info */
EdpPacket* PacketConnect2(const char* userid, const char* auth_info);
/* push_data (C->S) */
EdpPacket* PacketPushdata(const char* dst_devid, const char* data, uint32 data_len);
/* sava_data json (C->S) */
EdpPacket* PacketSavedataJson(const char* dst_devid, cJSON* json_obj);
/* sava_data bin (C->S) */
EdpPacket* PacketSavedataBin(const char* dst_devid, cJSON* desc_obj, uint8* bin_data, uint32 bin_len);
/* ping (C->S) */
EdpPacket* PacketPing(void);

/* recv stream to a edp packet (S->C) */
EdpPacket* GetEdpPacket(RecvBuffer* buf);
/* get edp packet type, client should use this type to invoke Unpack??? function */
/* for exmaple:
 * ...
 * int8 mtype = EdpPacketType(pkg);
 * switch(mtype)
 * {
 *  case CONNRESP:
 *      UnpackConnectResp(pkg);
 *      break;
 *  case PUSHDATA:
 *      UnpackPushdata(pkg, src_devid, data, data_len);
 *      break;
 *  case SAVEDATA:
 *      UnpackSavedata(pkg, src_devid, flag, data);
 *      break;
 *  case PINGRESP:
 *      UnpackPingResp(pkg); 
 *      break;
 *  ...
 * }
 */
uint8 EdpPacketType(EdpPacket* pkg);
/* connect_resp (S->C)*/
int32 UnpackConnectResp(EdpPacket* pkg);
/* push_data (S->C) */
int32 UnpackPushdata(EdpPacket* pkg, char** src_devid, char** data, uint32* data_len);
/* save_data (S->C) */
int32 UnpackSavedata(EdpPacket* pkg, char** src_devid, uint8* jb_flag);
int32 UnpackSavedataJson(EdpPacket* pkg, cJSON** json_obj);
int32 UnpackSavedataBin(EdpPacket* pkg, cJSON** desc_obj, uint8** bin_data, uint32* bin_len);
/* ping_resp (S->C) */
int32 UnpackPingResp(EdpPacket* pkg);

#endif /* __EDP_KIT_H__ */
