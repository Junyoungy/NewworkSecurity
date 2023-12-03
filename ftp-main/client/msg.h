#ifndef __MSG_H__
#define __MSG_H__
#include <openssl/aes.h>

#define AES_KEY_128     16
#define BUFSIZE     512
#define BUF_SIZE 128
#define FILE_NAME_LEN 20
#define COMMEND_LEN 20
#define AES_BLOCK_LEN 16


enum MSG_AND_COMMAND_TYPE
{
    PUBLIC_KEY,         
    SECRET_KEY,         
    PUBLIC_KEY_REQUEST, 
    IV,                 
    ENCRYPTED_KEY,      
    ENCRYPTED_MSG,      

    UPLOAD,             // upload File
    DOWNLOAD,           // download file from server
    LIST,               // show list of file_list
    QUIT,               // quit program
    SEND_LIST,          // send list of file_list
    SEND_COMPLETE,      // send complete
    FILE_NAME,          // file name
    FILE_DATA,          // data data
    EXIST_FILE,         // already existing file       
    NONE_FILE,          // none
    DOWN_FILE,          // downloaded file
    NOTHING_COMMAND,    //nothing
    ERROR               //error
};

typedef struct _APP_MSG_{

    int type;
    unsigned char payload[BUFSIZE+AES_BLOCK_SIZE];
    int msg_len;
    
}APP_MSG;

#endif