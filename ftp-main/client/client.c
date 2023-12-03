#include "readnwrite.h"
#include "msg.h"
#include "aesenc.h"


int main(int argc, char* argv[])
{
    int sock; 
    struct sockaddr_in serv_addr;
    
    APP_MSG MSG_IN;
    APP_MSG MSG_OUT;
    
    int fd = -1;
    int cnt_i = 0x00;
    int file_len = 0x00;
    int type;
    int plaintext_len;
    int ciphertext_len;
    int current_command;
    
    unsigned char session_key[AES_KEY_128] = {0x000, };
    unsigned char iv[AES_KEY_128] = {0x00, };
    char file_name[BUF_SIZE] = {0x00, };
    char command[COMMEND_LEN];
    char upload_file_name[FILE_NAME_LEN] = {0, };
    char enc_file_name1[FILE_NAME_LEN] = {0, };
    char save_file_name[FILE_NAME_LEN] = {0, };
    char enc_file_name2[FILE_NAME_LEN] = {0, };
    char buff[BUFSIZE];

    BIO *rpub = NULL;
    RSA *rsa_pubkey = NULL;

    if (argc != 3)
    {
        printf("Usage: %s <IP><port>\n", argv[0]);
        exit(1);
    }

    RAND_poll();
    RAND_bytes(session_key, sizeof(session_key)); 

    for (int cnt_i = 0; cnt_i < AES_KEY_128; cnt_i++)
    {
        iv[cnt_i] = (unsigned char)cnt_i;
    }

    sock = socket(PF_INET, SOCK_STREAM, 0);

    if (sock == -1)
    {
        error_handling("socket() error");
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    {
        error_handling("connect() error");
    }
    else
    {
        printf("[**** Server Connected ****]\n");
    }

    memset(&MSG_OUT, 0, sizeof(MSG_OUT)); 
    MSG_OUT.type = PUBLIC_KEY_REQUEST; 
    MSG_OUT.type = htonl(MSG_OUT.type);

    type = writen(sock, &MSG_OUT, sizeof(APP_MSG)); 
    if (type == -1)
    {
        error_handling("writen() error");
    }

    memset(&MSG_IN, 0, sizeof(APP_MSG)); 
    type = readn(sock, &MSG_IN, sizeof(APP_MSG)); 
    MSG_IN.type = ntohl(MSG_IN.type);
    MSG_IN.msg_len = ntohl(MSG_IN.msg_len); 
    printf("\n");

    if (type == -1)
    {
        error_handling("readn() error");
    }
    else if (type == 0)
    {
        error_handling("reading EOF");
    }

    if (MSG_IN.type != PUBLIC_KEY)
    {
        error_handling("message error");
    }
    else
    {
      
        rpub = BIO_new_mem_buf(MSG_IN.payload, -1); 
        BIO_write(rpub, MSG_IN.payload, MSG_IN.msg_len);
        if (!PEM_read_bio_RSAPublicKey(rpub, &rsa_pubkey, NULL, NULL))
        {
            error_handling("PEM_read_bio_RSAPublicKey() error");
        }
    }

    memset(&MSG_OUT, 0, sizeof(APP_MSG));
    MSG_OUT.type = ENCRYPTED_KEY;
    MSG_OUT.type = htonl(MSG_OUT.type);
    MSG_OUT.msg_len = RSA_public_encrypt(sizeof(session_key), session_key, MSG_OUT.payload, rsa_pubkey, RSA_PKCS1_OAEP_PADDING);
    MSG_OUT.msg_len = htonl(MSG_OUT.msg_len);

    type = writen(sock, &MSG_OUT, sizeof(APP_MSG));

    if (type == -1)
    {
        error_handling("writen() error");
    }
    
    printf("\n\n[**** Program Start! ****]\n");
    current_command = NOTHING_COMMAND;
    

    while(current_command != QUIT)
    {
        printf("How may i help you?(Enter the command)\n");
        printf("UPLOAD     DOWNLOAD     LIST     QUIT \n");
        scanf("%s", command);
        command[strlen(command)] = '\0';
    
        if (strcmp(command, "UPLOAD") == 0 || strcmp(command, "upload") == 0)
            current_command = UPLOAD;
        else if (strcmp(command, "DOWNLOAD") == 0 || strcmp(command, "download") == 0)
            current_command = DOWNLOAD;
        else if (strcmp(command, "LIST") == 0 || strcmp(command, "list") == 0)
            current_command = LIST;
        else if (strcmp(command, "QUIT") == 0|| strcmp(command, "quit") == 0)
            current_command = QUIT;
        else
            current_command = NOTHING_COMMAND;

        switch (current_command)
        {
            case NOTHING_COMMAND:
                printf("Command is wrong...\n");
                break;

            case UPLOAD: 
                printf("Please Enter File Name for Upload : ");
                scanf("%s", upload_file_name);
                printf("Please Enter File Name For Save: ");
                scanf("%s", save_file_name);

                upload_file_name[strlen(upload_file_name)] = '\0';
                save_file_name[strlen(save_file_name)] = '\0';

                fd = open(upload_file_name, O_RDONLY, S_IRWXU);
                if (fd == -1)
                    error_handling("open() error");

                memset(&MSG_OUT, 0, sizeof(APP_MSG));
                memcpy(enc_file_name2, save_file_name, strlen(save_file_name));

                
                plaintext_len = encrypt((unsigned char*)enc_file_name2, strlen(enc_file_name2), session_key, iv, MSG_OUT.payload);
                MSG_OUT.type = htonl(UPLOAD);
                MSG_OUT.msg_len = htonl(plaintext_len);
                writen(sock, &MSG_OUT, sizeof(APP_MSG));
               
 
                for (;;)
                {
                    memset(buff, 0x00, BUFSIZE);
                    
                    file_len = readn(fd, buff, BUFSIZE);
                    if (file_len == 0)
                    {
                        break;
                    }
                    
                    file_len = encrypt((unsigned char*)buff, file_len, session_key, iv, MSG_OUT.payload);
                    MSG_OUT.msg_len = htonl(file_len);
                    MSG_OUT.type = htonl(FILE_DATA);
                    writen(sock, &MSG_OUT, sizeof(APP_MSG));
                    
                }

                memset(&MSG_OUT, 0, sizeof(APP_MSG));
                MSG_OUT.type = htonl(SEND_COMPLETE);
                writen(sock, &MSG_OUT, sizeof(APP_MSG));
                close(fd);

                printf("[**** Upload Success ****]\n");
                current_command = NOTHING_COMMAND;
                break;

            case DOWNLOAD:
                printf("File Name to Download : ");
                scanf("%s", upload_file_name);
                printf("File Name to Save : ");
                scanf("%s", save_file_name);
                upload_file_name[strlen(upload_file_name)] = '\0';
                save_file_name[strlen(save_file_name)] = '\0';     
                fd = open(save_file_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);

                memset(&MSG_OUT, 0, sizeof(APP_MSG));
               
                memcpy(enc_file_name1, upload_file_name, strlen(upload_file_name));

                plaintext_len = encrypt((unsigned char*)enc_file_name1, strlen(enc_file_name1), session_key, iv, MSG_OUT.payload);
                MSG_OUT.type = htonl(DOWNLOAD);
                MSG_OUT.msg_len = htonl(plaintext_len);
                writen(sock, &MSG_OUT, sizeof(APP_MSG));
                
                for (;;)
                {
                    memset(&MSG_IN, 0, sizeof(APP_MSG));
                    memset(buff, 0, sizeof(buff));
            
                    readn(sock, &MSG_IN, sizeof(APP_MSG));
                    MSG_IN.msg_len = ntohl(MSG_IN.msg_len);
                    MSG_IN.type = ntohl(MSG_IN.type);
                    if (MSG_IN.type == EOF | MSG_IN.type == 0)
                    {
                        break;
                    }
                    if (MSG_IN.type == FILE_DATA)
                    {
                        file_len = decrypt(MSG_IN.payload, MSG_IN.msg_len, session_key, iv, (unsigned char *)buff);
                        
                        writen(fd, buff, file_len);
                    }
                    else if (MSG_IN.type == SEND_COMPLETE)
                    {
                        current_command = NOTHING_COMMAND;
                        break;
                    }
                }
                printf("[**** Download Complete ****]\n");
                close(fd);
                break;


            case LIST: 
                memset(&MSG_OUT, 0, sizeof(APP_MSG));
                MSG_OUT.type = current_command;
                MSG_OUT.type = htonl(MSG_OUT.type);
                writen(sock, &MSG_OUT, sizeof(APP_MSG));
                current_command = NOTHING_COMMAND;
                for (;;)
                {
                    memset(file_name,0,sizeof(file_name));
                    memset(&MSG_IN, 0, sizeof(APP_MSG));

                    readn(sock, &MSG_IN, sizeof(APP_MSG));


                    MSG_IN.type = ntohl(MSG_IN.type);
                    MSG_IN.msg_len = ntohl(MSG_IN.msg_len);
                    if (MSG_IN.type != SEND_COMPLETE)
                    {

                        ciphertext_len = decrypt(MSG_IN.payload, MSG_IN.msg_len, session_key, iv, (unsigned char*)file_name);
                        
                        if(file_name[0] != '.')
                        {
                            printf("FILE NAME : %s\n", file_name);
                        }
                    }
                    else if (MSG_IN.type == SEND_COMPLETE)
                    {
                        current_command = NOTHING_COMMAND;
                        break;
                    }
                }

                printf("[**** End of List ****]\n\n\n");
                current_command = NOTHING_COMMAND;
                break;

            case QUIT:
                current_command = QUIT;
                memset(&MSG_OUT, 0, sizeof(APP_MSG));
                MSG_OUT.type = current_command;
                MSG_OUT.type = htonl(MSG_OUT.type);
                writen(sock, &MSG_OUT, sizeof(APP_MSG));
                break;

            default:
                break;
        }
    }

    printf("QUIT\n");
    printf("[**** Program End ****]\n");
    close(sock);
    return 0;
}

void error_handling(char *msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(1);
}
