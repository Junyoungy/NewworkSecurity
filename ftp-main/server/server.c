#include "readnwrite.h"
#include "msg.h"
#include "aesenc.h"


int main(int argc, char* argv[])
{
    struct sockaddr_in serv_addr; 
    struct sockaddr_in clnt_addr; 
    socklen_t clnt_addr_size;

    APP_MSG MSG_IN;
    APP_MSG MSG_OUT;

    unsigned char session_key[AES_KEY_128] = {0x00, };
    unsigned char iv[AES_KEY_128] = {0x00, };
    unsigned char buffer[BUFSIZE] = {0x00, };

    char file_list[2*FILE_NAME_LEN] = "./file_list/";

    char file_name[BUF_SIZE] = {0x00, };
    char *save_file_name = NULL;
    char the_file[FILE_NAME_LEN] = {0x00, };
    char the_other_file[FILE_NAME_LEN] = {0x00, };
    char buff[BUFSIZE];

    int cnt_i;
    int path_len = strlen(file_list);
    int serv_sock; 
    int clnt_sock;
    int current_type = NOTHING_COMMAND;
    int type;
    int len;
    int ciphertext_len;
    int publickey_len;
    int encryptedkey_len;
    int fd = -1;
    int file_len = 0x00;

    BIO *bp_public = NULL, *bp_private = NULL;
    BIO *pub = NULL;
    RSA *rsa_pubkey = NULL, *rsa_privkey = NULL;

    pid_t pid;
    struct sigaction act;
    DIR *dir;
    struct dirent *ent;
    
    if (argc != 2)
    {
        fprintf(stderr, "%s <port>\n", argv[0]);
    }

    RAND_poll();
    for (int cnt_i = 0; cnt_i < AES_KEY_128; cnt_i++)
    {
        iv[cnt_i] = (unsigned char)cnt_i;
    }

    act.sa_handler = read_childproc;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    int state = sigaction(SIGCHLD, &act, 0);

    RSAES_key_generator();
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1)
    {
        error_handling("socket() error");
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;                
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1]));     

    if (bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    {
        error_handling("bind() error");
    }

    if (listen(serv_sock, 5) == -1)
    {
        error_handling("listen() error");
    }
    
    for (;;)
    {
        clnt_addr_size = sizeof(clnt_addr);
        clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
        if (clnt_sock == -1)
        {
            continue;
        }
        else
        {
            printf("[**** New Client Connected ****]\n");
        }

        bp_public = BIO_new_file("public.pem", "r");
        if (!PEM_read_bio_RSAPublicKey(bp_public, &rsa_pubkey, NULL, NULL))
        {
            goto ERROR;
        }
        
        bp_private = BIO_new_file("private.pem", "r");
        if (!PEM_read_bio_RSAPrivateKey(bp_private, &rsa_privkey, NULL, NULL)) 
        {
            goto ERROR;
        }

        memset(&MSG_IN, 0, sizeof(APP_MSG));
        type = readn(clnt_sock, &MSG_IN, sizeof(APP_MSG));
        MSG_IN.type = ntohl(MSG_IN.type);
        MSG_IN.msg_len = ntohl(MSG_IN.msg_len); 
        if (type == -1)
        {
            error_handling("readn() error");
        }
        else if (type == 0)
        {
            error_handling("reading EOF");
        }

        if (MSG_IN.type != PUBLIC_KEY_REQUEST)
        {
            error_handling("message error 1");
        }
        else
        {
       
            memset(&MSG_OUT, 0, sizeof(APP_MSG));
            MSG_OUT.type = PUBLIC_KEY;
            MSG_OUT.type = htonl(MSG_OUT.type);

            pub = BIO_new(BIO_s_mem()); 
            PEM_write_bio_RSAPublicKey(pub, rsa_pubkey); 
            publickey_len = BIO_pending(pub); 

            BIO_read(pub, MSG_OUT.payload, publickey_len);
            MSG_OUT.msg_len = publickey_len;
            MSG_OUT.msg_len = htonl(MSG_OUT.msg_len);
            
            type = writen(clnt_sock, &MSG_OUT, sizeof(APP_MSG));
            if (type == -1)
            {
                error_handling("writen() error");
                break;
            }
        }

        memset(&MSG_IN, 0, sizeof(APP_MSG));
        type = readn(clnt_sock, &MSG_IN, sizeof(APP_MSG));
        MSG_IN.type = ntohl(MSG_IN.type);
        MSG_IN.msg_len = ntohl(MSG_IN.msg_len);
        if (MSG_IN.type != ENCRYPTED_KEY)
        {
            error_handling("message error 2");
        } 
        else
        {
            encryptedkey_len = RSA_private_decrypt(MSG_IN.msg_len, MSG_IN.payload, buffer, rsa_privkey, RSA_PKCS1_OAEP_PADDING); 
            memcpy(session_key, buffer, encryptedkey_len);
        }

        if (clnt_sock == -1)
        {
            continue;
        }
        else
        {
            printf("\n");
        }

        pid = fork();

        if (pid == 0) 
        {
            close(serv_sock);

            printf("[**** Client Access Successful! ****]\n");
            current_type = NOTHING_COMMAND;
            while (current_type != QUIT)
            {
                memset(&MSG_IN, 0, sizeof(APP_MSG));
                memset(&MSG_OUT, 0, sizeof(APP_MSG));
                readn(clnt_sock, &MSG_IN, sizeof(APP_MSG));
                MSG_IN.type = ntohl(MSG_IN.type);
                current_type = MSG_IN.type;

                switch (current_type)
                {
                    case UPLOAD:
                        MSG_IN.msg_len = ntohl(MSG_IN.msg_len);
                        ciphertext_len = decrypt(MSG_IN.payload, MSG_IN.msg_len, session_key, iv, (unsigned char *)the_other_file);
                        
                        save_file_name = (char*)calloc(ciphertext_len + path_len, 1 );
                        for(cnt_i = 0 ; cnt_i < path_len ; cnt_i ++)
                        {
                            save_file_name[cnt_i] = file_list[cnt_i];
                        }

                        for(cnt_i = path_len ; cnt_i < path_len + ciphertext_len ; cnt_i ++)
                        {
                            save_file_name[cnt_i] = the_other_file[cnt_i - path_len];
                        }
                            
                        fd = open(save_file_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
                        if (fd == -1)
                        {
                            error_handling("open() error");
                        }

                        for (;;)
                        {
                            memset(&MSG_IN, 0, sizeof(APP_MSG));
                            readn(clnt_sock, &MSG_IN, sizeof(APP_MSG));
                            MSG_IN.msg_len = ntohl(MSG_IN.msg_len);
                            MSG_IN.type = ntohl(MSG_IN.type);
                            if (MSG_IN.type == EOF | MSG_IN.type == 0)
                            {
                                break;
                            }
                            if (MSG_IN.type == FILE_DATA)
                            {   
                                file_len = decrypt(MSG_IN.payload, MSG_IN.msg_len, session_key, iv, (unsigned char*)buff);
                                writen(fd, buff, file_len);
                            }
                            else if (MSG_IN.type == SEND_COMPLETE)
                            {
                                free(save_file_name);
                                close(fd);
                                printf("[**** Upload Success ****]\n");
                                current_type = NOTHING_COMMAND;
                                break;
                            }
                        
                        }       
                        break;

                    case DOWNLOAD:

                        memset(the_file, 0, sizeof(the_file));
                        MSG_IN.msg_len = ntohl(MSG_IN.msg_len);
                        ciphertext_len = decrypt(MSG_IN.payload, MSG_IN.msg_len, session_key, iv, (unsigned char *)the_file);

                        save_file_name = (char*)calloc(ciphertext_len + path_len, 1 );
                        for(cnt_i = 0 ; cnt_i < path_len ; cnt_i ++)
                        {
                            save_file_name[cnt_i] = file_list[cnt_i];
                        }

                        for(cnt_i = path_len ; cnt_i < path_len + ciphertext_len ; cnt_i ++)
                        {
                            save_file_name[cnt_i] = the_file[cnt_i - path_len];
                        }
                      
                        fd =  open(save_file_name, O_RDONLY, S_IRWXU);
                        if (fd == -1)
                        {
                            error_handling("open() error");
                            memset(&MSG_OUT, 0, sizeof(APP_MSG));
                            MSG_OUT.type = htonl(NONE_FILE);
                            writen(clnt_sock, &MSG_OUT, sizeof(APP_MSG));
                        }
                        else
                        {
                            memset(&MSG_OUT, 0, sizeof(APP_MSG));
                            MSG_OUT.type = htonl(EXIST_FILE);
                            writen(clnt_sock, &MSG_OUT, sizeof(APP_MSG));
                        }
 
                    
                        for (;;)
                        {
                            memset(buff, 0x00, BUFSIZE);
                            memset(&MSG_OUT, 0, sizeof(APP_MSG));
                            file_len = readn(fd, buff, BUFSIZE);
                            if (file_len == 0)
                            {
                                printf("[**** File Download Completed ****]\n");
                                break;
                            }
                            file_len = encrypt((unsigned char *)buff, file_len, session_key, iv, MSG_OUT.payload);
                            MSG_OUT.msg_len = htonl(file_len);
                            MSG_OUT.type = htonl(FILE_DATA);
                            writen(clnt_sock, &MSG_OUT, sizeof(APP_MSG));
                        }

                        memset(&MSG_OUT, 0, sizeof(APP_MSG));
                        MSG_OUT.type = htonl(SEND_COMPLETE);
                        writen(clnt_sock, &MSG_OUT, sizeof(APP_MSG));
                        
                        free(save_file_name);
                        close(fd);
                        current_type = NOTHING_COMMAND;
                        break;

                    case LIST:

                        dir = opendir("./file_list/");
                        if (dir != NULL)
                        {
                            while ((ent = readdir(dir)) != NULL)
                            {
                                memset(file_name, 0, sizeof(file_name));
                                memcpy(file_name, ent->d_name, strlen(ent->d_name));

                                len = encrypt((unsigned char*)file_name, strlen(file_name), session_key, iv, MSG_OUT.payload);
                                MSG_OUT.type = SEND_LIST;
                                MSG_OUT.msg_len = len;
                                MSG_OUT.type = htonl(MSG_OUT.type);
                                MSG_OUT.msg_len = htonl(MSG_OUT.msg_len);
                                writen(clnt_sock, &MSG_OUT, sizeof(APP_MSG));
                            }
                            current_type = SEND_COMPLETE;
                            MSG_OUT.type = SEND_COMPLETE;
                            MSG_OUT.type = htonl(MSG_OUT.type);
                            writen(clnt_sock, &MSG_OUT, sizeof(APP_MSG));
                            closedir(dir);
                        }
                        else
                        {
                            printf("[XXXX List Error XXXX]\n");
                            return EXIT_FAILURE;
                        }

                        printf("[Command Complete And Waiting...]\n");

                        current_type = NOTHING_COMMAND;
                        break;
                    
                    case QUIT:
                        current_type = QUIT;
                        break;
                    default:
                        break;
                }
            }

            close(clnt_sock); 
            puts("[**** Client Disconnected ****]");
        }
        else
        {
            close(clnt_sock); 
        }

    }
    close(serv_sock);

    ERROR:
        close(serv_sock);

    return 0;
}

void error_handling(char *msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(1);
}

int RSAES_key_generator()
{
    RSA *rsa; 
    BIO *bp_public = NULL, *bp_private = NULL; 
    unsigned long e_value = RSA_F4; 
    BIGNUM *exponent_e = BN_new();

    rsa = RSA_new();

    BN_set_word(exponent_e, e_value); 

    if (RSA_generate_key_ex(rsa, 2048, exponent_e, NULL) == '\0') 
    {
        fprintf(stderr, "RSA_generate_key_ex() error\n");
    }

    bp_public = BIO_new_file("public.pem", "w+");
    int ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);

    if (ret != 1)
    {
        goto ERROR;
    }

    bp_private = BIO_new_file("private.pem", "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL); 

    if (ret != 1)
    {
        goto ERROR;
    }

    ERROR:
        RSA_free(rsa);
        BIO_free_all(bp_public);
        BIO_free_all(bp_private);

    return ret;
}


void read_childproc(int sign) 
{
    pid_t PID;
    int status;
    PID = waitpid(-1, &status, WNOHANG); 
    printf("[removed proc id : %d]\n", PID);
}
