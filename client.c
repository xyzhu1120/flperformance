#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <string.h>

int main()
{
	int cfd;
	int nread;
	int sin_size;
	int rfd;
	char buffer[2048] = {0};
	struct sockaddr_in s_add,c_add;
	unsigned short portnum = 0x8888;

	printf("hellp, welcome to use test client\n");

	rfd = open("util.test.c",O_RDONLY);
	if(rfd < 0){
		printf("fail to open file %i\n", rfd);
		return -1;
	}
	cfd = socket(AF_INET, SOCK_STREAM, 0);
	if(cfd == -1){
		printf("socket fail \n");
		return -1;
	}

	printf("socket ok \n");

	bzero(&s_add, sizeof(struct sockaddr_in));
	
	s_add.sin_family = AF_INET;
	s_add.sin_addr.s_addr = inet_addr("192.168.58.132");
	s_add.sin_port = htons(portnum);

	if(connect(cfd,(struct sockadd *)(&s_add), sizeof(struct sockaddr)) == -1){
		printf("connect fail!\n");
		return -1;
	}

	read(rfd, buffer, sizeof(buffer));
	if( write(cfd, buffer,sizeof(buffer)) == -1){
		printf("write fail~\n");
		return -1;
	}

	
	if( read(cfd, buffer, 1024) == -1){
		printf("read form server fail!\n");
		return -1;
	}
	buffer[sizeof(buffer) - 1] = '\0';
	printf("%s\n",buffer);
	
	printf("success!\n");
	close(cfd);

	return 0;
}
