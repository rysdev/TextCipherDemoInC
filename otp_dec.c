/*********************************************************************
otp_dec.c
Author: Ryan Ruiz
Description: Client side program that connects to otp_dec_d. otp_dec sends
ciphertext and a key for otp_dec_d to decode and send back plaintext.
Ciphertext and key must have valid characters only containing
A-Z or SPACE only.
Command Line Format: otp_dec ciphertext key [portNumber]
Resource Used: http://beej.us/guide/bgnet/output/html/multipage/index.html
*********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(int argc, char *argv[]) {
   int sockfd, portno, charsWritten, fileDesc, plainsize, keysize;
   struct sockaddr_in serv_addr;
   struct hostent* serverInfo;
   struct stat fileStat;
   ssize_t nread;
   
   char buffer[500];
   char confirmation[32];
   char fileSize[256];
   char *plainfile;
   int remaining;
   
   /* Handle invalid arguments */
   if (argc < 4) {
      fprintf(stderr,"USAGE: %s ciphertext key port\n", argv[0]);
      exit(0);
   }
	
   /* Setup Server Addr Struct */
   portno = atoi(argv[3]);
   serverInfo = gethostbyname("localhost");
   
   if (serverInfo == NULL) {
      fprintf(stderr,"ERROR, no such host\n");
      exit(0);
   }
   
   memset((char *)&serv_addr, '\0', sizeof(serv_addr));
   serv_addr.sin_family = AF_INET;
   memcpy((char *)&serv_addr.sin_addr.s_addr, (char *)serverInfo->h_addr, serverInfo->h_length);
   serv_addr.sin_port = htons(portno);

   /* Create a socket point */
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sockfd < 0) {
      fprintf(stderr,"ERROR opening socket\n");
   }
   
   /* Now connect to the server */
   if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
      fprintf(stderr,"ERROR connecting to server\n");
   }

   /* Send program identity to server */
   charsWritten = send(sockfd, "dec", 3, 0);
   if (charsWritten < 0)
      fprintf(stderr,"CLIENT: ERROR writing to socket\n");
   if (charsWritten < 3) {
      fprintf(stderr,"CLIENT: WARNING not all data written to socket\n");
   }

   /* Receive identity confirmation from server */
   memset(confirmation, '\0', sizeof(confirmation));
   charsWritten = recv(sockfd, confirmation, sizeof(confirmation) - 1, 0);
   
   if (charsWritten < 0) {
      fprintf(stderr,"CLIENT: ERROR reading from socket\n");
      exit(1);
   }

   /* Receive valid program confirmation */
   if(strcmp(confirmation, "success") == 0) {

      /* Open plainfile */
      fileDesc = open(argv[1], O_RDONLY);

      if (fileDesc < 0) {
         fprintf(stderr, "Could not open file %s\n", argv[1]);
         exit(1);
      }

      /* Get ciphertext size */
      if (fstat(fileDesc, &fileStat) < 0) {
         fprintf(stderr, "Error with fstat\n");
         exit(1);
      }
      sprintf(fileSize, "%d", fileStat.st_size);

      /* Send ciphertext size to server */
      charsWritten = send(sockfd, fileSize, strlen(fileSize), 0);
      if (charsWritten < 0)
         fprintf(stderr,"CLIENT: ERROR writing to socket\n");
      if (charsWritten < strlen(fileSize)) {
         fprintf(stderr,"CLIENT: WARNING not all data written to socket\n");
      }

      plainsize = atoi(fileSize);

      /* Wait for server confirmation */
      memset(confirmation, '\0', sizeof(confirmation));
      charsWritten = recv(sockfd, confirmation, sizeof(confirmation) - 1, 0);
   
      if (charsWritten < 0) {
         fprintf(stderr,"CLIENT: ERROR reading from socket\n");
         exit(1);
      }

      if(strcmp(confirmation, "success") != 0) {
         fprintf(stderr,"CLIENT: ERROR, no plaintext confirmation from server\n");
         exit(1);
      }

      lseek(fileDesc, 0, SEEK_SET);

      /*Send cipherfile to server */
      remaining = plainsize;
      while(remaining > 0) {
         memset(buffer, '\0', sizeof(buffer));
         nread = read(fileDesc, buffer, sizeof(buffer));
         if(nread < 0) {
            fprintf(stderr,"CLIENT: ERROR reading file\n");
         }
         charsWritten = send(sockfd, buffer, nread, 0);
         if (charsWritten < 0)
            fprintf(stderr,"CLIENT: ERROR writing to socket\n");
         if (charsWritten < strlen(buffer)) {
            fprintf(stderr,"CLIENT: WARNING not all data written to socket\n");
         }
         remaining -= charsWritten;
      }

      /* Wait for server confirmation */
      memset(confirmation, '\0', sizeof(confirmation));
      charsWritten = recv(sockfd, confirmation, sizeof(confirmation) - 1, 0);
   
      if (charsWritten < 0) {
         fprintf(stderr,"CLIENT: ERROR reading from socket\n");
         exit(1);
      }

      if(strcmp(confirmation, "success") != 0) {
         fprintf(stderr,"CLIENT: ERROR, no ciphertext confirmation from server\n");
         exit(1);
      }

      /* Open key */
      fileDesc = open(argv[2], O_RDONLY);

      if (fileDesc < 0) {
         fprintf(stderr, "Could not open file %s\n", argv[2]);
         exit(1);
      }

      /* Get key file size */
      if (fstat(fileDesc, &fileStat) < 0) {
         fprintf(stderr, "Error with fstat\n");
         exit(1);
      }
      sprintf(fileSize, "%d", fileStat.st_size);


      /* Send key size to server */
      charsWritten = send(sockfd, fileSize, strlen(fileSize), 0);
      if (charsWritten < 0)
         fprintf(stderr,"CLIENT: ERROR writing to socket\n");
      if (charsWritten < strlen(fileSize)) {
         fprintf(stderr,"CLIENT: WARNING not all data written to socket\n");
      }

      keysize = atoi(fileSize);

      /* Handle if key is too small */
      if(keysize < plainsize) {
         fprintf(stderr,"ERROR: Key %s is not large enough\n", argv[2]);
         exit(1);
      }

      lseek(fileDesc, 0, SEEK_SET);

      /*Send key to server */
      remaining = keysize;
      while(remaining > 0) {
         memset(buffer, '\0', sizeof(buffer));
         nread = read(fileDesc, buffer, sizeof(buffer));
         if(nread < 0) {
            fprintf(stderr,"CLIENT: ERROR reading file\n");
         }
         charsWritten = send(sockfd, buffer, nread, 0);
         if (charsWritten < 0)
            fprintf(stderr,"CLIENT: ERROR writing to socket\n");
         if (charsWritten < strlen(buffer)) {
            fprintf(stderr,"CLIENT: WARNING not all data written to socket\n");
         }
         remaining -= charsWritten;
      }

      close(fileDesc);

      /* Wait for server confirmation */
      memset(confirmation, '\0', sizeof(confirmation));
      charsWritten = recv(sockfd, confirmation, sizeof(confirmation) - 1, 0);
   
      if (charsWritten < 0) {
         fprintf(stderr,"CLIENT: ERROR reading from socket\n");
         exit(1);
      }

      if(strcmp(confirmation, "success") != 0) {
         fprintf(stderr,"opt_enc: ERROR Input contains invalid characters\n");
         exit(1);
      }

      /* If ciphertext and key valid receive plaintext */
      else {
         charsWritten = send(sockfd, "dec", 3, 0);
         if (charsWritten < 0)
            fprintf(stderr,"CLIENT: ERROR writing to socket\n");
         if (charsWritten < 3) {
            fprintf(stderr,"CLIENT: WARNING not all data written to socket\n");
         }

         /* Receive decoded plaintext from server */
         plainfile = (char *) malloc(plainsize * sizeof(char));
         if(plainsize > 0)
            memset(plainfile, '\0', sizeof(plainfile));

         remaining = plainsize;
         while(remaining > 0) {
            memset(buffer, '\0', sizeof(buffer));
            charsWritten = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
            if (charsWritten < 0)
               fprintf(stderr,"CLIENT: ERROR reading from socket\n");
            if (charsWritten < strlen(buffer))
               fprintf(stderr,"CLIENT: WARNING not all data read from socket\n");

            remaining -= charsWritten;
            strcat(plainfile, buffer);
         }

         printf("%s", plainfile);

         /*int x = 0;
         printf("CHAR INT\n");
         fflush(stdout);
         for (x = 0; x < strlen(plainfile); x++) {
            printf(" %c   %d\n", plainfile[x], plainfile[x]);
            fflush(stdout);
         } */

         free(plainfile);
      }
   }
   else {
      fprintf(stderr,"ERROR: opt_dec not compatible with program on port %s\n", argv[3]);
      exit(1);
   }
   return 0;
}