/*
otp_dec_d.c
Author: Ryan Ruiz
Description: Server side program that connects to otp_dec. otp_dec_d receives
ciphertext and a key from otp_dec. opt_dec_d encodes the plaintext using the key
and sends the coded text back plaintext to client.
Ciphertext and key must have valid characters only containing
A-Z or SPACE only.
Command Line Format: otp_dec_d [portNumber]
Resources Used:	http://beej.us/guide/bgnet/output/html/multipage/index.html
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

int numChildren = 0;

/* Handler for SIGCHILD  */
void sigChildHandler(int signo)
{
   while (waitpid((pid_t)(-1), 0, WNOHANG) > 0)
      numChildren--;
}

void handleConnection(int incomingFD) {
   char userInput[256];
   char buffer[500];
   int charsIn, i, index, remaining, message, key, coded;
   int plainsize = 0;
   int keysize = 0;
   char *plainfile;
   char *keyfile;

   /*printf("SERVER: Connected with client\n");
   fflush(stdout); */

   memset(userInput, '\0', sizeof(userInput));

   /* Receive incoming program name */
   charsIn = recv(incomingFD, userInput, sizeof(userInput) - 1, 0);
   if(charsIn < 0)
      fprintf(stderr,"SERVER: ERROR reading from socket\n");

   /*Verify program for handling connection */
   if(strcmp(userInput, "dec") == 0) {

      charsIn = send(incomingFD, "success", 7, 0);
      if(charsIn < 0)
         fprintf(stderr,"SERVER: ERROR writing to socket\n");

      /* Receive plaintext size */
      memset(userInput, '\0', sizeof(userInput));
      charsIn = recv(incomingFD, userInput, sizeof(userInput) - 1, 0);
      if(charsIn < 0)
         fprintf(stderr,"SERVER: ERROR reading from socket\n");

      /* Send Receive confirmation to client */
      charsIn = send(incomingFD, "success", 7, 0);
      if(charsIn < 0)
         fprintf(stderr,"SERVER: ERROR writing to socket\n");

      plainsize = atoi(userInput);

      /* Inititialize plainfile string */
      plainfile = (char *) malloc(plainsize * sizeof(char));
      if(plainsize > 0)
         memset(plainfile, '\0', sizeof(plainfile));

      /* Retrieve plaintext from client */
      remaining = plainsize;
      while(remaining > 0) {
         memset(buffer, '\0', sizeof(buffer));
         charsIn = recv(incomingFD, buffer, sizeof(buffer) - 1, 0);
         if (charsIn < 0)
            fprintf(stderr,"SERVER: ERROR reading from socket\n");
         if (charsIn < strlen(buffer))
            fprintf(stderr,"SERVER: WARNING not all data read from socket\n");

         remaining -= charsIn;
         strcat(plainfile, buffer);
      }

      /* Strip off newline char of plainfile for decoding */
      plainfile[strcspn(plainfile, "\n")] = '\0';
      plainfile[strcspn(plainfile, "\r")] = '\0';

      /* Send Receive confirmation to client */
      charsIn = send(incomingFD, "success", 7, 0);
      if(charsIn < 0)
         fprintf(stderr,"SERVER: ERROR writing to socket\n");

      /* Receive key size */
      memset(userInput, '\0', sizeof(userInput));
      charsIn = recv(incomingFD, userInput, sizeof(userInput) - 1, 0);
      if(charsIn < 0)
         fprintf(stderr,"SERVER: ERROR reading from socket\n");

      keysize = atoi(userInput);

      /* Inititialize keyfile string */
      keyfile = (char *) malloc(keysize * sizeof(char));
      if(keysize > 0)
         memset(keyfile, '\0', sizeof(keyfile));

      if(keysize >= plainsize) {

      /* Retrieve key from client */
      remaining = keysize;
      while(remaining > 0) {
         memset(buffer, '\0', sizeof(buffer));
         charsIn = recv(incomingFD, buffer, sizeof(buffer) - 1, 0);
         if (charsIn < 0)
            fprintf(stderr,"SERVER: ERROR reading from socket\n");
         if (charsIn < strlen(buffer))
            fprintf(stderr,"SERVER: WARNING not all data read from socket\n");

         remaining -= charsIn;
         strcat(keyfile, buffer);
      }

      /* Strip off newline char of key for decoding */
      keyfile[strcspn(keyfile, "\n")] = '\0';
      keyfile[strcspn(keyfile, "\r")] = '\0';

      /* Decode Ciphertext */
      for(i = 0; i < strlen(plainfile); i++) {
         if(plainfile[i] == 32 || (plainfile[i] >= 65 && plainfile[i] <= 90)) {
            if(keyfile[i] == 32 || (keyfile[i] >= 65 && keyfile[i] <= 90)) {
               /* decode here */

               if(keyfile[i] == 32)
                  key = 26;
               else
                  key = keyfile[i] - 65;

               if(plainfile[i] == 32)
                  coded = 26;
               else
                  coded = plainfile[i] - 65;

               coded += 27;
               coded -= key;
               coded %= 27;
               if(coded == 26)
                  plainfile[i] = 32;
               else {
                  plainfile[i] = coded + 65;
               }
               /*printf("%d\n", coded); */
            }
            /* Keyfile invalid */
            else {
               memset(plainfile, '\0', sizeof(plainfile));
               strcpy(plainfile, "@");
               i = strlen(plainfile);
            }
         }
         /* plaintext invalid */
         else {
            memset(plainfile, '\0', sizeof(plainfile));
            strcpy(plainfile, "@");
            i = strlen(plainfile);
         }
      }

      /*printf("SERVER: after decoding:\n%s\n", plainfile);
      fflush(stdout); */

      /* If key or plaintext invalid */
      if(strcmp(plainfile, "@") == 0) {
         charsIn = send(incomingFD, "invalid", 7, 0);
         if(charsIn < 0)
            fprintf(stderr,"SERVER: ERROR writing to socket\n");
      }
      /* If key or plaintext valid */
      else {
         charsIn = send(incomingFD, "success", 7, 0);
         if(charsIn < 0)
            fprintf(stderr,"SERVER: ERROR writing to socket\n");

         /* Receive confirmation to transmit decoded message */
         memset(userInput, '\0', sizeof(userInput));
         charsIn = recv(incomingFD, userInput, sizeof(userInput) - 1, 0);
         if(charsIn < 0)
            fprintf(stderr,"SERVER: ERROR reading from socket\n");

         /* Transmit decoded plaintext */
         if(strcmp(userInput, "dec") == 0) {

            /* Add newline to decoded message before sending to client */
            plainfile[strlen(plainfile)] = '\n';

            /* Send decoded message to client */
            remaining = strlen(plainfile);
            index = 0;
            while(remaining > 0) {
               memset(buffer, '\0', sizeof(buffer));
               strncpy(buffer, plainfile + index, sizeof(buffer));

               charsIn = send(incomingFD, buffer, sizeof(buffer), 0);
               if (charsIn < 0)
                  fprintf(stderr,"SERVER: ERROR writing to socket\n");
               if (charsIn < (strlen(buffer) - 1)) {
                  fprintf(stderr,"SERVER: WARNING not all data written to socket\n");
               }
               index += charsIn;
               remaining -= charsIn;
            }
         }
      }
      }
      free(plainfile);
      free(keyfile);
   }
}

int main(int argc, char *argv[]) {
	int listenFD, connectFD, portNum;
	socklen_t sizeOfClientInfo;
	struct sockaddr_in serverAddr, clientAddr;
   pid_t spawnPid = -5;
   pid_t childPid = -5;
   int childExitStatus = 0;

   /* Setup Signal Struct */
   struct sigaction sigChildAction = {0};
   sigChildAction.sa_handler = &sigChildHandler;
   sigfillset(&sigChildAction.sa_mask);
   sigChildAction.sa_flags = SA_RESTART | SA_NOCLDSTOP;
   if (sigaction(SIGCHLD, &sigChildAction, 0) == -1) {
      fprintf(stderr,"SERVER: Sigaction error\n");
      exit(1);
   }

   /* Handle invalid arguments */
   if (argc < 2) {
      fprintf(stderr,"Usage: %s port\n", argv[0]);
      exit(1);
   }

   /* Set up server address struct */
   memset((char *)&serverAddr, '\0', sizeof(serverAddr));
   portNum = atoi(argv[1]);
   serverAddr.sin_family = AF_INET;
   serverAddr.sin_port = htons(portNum);
   serverAddr.sin_addr.s_addr = INADDR_ANY;

   /* Set up connection socket */
   listenFD = socket(AF_INET, SOCK_STREAM, 0);
   if(listenFD < 0)
      fprintf(stderr,"SERVER: Could not open socket\n");

   /* Enable listening on connection socket */
   if(bind(listenFD, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
   	fprintf(stderr,"SERVER: Could not start listening on socket\n");
   /* Socket on for up to 5 connections */
   listen(listenFD, 5);

   /*Main Server Listening Loop */
   while(1) {
   	/* Accept incoming connections */
   	sizeOfClientInfo = sizeof(clientAddr);
   	connectFD = accept(listenFD, (struct sockaddr *)&clientAddr, &sizeOfClientInfo);
   	if(connectFD < 0)
         fprintf(stderr,"SERVER: Error with accept\n");

      /* Spawn child on each accept */
      spawnPid = fork();
      switch (spawnPid) {
         case -1: { 
            fprintf(stderr,"SERVER: Forking issue\n");
            exit(1); 
            break; 
         }
         case 0: {
            handleConnection(connectFD);
            exit(0); break;
         }
      }

      /* Close Connection */
      numChildren++;
      childPid = waitpid(spawnPid, &childExitStatus, 0);
      close(connectFD);
   }

   close(listenFD);
   return 0;
}