#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>


#define	BUFFER_LEN 1024

struct ctr_state 
{ 
	unsigned char ivec[AES_BLOCK_SIZE];	 
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
}; 

AES_KEY key; 
char* symmetric_key;


int bytes_read, bytes_written;	 
unsigned char indata[AES_BLOCK_SIZE]; 
unsigned char outdata[AES_BLOCK_SIZE];
unsigned char iv[AES_BLOCK_SIZE];
struct ctr_state state;	 
int client_fd;

void init_ctr(struct ctr_state *state, const unsigned char iv[16]) {		 
	/* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
     * first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);

    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}

void iencrypt(char* input, char* encrypted_output, int indata_len, const unsigned char* enc_key) { 
    
	//Initializing the encryption KEY
	if (AES_set_encrypt_key(enc_key, 128, &key) < 0) {
        fprintf(stderr, "Could not set encryption key.");
        exit(1); 
    }

	init_ctr(&state, iv); 

	AES_ctr128_encrypt(input, encrypted_output, indata_len, &key, state.ivec, state.ecount, &state.num);
}
	
void idecrypt(char* input, char* decrypted_output, int indata_len, const unsigned char* enc_key)
{	

	//Initializing the encryption KEY
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
    {
        fprintf(stderr, "Could not set decryption key.");
        exit(1);
    }

	init_ctr(&state, iv);
	AES_ctr128_encrypt(input, decrypted_output, indata_len, &key, state.ivec, state.ecount, &state.num);
}


int start_client(struct sockaddr_in ssh_server_address) {
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char *hello = "Hello from client";
    char buffer[BUFFER_LEN] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
    
    if (connect(sock, (struct sockaddr *)&ssh_server_address, sizeof(ssh_server_address)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }


    RAND_bytes(iv, AES_BLOCK_SIZE);
    if(!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Could not create random bytes.");
        exit(1);    
    }
	memcpy(buffer,iv,AES_BLOCK_SIZE);
	buffer[AES_BLOCK_SIZE]='\0';
	send(sock , buffer , strlen(buffer) , 0 );
	bzero(buffer,1024);
	// printf("%s\n", iv);


    while(1) {
        printf("Please enter any short text to send to server: \n");
        fgets(buffer, BUFFER_LEN, stdin);
        // To remove newline caught by fgets after user types the input
        if('\n' == buffer[strlen(buffer) - 1]) {
            buffer[strlen(buffer) - 1] = '\0';
        }
        char encrypted_buffer[AES_BLOCK_SIZE];
        bzero(encrypted_buffer, AES_BLOCK_SIZE);
        iencrypt(buffer, encrypted_buffer, strlen(buffer), (unsigned const char*)symmetric_key);
        send(sock , encrypted_buffer , strlen(encrypted_buffer) , 0 );
        printf("%s %s\n", "Encrypted message sent to server by client: ", encrypted_buffer);

        bzero(buffer, BUFFER_LEN);
        valread = read( sock , buffer, 1024);
        if (valread > 0) {
        	char decrypted_buffer[AES_BLOCK_SIZE];
        	bzero(decrypted_buffer, AES_BLOCK_SIZE);
			idecrypt(buffer, decrypted_buffer, strlen(buffer), (unsigned const char*)symmetric_key);
			printf("%s %s\n", "Decrypted message received from pbproxy server: ", decrypted_buffer);
        }
    }

    close(sock);
    return 0;
}

void start_server(struct sockaddr_in pbproxy_server_addr, struct sockaddr_in ssh_server_addr) {
    int server_fd, new_socket, valread, i;
    int ssh_server_sock = 0;
    int pbproxy_server_addrlen = sizeof(pbproxy_server_addr);
    char buffer[BUFFER_LEN] = {0};
    char *hello = "Hello from server";
    fd_set		open_sockets_set; 		/* set of open sockets */
    fd_set		waiting_sockets_set; 		/* set of sockets waiting to be read */
    int			dsize; 		/* size of file descriptors table */
    struct sockaddr_in	client_address; 
    /* calculate size of file descriptors table */
    dsize = getdtablesize();

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
      
    if (bind(server_fd, (struct sockaddr *)&pbproxy_server_addr, sizeof(pbproxy_server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    if ((ssh_server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        exit(EXIT_FAILURE);
    }
    
    if (connect(ssh_server_sock, (struct sockaddr *)&ssh_server_addr, sizeof(ssh_server_addr)) < 0) {
        printf("\nConnection Failed \n");
        exit(EXIT_FAILURE);
    }

    /* we innitialy have only one socket open,	*/
    /* to receive new incoming connections.	*/
    FD_ZERO(&open_sockets_set);
    FD_SET(server_fd, &open_sockets_set);

    while (1) {
    	waiting_sockets_set = open_sockets_set;
		// printf("Waiting for connections on socket fd:%i \n", server_fd);
		valread = select(dsize, &waiting_sockets_set, NULL, NULL, (struct timeval *)NULL);
		// printf("Someone waked the select %i\n", valread);

		if (FD_ISSET(server_fd, &waiting_sockets_set)) {
			/* accept the incoming connection */
			if ((new_socket = accept(server_fd, (struct sockaddr *)&client_address, (socklen_t*)&client_address)) < 0) {
	            perror("couldn't accept new connection.");
	            continue;
	        }
			/* add the new sockets to the set of open sockets */

	        // Client will send IV at start of connection
			bzero(buffer, BUFFER_LEN);
			valread = read(new_socket, buffer, BUFFER_LEN);
			if (valread < 0) 
				 perror("ERROR reading from socket");
			memcpy(iv, buffer, AES_BLOCK_SIZE);
			// printf("%s\n", iv);
			client_fd = new_socket;
			FD_SET(new_socket, &open_sockets_set);
			FD_SET(ssh_server_sock, &open_sockets_set);

			/* and loop again */
			continue;
		}

		/* check which sockets are ready for reading,	*/
		for (i = 0; i  < dsize; i++) {
			if (i != server_fd && FD_ISSET(i, &waiting_sockets_set)) {
				bzero(buffer, BUFFER_LEN);
				valread = read(i, buffer, BUFFER_LEN);
				/* if client closed the connection... */
				if (valread == 0) {
					/* close the socket */
					close(i);
					FD_CLR(i, &open_sockets_set);
				}
				/* if there was data to read */
				else {
					if (i == client_fd){
						char decrypted_buffer[AES_BLOCK_SIZE];
						bzero(decrypted_buffer, AES_BLOCK_SIZE);
				        idecrypt(buffer, decrypted_buffer, strlen(buffer), (unsigned const char*)symmetric_key);
				        send(ssh_server_sock , decrypted_buffer , strlen(decrypted_buffer) , 0 );
				        printf("%s %s\n", "Message sent to ssh server by pbproxy server: ", decrypted_buffer);
            			bzero(buffer, BUFFER_LEN);
					} else {
						char encrypted_buffer[AES_BLOCK_SIZE];
						bzero(encrypted_buffer, AES_BLOCK_SIZE);
				        iencrypt(buffer, encrypted_buffer, strlen(buffer), (unsigned const char*)symmetric_key);
				        send(client_fd , encrypted_buffer , strlen(encrypted_buffer) , 0 );
				        printf("%s %s\n", "Message sent to client after encrypting by pbproxy server: ", encrypted_buffer);
					}
				}
			}
		}
    }
}



int main(int argc, char *argv[]) {
	int opt;
	int is_server = 0;
	char* keyfilename = NULL;
	char* pbproxy_server_port = NULL;
	while ((opt = getopt (argc, argv, "l:k:")) != -1){
		switch (opt) {
			case 'l':
				is_server = 1;
				pbproxy_server_port = optarg;
				break;
			case 'k':
				keyfilename = optarg;
				break;
			default:
				perror("Incorrect or missing option arguments");
				exit(EXIT_FAILURE);
		}
	}

	FILE * keyFile;
	keyFile = fopen(keyfilename,"r");
	size_t length = 0;
	ssize_t read;
	char * line = NULL;
	if (keyFile == NULL) {
		exit(EXIT_FAILURE);
	}
	if ((read = getline(&line, &length, keyFile)) != -1) {
		symmetric_key = line;
	} else {
		symmetric_key = "1234567812345678";
	}

	printf("%s\n", symmetric_key);
	fclose(keyFile);

	struct sockaddr_in ssh_server_addr;
	bzero(&ssh_server_addr, sizeof(ssh_server_addr));

	char* host = argv[optind];
	int ssh_port = atoi(argv[optind+1]);
	struct hostent *ssh_host = gethostbyname(host);

	if (is_server) {
		
		if (ssh_host == NULL) {
	        fprintf(stderr,"ERROR, no such host\n");
	        exit(EXIT_FAILURE);
	    }

		struct sockaddr_in pbproxy_server_addr;
		bzero(&pbproxy_server_addr, sizeof(pbproxy_server_addr));

		pbproxy_server_addr.sin_family = AF_INET;
	    pbproxy_server_addr.sin_addr.s_addr = INADDR_ANY;
	    pbproxy_server_addr.sin_port = htons( atoi(pbproxy_server_port) );

	    ssh_server_addr.sin_family = AF_INET;
	    ssh_server_addr.sin_addr.s_addr = ((struct in_addr*)(ssh_host->h_addr))->s_addr;
	    ssh_server_addr.sin_port = htons(ssh_port);

		start_server(pbproxy_server_addr, ssh_server_addr);
	} else {

		ssh_server_addr.sin_family = AF_INET;
	    ssh_server_addr.sin_addr.s_addr = ((struct in_addr*)(ssh_host->h_addr))->s_addr;
	    ssh_server_addr.sin_port = htons(ssh_port);
	    start_client(ssh_server_addr);

	}

	return 0;
}