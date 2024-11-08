#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"

#define MAX_DATA_ARRAYS 1000
#define CLEAR_BUFFER(buff, size) memset(buff, 0, size) 

/* There can exist multiple cookie lines extracted from the server's response, so
 * build the cookie buffer accordingly */
void add_cookies_in_buffer(char **cookies, int cookies_count, char *buff) {
    sprintf(buff, "Cookie: ");
    for (int i = 0; i < cookies_count - 1; i++) {
        strcat(buff, cookies[i]);
        strcat(buff, ";");
    }
    strcat(buff, cookies[cookies_count - 1]);
}

/* Builds the packet to be send to the server, gets two types of packet types
 * GET, DELETE and POST
 * Included the jwt_token parameter, as it was not present in the lab skel
 * also remoed the query params since they were of no use in this assignment 
 * @return the formatted packet ready to be send to the server */
char *compute_request(const char *packet_type, const char *host, const char *url, char *jwt_token,
                        const char *content_type, char *data, char **cookies, int cookies_count)
{
    char *message = (char *)calloc(BUFLEN, sizeof(char));
    char *line = (char *)calloc(LINELEN, sizeof(char));

    // Step 1: write the method name, URL and protocol type
    sprintf(line, "%s %s HTTP/1.1", packet_type, url);
    compute_message(message, line);
    
    /* add the host */
    CLEAR_BUFFER(line, LINELEN);
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    /* Add content type header */
    if (content_type) {
        CLEAR_BUFFER(line, LINELEN);
        sprintf(line, "Content-Type: %s", content_type);
        compute_message(message, line);
        /* Add content length header */
        CLEAR_BUFFER(line, LINELEN);
        size_t content_length = strlen(data);
        sprintf(line, "Content-Length: %ld", content_length);
        compute_message(message, line);
    }
    /* Add the token parameter if present */
    if (jwt_token != NULL) {
        CLEAR_BUFFER(line, LINELEN);
        sprintf(line, "Authorization: Bearer %s", jwt_token);
        compute_message(message, line);
    }

    /* Add cookies if present */
    if (cookies != NULL) {
        CLEAR_BUFFER(line, LINELEN);
        add_cookies_in_buffer(cookies, cookies_count, line);
        compute_message(message, line);
    }
    strcat(message, "\r\n");

    if (data) {
        /* Add the actual data payload */
        strcat(message, data);
    }

    free(line);
    return message;
}
