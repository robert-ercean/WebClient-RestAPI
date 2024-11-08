#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include <fstream>
#include "json.hpp"
#include <iostream>

using namespace std;
using json = nlohmann::json;

#define SV_ADDR "34.246.184.49"
#define SV_PORT 8080
#define JSON_TYPE "application/json"

#define POST_TYPE "POST"
#define DELETE_TYPE "DELETE"
#define GET_TYPE "GET"

#define REGISTER_URL "/api/v1/tema/auth/register"
#define LOGIN_URL "/api/v1/tema/auth/login"
#define LIBRARY_URL "/api/v1/tema/library/access"
#define GET_BOOKS_URL "/api/v1/tema/library/books"
#define ADD_BOOK_URL "/api/v1/tema/library/books"
#define LOGOUT_URL "/api/v1/tema/auth/logout"
#define GET_BOOK_ID_URL_PREFIX "/api/v1/tema/library/books/"
#define DELETE_URL "/api/v1/tema/library/books/"

#define LOGIN "login"
#define REGISTER "register"
#define ENTER_LIBRARY "enter_library"
#define GET_BOOKS "get_books"
#define ADD_BOOK "add_book"
#define LOGOUT "logout"
#define EXIT "exit"
#define GET_BOOK_ID "get_book"
#define DELETE_BOOK "delete_book"

/* Status codes */
#define CREATED 201
#define RESOURCE_NOT_FOUND 404
#define BAD_REQUEST 400
#define OK 200
#define UNAUTHORIZED 401

/* Maximum number of cookies (char arrays) a client can hold */
#define COOKIE_MAX_BACKLOG 128

/* Determines the offset of the status code inside the server's response
 * extract one byte for the null terminator inside the string 
 * literal, since it is not present inside the packet */
#define STATUS_CODE_RESPONSE_OFFSET (sizeof("HTTP/1.1 ") - 1)
#define SET_COOKIES_HEADER_PREFIX "Set-Cookie: "

#define CLEAR_BUFFER() cin.ignore(numeric_limits<streamsize>::max(), '\n')
#define CHECK_STRING_FOR_SPACE(str, flag) \
    if (has_space(str)) flag = false

char *jwt_token;
char **session_cookies;
char cookie_count;

bool has_space(string s) {
    return std::find_if(s.begin(), s.end(), ::isspace) != s.end();
}

string extract_server_err_response(char *sv_packet) {
    char *response = basic_extract_json_response(sv_packet);
    if (!response) {
        fprintf(stderr, "basic_extract_json_response failed in server's error response!\n");
        return NULL;
    }
    json json_response = json::parse(response);
    if (json_response.contains("error")) {
        return json_response["error"].get<string>();
    } else {
        return "Key \"error\" not found in the JSON object!";
    }
}

/* Scans from STDIN the credentials, stores them into a json object
 * then serializes that object to a char *string 
 * @return the serialized credentials */
char *scan_credentials_to_json() {
    string username, password;
    json credentials;
    bool valid = true;
    
    cout << "username=";
    getline(cin, username);
    cout << endl;
    CHECK_STRING_FOR_SPACE(username, valid);
    cout << "password=";
    getline(cin, password);

    /* One of the string has spaces */
    if (!valid)
        return NULL;

    credentials["username"] = username;
    credentials["password"] = password;

    /* Convert json object to a string object */
    string serialized_credentials = credentials.dump();
    /* Convert string object to char* representation */
    const char *str = serialized_credentials.c_str();
    char *serialized_credentials_c_str = (char *)malloc(sizeof(char) * (strlen(str) + 1));
    memcpy(serialized_credentials_c_str, str, strlen(str) + 1);
    return serialized_credentials_c_str;
}

/* Extracts the session cookies from the server's response packet 
 * inside the global session cookies array and sets the the appropiate
 * cookie count number */
void extract_cookies(char *sv_packet) {
    if (session_cookies && cookie_count != 0) {
       for (int i = 0; i < cookie_count; i++)
            free(session_cookies[i]);
        session_cookies = 0;
        session_cookies = NULL;
    }
    size_t count = 0;
    const char *cookies_header_prefix = SET_COOKIES_HEADER_PREFIX;
    char *response = sv_packet;
    while ((response = strstr(response, cookies_header_prefix)) != NULL) {
        response += strlen(SET_COOKIES_HEADER_PREFIX);
        char *cookie_value_end = strstr(response, "\r\n");
        size_t cookie_value_length = cookie_value_end - response;
        /* Don't forget to add the null terminator since we'll call strlen() on these
         * arrays later */
        session_cookies = (char **)malloc(sizeof(char *) * COOKIE_MAX_BACKLOG);
        session_cookies[count] = (char *)malloc(sizeof(char) * (cookie_value_length + 1));
        memcpy(session_cookies[count], response, cookie_value_length);
        if (!session_cookies[count]) {
            fprintf(stderr, "malloc in session_cookies failed!\n");
            exit(EXIT_FAILURE);
        }
        session_cookies[count][cookie_value_length] = '\0';
        count++;
    }
    cookie_count = count;
}

/* Extracts the bearer auth token from the server's response, allocs memory
 * and stores in the global variable */
void extract_jwt_token(char *sv_packet) {
    char *response = basic_extract_json_response(sv_packet);
    if (!response) {
        fprintf(stderr, "basic_extract_json_response failed in jwt_token!\n");
        return;
    }
    json json_response = json::parse(response);
    if (json_response.contains("token")) {
        string token_str = json_response["token"].get<string>();
        jwt_token = (char *)malloc(sizeof(*jwt_token) * token_str.length() + 1);
        memcpy(jwt_token, token_str.c_str(), token_str.length());
        jwt_token[token_str.length()] = '\0';
    } else {
        fprintf(stderr, "Key \"token\" not found in the JSON object!\n");
    }
}

/* Extracts the books from the server's response in a json format
 * then prints them */
void extract_and_print_books(char *sv_packet) {
    char *response = basic_extract_json_array_response(sv_packet);
    if (!response) {
        fprintf(stderr, "basic_extract_json_array_response failed in extract_books!\n");
        exit(EXIT_FAILURE);
    }
    json books_json = json::parse(response);
    for (auto &book : books_json) {
        cout << book.dump(4) << endl;
    }
}

/* Extracts the book from the server's response in a json format
 * then prints it */
void extract_and_print_single_book(char *sv_packet) {
    // cout << sv_packet << endl;
    char *response = basic_extract_json_response(sv_packet);
    if (!response) {
        fprintf(stderr, "basic_extract_response failed in extract_books!\n");
        exit(EXIT_FAILURE);
    }
    json book_json = json::parse(response);
    cout << book_json.dump(4) << endl;
}

void handle_login() {
    char *serialized_creds = scan_credentials_to_json();
    if (!serialized_creds) {
        fprintf(stderr, "ERROR: Bad credentials format!\n");
        return;
    }
    char *sv_packet = send_post_packet(LOGIN_URL, serialized_creds, NULL, NULL, 0);

    char *status_code = sv_packet + STATUS_CODE_RESPONSE_OFFSET;
    int status_code_int = atoi(status_code);

    switch(status_code_int) {
        case BAD_REQUEST: {
            string sv_response = extract_server_err_response(sv_packet);
            cout << "ERROR: Bad credentials! / " << sv_response << endl;
            break;
        }
        case RESOURCE_NOT_FOUND: {
            cout << "ERROR: RESOURCE NOT FOUND, maybe broken URL?" << endl;
            break;
        }
        case OK: {
            cout << "SUCCESS: Logged in!, extracting cookies now!" << endl;
            extract_cookies(sv_packet);
            break;
        }
        default: {
            cout << "ERROR: Unknown return code: " << status_code_int << endl;
            break;
        }
    }
}

/* Opens a socket to the server, sends a packet of type POST, and waits for the server's response 
 * @return the server's response packet */
char *send_post_packet(const char *url, char *payload, char *jwt_token,
                       char **cookies, int cookies_count) {
    /* Send the packet to server */
    int sockfd = open_connection(SV_ADDR, SV_PORT, AF_INET, SOCK_STREAM, 0);
    char *message = compute_request(POST_TYPE, SV_ADDR, url, jwt_token, JSON_TYPE, payload, cookies, cookies_count);
    send_to_server(sockfd, message);

    /* Get the server's response */
    char *sv_packet = receive_from_server(sockfd);
    close_connection(sockfd);
    return sv_packet;
}

/* Opens a socket to the server, sends a packet of type GET, and waits for the server's response 
 * @return the server's response packet */
char *send_get_packet(const char *url, char *jwt_token, char **cookies, int cookies_count) {
    int sockfd = open_connection(SV_ADDR, SV_PORT, AF_INET, SOCK_STREAM, 0);
    char *message = compute_request(GET_TYPE, SV_ADDR, url, jwt_token, NULL, NULL, 
                                    session_cookies, cookie_count);

    send_to_server(sockfd, message);

    char *sv_packet = receive_from_server(sockfd);
    close_connection(sockfd);
    return sv_packet;
}

void handle_register() {
    char *serialized_creds = scan_credentials_to_json();
    if (!serialized_creds) {
        fprintf(stderr, "ERROR: Bad credentials format!\n");
        return;
    }
    printf("%s\n", serialized_creds);
    char *sv_packet = send_post_packet(REGISTER_URL, serialized_creds, NULL, NULL, 0);

    /* Parse the status code */
    char *status_code = sv_packet + STATUS_CODE_RESPONSE_OFFSET;
    int status_code_int = atoi(status_code);


    switch(status_code_int) {
        case CREATED: {
            cout << "SUCCESS: Account registered!" << endl;
            break;
        }
        case BAD_REQUEST: {
            string sv_response = extract_server_err_response(sv_packet);
            cout << "ERROR: BAD REQUEST! / Message: " << sv_response << endl;
            break;
        }
        case RESOURCE_NOT_FOUND: {
            cout << "ERROR: RESOURCE NOT FOUND, maybe broken URL?" << endl;
            break;
        }
        default: {
            cout << "ERROR: Unknown return code: " << status_code_int << endl;
            break;
        }
    }
}

void handle_enter_library() {
    if (!session_cookies) {
        fprintf(stderr, "ERROR: Not logged-in, in enter_library!\n");
        return;
    }
    char *sv_packet = send_get_packet(LIBRARY_URL, NULL, session_cookies, cookie_count);
    char *status_code = sv_packet + STATUS_CODE_RESPONSE_OFFSET;
    int status_code_int = atoi(status_code);

    switch(status_code_int) {
        case OK: {
            extract_jwt_token(sv_packet);
            cout << "SUCCESS: Authorized to enter the library!" << endl;
            break;
        }
        case BAD_REQUEST: {
            string sv_response = extract_server_err_response(sv_packet);
            cout << "ERROR: BAD REQUEST! / Message: " << sv_response << endl;
            break;
        }
        case RESOURCE_NOT_FOUND: {
            cout << "ERROR: RESOURCE NOT FOUND, maybe broken URL?" << endl;
            break;
        }
        default: {
            cout << "ERROR: Unknown return code: " << status_code_int << endl;
            break;
        }
    }
}

void handle_get_books() {
    if (!session_cookies) {
        fprintf(stderr, "ERROR: Not logged-in, in get_bookds!\n");
        return;
    }
    if (!jwt_token) {
        fprintf(stderr, "ERROR: Not autorized to do this!\n");
        return;
    }

    char *sv_packet = send_get_packet(GET_BOOKS_URL, jwt_token, session_cookies, cookie_count);
    char *status_code = sv_packet + STATUS_CODE_RESPONSE_OFFSET;
    int status_code_int = atoi(status_code);

    switch(status_code_int) {
        case OK: {
            cout << "SUCCESS: Got the books: " << endl;
            extract_and_print_books(sv_packet);
            break;
        }
        case UNAUTHORIZED: {
            cout << "ERROR: UNAUTHORIZED! / Message: ";
            string sv_response = extract_server_err_response(sv_packet);
            cout << sv_response << endl;
            break;
        }
        case BAD_REQUEST: {
            cout << "ERROR: BAD REQUEST! / Message: ";
            string sv_response = extract_server_err_response(sv_packet);
            cout << sv_response << endl;
            break;
        }
        case RESOURCE_NOT_FOUND: {
            cout << "ERROR: RESOURCE NOT FOUND, maybe broken URL?" << endl;
            break;
        }
        default: {
            cout << "ERROR: Unknown return code: " << status_code_int << endl;
            break;
        }
    }
}

bool has_digits(string &s) {
    return std::find_if(s.begin(), s.end(), ::isdigit) != s.end();
}

/* Checks if a string is a valid representation of a number */
bool is_valid_number(const std::string &s) {
    /* Number can't start with a 0 */
    if (s.empty() || s[0] == '0') {
        return false;
    }
    return !s.empty() && std::all_of(s.begin(), s.end(), ::isdigit);
}

void is_book_field_valid(string &str, bool &valid) {
    if (str.empty() || has_digits(str))
        valid = false;
}

/* Responsible for scanning the book, check fields validity and 
 * deserializing the book string in JSON format, then serializing 
 * @return the serialized book info ready to be send to the server */
char *scan_book_json_then_serialize() {
    string title, author, genre, publisher;
    bool valid = true;

    cout << "title=";
    getline(cin, title);
    cout << endl;
    is_book_field_valid(title, valid);

    cout << "author=";
    getline(cin, author);
    cout << endl;
    is_book_field_valid(author, valid);

    cout << "genre=";
    getline(cin, genre);
    cout << endl;
    is_book_field_valid(genre, valid);
    
    cout << "publisher=";
    getline(cin, publisher);
    cout << endl;
    is_book_field_valid(publisher, valid);
    
    /* Check page_count validity */
    string page_count_str;
    int page_count;
    cout << "page_count=";
    getline(cin, page_count_str);
    
    if (is_valid_number(page_count_str)) {
        page_count = stoi(page_count_str);
    } else {
        cout << "Page count must be a number!" << endl;
        valid = false;
    }

    if (!valid)
        return NULL;

    json book_json;
    /* Add the fields to the JSON object */
    book_json["title"] = title;
    book_json["author"] = author;
    book_json["publisher"] = publisher;
    book_json["genre"] = genre;
    book_json["page_count"] = page_count;

    /* Serialize the JSON book obj */
    string book_serialized = book_json.dump();
    char *book_c_str = (char *)malloc(sizeof(char) * (book_serialized.length() + 1));
    memcpy(book_c_str, book_serialized.c_str(), book_serialized.length() + 1);

    return book_c_str;
}

void handle_add_book() {
    if (!session_cookies) {
        fprintf(stderr, "ERROR: Not logged-in, in add_book!\n");
        return;
    }

    if (!jwt_token) {
        fprintf(stderr, "ERROR: Not authorized to do this!\n");
        return;
    }
    char *book = scan_book_json_then_serialize();
    if (!book) {
        fprintf(stderr, "ERROR: Wrong book info formatting!\n");
        return;
    }
    char *sv_packet = send_post_packet(ADD_BOOK_URL, book, jwt_token, session_cookies, cookie_count);

    char *status_code = sv_packet + STATUS_CODE_RESPONSE_OFFSET;
    int status_code_int = atoi(status_code);

    switch(status_code_int) {
        case UNAUTHORIZED: {
            cout << "ERROR: Not Authorized !" << endl;
            string sv_response = extract_server_err_response(sv_packet);
            break;
        }
        case BAD_REQUEST: {
            cout << "ERROR: Bad credentials! / "<< endl;
            string sv_response = extract_server_err_response(sv_packet);
            break;
        }
            cout << "ERROR: RESOURCE NOT FOUND, maybe broken URL?" << endl;
        case RESOURCE_NOT_FOUND: {
            break;
        }
        case OK: {
            cout << "SUCCESS: Book added!" << endl;
            break;
        }
        default: {
            cout << "ERROR: Unknown return code: " << status_code_int << endl;
            break;
        }
    }
}

void handle_logout() {
    if (!session_cookies) {
        fprintf(stderr, "ERROR: Not logged-in, in logout!\n");
        return;
    }

    char *sv_packet = send_get_packet(LOGOUT_URL, jwt_token, session_cookies, cookie_count);
    char *status_code = sv_packet + STATUS_CODE_RESPONSE_OFFSET;
    int status_code_int = atoi(status_code);

    switch(status_code_int) {
        case OK: {
            cout << "SUCCESS: Logged-out!" << endl;
            break;
        }
        case UNAUTHORIZED: {
            string sv_response = extract_server_err_response(sv_packet);
            cout << "ERROR: Not Authorized, maybe not logged-in !" << sv_response << endl;
            break;
        }
        case BAD_REQUEST: {
            string sv_response = extract_server_err_response(sv_packet);
            cout << "ERROR: Bad request! / " << sv_response << endl;
            break;
        }
        case RESOURCE_NOT_FOUND: {
            cout << "ERROR: RESOURCE NOT FOUND, maybe broken URL?" << endl;
            break;
        }
        default: {
            cout << "ERROR: Unknown return code: " << status_code_int << endl;
            break;
        }
    }
    /* Clear the session cookies and the jwt token */
    for (int i = 0; i < cookie_count; i++) {
        free(session_cookies[i]);
    }
    free(session_cookies);
    free(jwt_token);
    session_cookies = NULL;
    jwt_token = NULL;
    cookie_count = 0;
}

/* Opens a socket to the server, sends a packet of type DELETE, and waits for the server's response 
 * @return the server's response packet */
char *send_delete_packet(const char *url, char *jwt_token, char **cookies, int cookies_count) {
    int sockfd = open_connection(SV_ADDR, SV_PORT, AF_INET, SOCK_STREAM, 0);
    char *message = compute_request(DELETE_TYPE, SV_ADDR, url, jwt_token, NULL, NULL, session_cookies, cookie_count);

    send_to_server(sockfd, message);

    char *sv_packet = receive_from_server(sockfd);
    close_connection(sockfd);
    return sv_packet;
}

void handle_get_book_id() {
    if (!session_cookies) {
        fprintf(stderr, "ERROR: Not logged-in, in get_book_id!\n");
        return;
    }

    if (!jwt_token) {
        fprintf(stderr, "ERROR: Not authorized to do this!\n");
        return;
    }
    cout << "id=";
    /* Build specific Book ID URL */
    string book_id_url(GET_BOOK_ID_URL_PREFIX);
    string id;
    getline(cin, id);
    book_id_url.append(id);
    cout << endl;

    char *sv_packet = send_get_packet(book_id_url.c_str(), jwt_token, session_cookies, cookie_count);
    char *status_code = sv_packet + STATUS_CODE_RESPONSE_OFFSET;
    int status_code_int = atoi(status_code);

    switch(status_code_int) {
        case OK: {
            cout << "SUCCESS: Got the specific book :" << endl;
            extract_and_print_single_book(sv_packet);
            break;
        }
        case UNAUTHORIZED: {
            cout << "ERROR: UNAUTHORIZED! / Message: ";
            string sv_response = extract_server_err_response(sv_packet);
            cout << sv_response << endl;
            break;
        }
        case BAD_REQUEST: {
            cout << "ERROR: BAD REQUEST! / Message: ";
            string sv_response = extract_server_err_response(sv_packet);
            cout << sv_response << endl;
            break;
        }
        case RESOURCE_NOT_FOUND: {
            cout << "ERROR: RESOURCE NOT FOUND, maybe broken URL?" << endl;
            break;
        }
        default: {
            cout << "ERROR: Unknown return code: " << status_code_int << endl;
            break;
        }
    }    
}

void handle_delete_book() {
    if (!session_cookies) {
        fprintf(stderr, "ERROR: Not logged-in, in delete_book!\n");
        return;
    }

    if (!jwt_token) {
        fprintf(stderr, "ERROR: Not authorized to do this!\n");
        return;
    }
    cout << "id=";
    /* Build specific Book ID URL */
    string book_id_url(GET_BOOK_ID_URL_PREFIX);
    string id;
    getline(cin, id);
    book_id_url.append(id);
    cout << endl;

    char *sv_packet = send_delete_packet(book_id_url.c_str(), jwt_token, session_cookies, cookie_count);
    char *status_code = sv_packet + STATUS_CODE_RESPONSE_OFFSET;
    int status_code_int = atoi(status_code);

    switch(status_code_int) {
        case OK: {
            cout << "SUCCESS: Deleted book number [" << id << "]" << endl;
            break;
        }
        case UNAUTHORIZED: {
            cout << "ERROR: UNAUTHORIZED! / Message: ";
            string sv_response = extract_server_err_response(sv_packet);
            cout << sv_response << endl;
            break;
        }
        case BAD_REQUEST: {
            cout << "ERROR: BAD REQUEST! / Message: ";
            string sv_response = extract_server_err_response(sv_packet);
            cout << sv_response << endl;
            break;
        }
        case RESOURCE_NOT_FOUND: {
            cout << "ERROR: RESOURCE NOT FOUND, maybe broken URL?" << endl;
            break;
        }
        default: {
            cout << "ERROR: Unknown return code: " << status_code_int << endl;
            break;
        }
    }    
}

int main(int argc, char *argv[])
{
    string command;
    jwt_token = NULL;
    session_cookies = NULL;
    cookie_count = 0;

    while(true) {
        getline(cin, command);
        if (strncmp(command.c_str(), LOGIN, 5) == 0) {
            handle_login();
        } else if (strncmp(command.c_str(), REGISTER, 8) == 0) {
            handle_register();
        } else if(strncmp(command.c_str(), ENTER_LIBRARY, 13) == 0) {
            handle_enter_library();
        } else if(strncmp(command.c_str(), GET_BOOKS, 9) == 0) {
            handle_get_books();
        } else if(strncmp(command.c_str(), ADD_BOOK, 8) == 0) {
            handle_add_book();
        } else if(strncmp(command.c_str(), LOGOUT, 6) == 0) {
            handle_logout();
        } else if (strncmp(command.c_str(), GET_BOOK_ID, 8) == 0) {
            handle_get_book_id();
        } else if (strncmp(command.c_str(), DELETE_BOOK, 11) == 0) {
            handle_delete_book();
        } else if (strncmp(command.c_str(), EXIT, 4) == 0) {
            cout << "SUCCESS: Closing program!" << endl;
            exit(EXIT_SUCCESS);
        } else {
            cout << "ERROR: Unknown command" << endl;
        }
    }
    return 0;
}
