#ifndef _REQUESTS_
#define _REQUESTS_

char *compute_request(const char *packet_type, const char *host, const char *url, char *jwt_token,
                        const char *content_type, char *data, char **cookies, int cookies_count);

char *send_post_packet(const char *url, char *payload, char *jwt_token,
                       char **cookies, int cookies_count);

char *send_get_packet(const char *url, char *jwt_token, char *cookies, int cookies_count);
#endif
