/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 1998 Steven Young <sdyoung@miranda.org>
 * Copyright (C) 1999-2005 Robert James Kaes <rjkaes@users.sourceforge.net>
 * Copyright (C) 2000 Chris Lightfoot <chris@ex-parrot.com>
 * Copyright (C) 2002 Petr Lampa <lampa@fit.vutbr.cz>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* This is where all the work in tinyproxy is actually done. Incoming
 * connections have a new child created for them. The child then
 * processes the headers from the client, the response from the server,
 * and then relays the bytes between the two.
 */

#include "main.h"

#include "acl.h"
#include "anonymous.h"
#include "buffer.h"
#include "conns.h"
#include "filter.h"
#include "hashmap.h"
#include "heap.h"
#include "html-error.h"
#include "log.h"
#include "network.h"
#include "reqs.h"
#include "sock.h"
#include "stats.h"
#include "text.h"
#include "utils.h"
#include "vector.h"
#include "reverse-proxy.h"
#include "transparent-proxy.h"
#include "upstream.h"
#include "connect-ports.h"
#include "conf.h"

/*
 * Maximum length of a HTTP line
 */
#define HTTP_LINE_LENGTH (MAXBUFFSIZE / 6)

/*
 * Macro to help test if the Upstream proxy supported is compiled in and
 * enabled.
 */
#ifdef UPSTREAM_SUPPORT
#  define UPSTREAM_CONFIGURED() (config.upstream_list != NULL)
#  define UPSTREAM_HOST(host) upstream_get(host, config.upstream_list)
#else
#  define UPSTREAM_CONFIGURED() (0)
#  define UPSTREAM_HOST(host) (NULL)
#endif

/*
 * Codify the test for the carriage return and new line characters.
 */
#define CHECK_CRLF(header, len)                                 \
  (((len) == 1 && header[0] == '\n') ||                         \
   ((len) == 2 && header[0] == '\r' && header[1] == '\n'))

/*
 * Codify the test for header fields folded over multiple lines.
 */
#define CHECK_LWS(header, len)                                  \
  ((len) > 0 && (header[0] == ' ' || header[0] == '\t'))

/*
 * Read in the first line from the client (the request line for HTTP
 * connections. The request line is allocated from the heap, but it must
 * be freed in another function.
 */
static int read_request_line (struct conn_s *connptr)
{
        ssize_t len;

retry:
        len = readline (connptr->client_fd, &connptr->request_line);
        if (len <= 0) {
                log_message (LOG_ERR,
                             "read_request_line: Client (file descriptor: %d) "
                             "closed socket before read.", connptr->client_fd);

                return -1;
        }

        /*
         * Strip the new line and carriage return from the string.
         */
        if (chomp (connptr->request_line, len) == len) {
                /*
                 * If the number of characters removed is the same as the
                 * length then it was a blank line. Free the buffer and
                 * try again (since we're looking for a request line.)
                 */
                safefree (connptr->request_line);
                goto retry;
        }

        log_message (LOG_CONN, "Request (file descriptor %d): %s",
                     connptr->client_fd, connptr->request_line);

        return 0;
}

/*
 * Free all the memory allocated in a request.
 */
static void free_request_struct (struct request_s *request)
{
        if (!request)
                return;

        safefree (request->method);
        safefree (request->protocol);

        if (request->host)
                safefree (request->host);
        if (request->path)
                safefree (request->path);

        safefree (request);
}

/*
 * Take a host string and if there is a username/password part, strip
 * it off.
 */
static void strip_username_password (char *host)
{
        char *p;

        assert (host);
        assert (strlen (host) > 0);

        if ((p = strchr (host, '@')) == NULL)
                return;

        /*
         * Move the pointer past the "@" and then copy from that point
         * until the NUL to the beginning of the host buffer.
         */
        p++;
        while (*p)
                *host++ = *p++;
        *host = '\0';
}

/*
 * Take a host string and if there is a port part, strip
 * it off and set proper port variable i.e. for www.host.com:8001
 */
static int strip_return_port (char *host)
{
        char *ptr1;
        char *ptr2;
        int port;

        ptr1 = strrchr (host, ':');
        if (ptr1 == NULL)
                return 0;

        /* Check for IPv6 style literals */
        ptr2 = strchr (ptr1, ']');
        if (ptr2 != NULL)
                return 0;

        *ptr1++ = '\0';
        if (sscanf (ptr1, "%d", &port) != 1)    /* one conversion required */
                return 0;
        return port;
}

/*
 * Pull the information out of the URL line.  This will handle both HTTP
 * and FTP (proxied) URLs.
 */
static int extract_http_url (const char *url, struct request_s *request)
{
        char *p;
        int len;
        int port;

        /* Split the URL on the slash to separate host from path */
        p = strchr (url, '/');
        if (p != NULL) {
                len = p - url;
                request->host = (char *) safemalloc (len + 1);
                memcpy (request->host, url, len);
                request->host[len] = '\0';
                request->path = safestrdup (p);
        } else {
                request->host = safestrdup (url);
                request->path = safestrdup ("/");
        }

        if (!request->host || !request->path)
                goto ERROR_EXIT;

        /* Remove the username/password if they're present */
        strip_username_password (request->host);

        /* Find a proper port in www.site.com:8001 URLs */
        port = strip_return_port (request->host);
        request->port = (port != 0) ? port : HTTP_PORT;

        /* Remove any surrounding '[' and ']' from IPv6 literals */
        p = strrchr (request->host, ']');
        if (p && (*(request->host) == '[')) {
                request->host++;
                *p = '\0';
        }

        return 0;

ERROR_EXIT:
        if (request->host)
                safefree (request->host);
        if (request->path)
                safefree (request->path);

        return -1;
}

/*
 * Extract the URL from a SSL connection.
 */
static int extract_ssl_url (const char *url, struct request_s *request)
{
        request->host = (char *) safemalloc (strlen (url) + 1);
        if (!request->host)
                return -1;

        if (sscanf (url, "%[^:]:%hu", request->host, &request->port) == 2) ;
        else if (sscanf (url, "%s", request->host) == 1)
                request->port = HTTP_PORT_SSL;
        else {
                log_message (LOG_ERR, "extract_ssl_url: Can't parse URL.");

                safefree (request->host);
                return -1;
        }

        /* Remove the username/password if they're present */
        strip_username_password (request->host);

        return 0;
}

/*
 * Create a connection for HTTP connections.
 */
static int
establish_http_connection (struct conn_s *connptr, struct request_s *request)
{
        char portbuff[7];
        char dst[sizeof(struct in6_addr)];

        /* Build a port string if it's not a standard port */
        if (request->port != HTTP_PORT && request->port != HTTP_PORT_SSL)
                snprintf (portbuff, 7, ":%u", request->port);
        else
                portbuff[0] = '\0';

        if (inet_pton(AF_INET6, request->host, dst) > 0) {
                /* host is an IPv6 address literal, so surround it with
                 * [] */
                return write_message (connptr->server_fd,
                                      "%s %s HTTP/1.0\r\n"
                                      "Host: [%s]%s\r\n"
                                      "Connection: close\r\n",
                                      request->method, request->path,
                                      request->host, portbuff);
        } else {
                return write_message (connptr->server_fd,
                                      "%s %s HTTP/1.0\r\n"
                                      "Host: %s%s\r\n"
                                      "Connection: close\r\n",
                                      request->method, request->path,
                                      request->host, portbuff);
        }
}

/*
 * These two defines are for the SSL tunnelling.
 */
#define SSL_CONNECTION_RESPONSE "HTTP/1.0 200 Connection established"
#define PROXY_AGENT "Proxy-agent: " PACKAGE "/" VERSION

/*
 * Send the appropriate response to the client to establish a SSL
 * connection.
 */
static int send_ssl_response (struct conn_s *connptr)
{
        return write_message (connptr->client_fd,
                              "%s\r\n"
                              "%s\r\n"
                              "\r\n", SSL_CONNECTION_RESPONSE, PROXY_AGENT);
}

/*
 * Break the request line apart and figure out where to connect and
 * build a new request line. Finally connect to the remote server.
 */
static struct request_s *process_request (struct conn_s *connptr,
                                          hashmap_t hashofheaders)
{
        char *url;
        struct request_s *request;
        int ret;
        size_t request_len;

        /* NULL out all the fields so frees don't cause segfaults. */
        request =
            (struct request_s *) safecalloc (1, sizeof (struct request_s));
        if (!request)
                return NULL;

        request_len = strlen (connptr->request_line) + 1;

        request->method = (char *) safemalloc (request_len);
        url = (char *) safemalloc (request_len);
        request->protocol = (char *) safemalloc (request_len);

        if (!request->method || !url || !request->protocol) {
                goto fail;
        }

        ret = sscanf (connptr->request_line, "%[^ ] %[^ ] %[^ ]",
                      request->method, url, request->protocol);
        if (ret == 2 && !strcasecmp (request->method, "GET")) {
                request->protocol[0] = 0;

                /* Indicate that this is a HTTP/0.9 GET request */
                connptr->protocol.major = 0;
                connptr->protocol.minor = 9;
        } else if (ret == 3 && !strncasecmp (request->protocol, "HTTP/", 5)) {
                /*
                 * Break apart the protocol and update the connection
                 * structure.
                 */
                ret = sscanf (request->protocol + 5, "%u.%u",
                              &connptr->protocol.major,
                              &connptr->protocol.minor);

                /*
                 * If the conversion doesn't succeed, drop down below and
                 * send the error to the user.
                 */
                if (ret != 2)
                        goto BAD_REQUEST_ERROR;
        } else {
BAD_REQUEST_ERROR:
                log_message (LOG_ERR,
                             "process_request: Bad Request on file descriptor %d",
                             connptr->client_fd);
                indicate_http_error (connptr, 400, "Bad Request",
                                     "detail", "Request has an invalid format",
                                     "url", url, NULL);
                goto fail;
        }

        if (!url) {
                log_message (LOG_ERR,
                             "process_request: Null URL on file descriptor %d",
                             connptr->client_fd);
                indicate_http_error (connptr, 400, "Bad Request",
                                     "detail", "Request has an empty URL",
                                     "url", url, NULL);
                goto fail;
        }
#ifdef REVERSE_SUPPORT
        if (config.reversepath_list != NULL) {
                /*
                 * Rewrite the URL based on the reverse path.  After calling
                 * reverse_rewrite_url "url" can be freed since we either
                 * have the newly rewritten URL, or something failed and
                 * we'll be closing anyway.
                 */
                char *reverse_url;

                reverse_url = reverse_rewrite_url (connptr, hashofheaders, url);

                if (!reverse_url) {
                        goto fail;
                }

                safefree (url);
                url = reverse_url;
        }
#endif

        if (strncasecmp (url, "http://", 7) == 0
            || (UPSTREAM_CONFIGURED () && strncasecmp (url, "ftp://", 6) == 0))
        {
                char *skipped_type = strstr (url, "//") + 2;

                if (extract_http_url (skipped_type, request) < 0) {
                        indicate_http_error (connptr, 400, "Bad Request",
                                             "detail", "Could not parse URL",
                                             "url", url, NULL);
                        goto fail;
                }
        } else if (strcmp (request->method, "CONNECT") == 0) {
                if (extract_ssl_url (url, request) < 0) {
                        indicate_http_error (connptr, 400, "Bad Request",
                                             "detail", "Could not parse URL",
                                             "url", url, NULL);
                        goto fail;
                }

                /* Verify that the port in the CONNECT method is allowed */
                if (!check_allowed_connect_ports (request->port,
                                                  config.connect_ports))
                {
                        indicate_http_error (connptr, 403, "Access violation",
                                             "detail",
                                             "The CONNECT method not allowed "
                                             "with the port you tried to use.",
                                             "url", url, NULL);
                        log_message (LOG_INFO,
                                     "Refused CONNECT method on port %d",
                                     request->port);
                        goto fail;
                }

                connptr->connect_method = TRUE;
        } else {
#ifdef TRANSPARENT_PROXY
                if (!do_transparent_proxy
                    (connptr, hashofheaders, request, &config, &url)) {
                        goto fail;
                }
#else
                indicate_http_error (connptr, 501, "Not Implemented",
                                     "detail",
                                     "Unknown method or unsupported protocol.",
                                     "url", url, NULL);
                log_message (LOG_INFO, "Unknown method (%s) or protocol (%s)",
                             request->method, url);
                goto fail;
#endif
        }

#ifdef FILTER_ENABLE
        /*
         * Filter restricted domains/urls
         */
        if (config.filter) {
                if (config.filter_url)
                        ret = filter_url (url);
                else
                        ret = filter_domain (request->host);

                if (ret) {
                        update_stats (STAT_DENIED);

                        if (config.filter_url)
                                log_message (LOG_NOTICE,
                                             "Proxying refused on filtered url \"%s\"",
                                             url);
                        else
                                log_message (LOG_NOTICE,
                                             "Proxying refused on filtered domain \"%s\"",
                                             request->host);

                        indicate_http_error (connptr, 403, "Filtered",
                                             "detail",
                                             "The request you made has been filtered",
                                             "url", url, NULL);
                        goto fail;
                }
        }
#endif


        /*
         * Check to see if they're requesting the stat host
         */
        if (config.stathost && strcmp (config.stathost, request->host) == 0) {
                log_message (LOG_NOTICE, "Request for the stathost.");
                connptr->show_stats = TRUE;
                goto fail;
        }

        safefree (url);

        return request;

fail:
        safefree (url);
        free_request_struct (request);
        return NULL;
}

/*
 * pull_client_data is used to pull across any client data (like in a
 * POST) which needs to be handled before an error can be reported, or
 * server headers can be processed.
 *	- rjkaes
 */
static int pull_client_data (struct conn_s *connptr, long int length)
{
        char *buffer;
        ssize_t len;

        buffer =
            (char *) safemalloc (min (MAXBUFFSIZE, (unsigned long int) length));
        if (!buffer)
                return -1;

        do {
                len = safe_read (connptr->client_fd, buffer,
                                 min (MAXBUFFSIZE, (unsigned long int) length));
                if (len <= 0)
                        goto ERROR_EXIT;

                if (!connptr->error_variables) {
                        if (safe_write (connptr->server_fd, buffer, len) < 0)
                                goto ERROR_EXIT;
                }

                length -= len;
        } while (length > 0);

        /*
         * BUG FIX: Internet Explorer will leave two bytes (carriage
         * return and line feed) at the end of a POST message.  These
         * need to be eaten for tinyproxy to work correctly.
         */
        socket_nonblocking (connptr->client_fd);
        len = recv (connptr->client_fd, buffer, 2, MSG_PEEK);
        socket_blocking (connptr->client_fd);

        if (len < 0 && errno != EAGAIN)
                goto ERROR_EXIT;

        if ((len == 2) && CHECK_CRLF (buffer, len)) {
                ssize_t ret;

                ret = read (connptr->client_fd, buffer, 2);
                if (ret == -1) {
                        log_message
                                (LOG_WARNING,
                                 "Could not read two bytes from POST message");
                }
        }

        safefree (buffer);
        return 0;

ERROR_EXIT:
        safefree (buffer);
        return -1;
}

#ifdef XTINYPROXY_ENABLE
/*
 * Add the X-Tinyproxy header to the collection of headers being sent to
 * the server.
 *	-rjkaes
 */
static int add_xtinyproxy_header (struct conn_s *connptr)
{
        assert (connptr && connptr->server_fd >= 0);
        return write_message (connptr->server_fd,
                              "X-Tinyproxy: %s\r\n", connptr->client_ip_addr);
}
#endif /* XTINYPROXY */

/*
 * Take a complete header line and break it apart (into a key and the data.)
 * Now insert this information into the hashmap for the connection so it
 * can be retrieved and manipulated later.
 */
static int
add_header_to_connection (hashmap_t hashofheaders, char *header, size_t len)
{
        char *sep;

        /* Get rid of the new line and return at the end */
        len -= chomp (header, len);

        sep = strchr (header, ':');
        if (!sep)
                return -1;

        /* Blank out colons, spaces, and tabs. */
        while (*sep == ':' || *sep == ' ' || *sep == '\t')
                *sep++ = '\0';

        /* Calculate the new length of just the data */
        len -= sep - header - 1;

        return hashmap_insert (hashofheaders, header, sep, len);
}

/*
 * Read all the headers from the stream
 */
static int get_all_headers (int fd, hashmap_t hashofheaders)
{
        char *line = NULL;
        char *header = NULL;
        char *tmp;
        ssize_t linelen;
        ssize_t len = 0;
        unsigned int double_cgi = FALSE;        /* boolean */

        assert (fd >= 0);
        assert (hashofheaders != NULL);

        for (;;) {
                if ((linelen = readline (fd, &line)) <= 0) {
                        safefree (header);
                        safefree (line);
                        return -1;
                }

                /*
                 * If we received a CR LF or a non-continuation line, then add
                 * the accumulated header field, if any, to the hashmap, and
                 * reset it.
                 */
                if (CHECK_CRLF (line, linelen) || !CHECK_LWS (line, linelen)) {
                        if (!double_cgi
                            && len > 0
                            && add_header_to_connection (hashofheaders, header,
                                                         len) < 0) {
                                safefree (header);
                                safefree (line);
                                return -1;
                        }

                        len = 0;
                }

                /*
                 * If we received just a CR LF on a line, the headers are
                 * finished.
                 */
                if (CHECK_CRLF (line, linelen)) {
                        safefree (header);
                        safefree (line);
                        return 0;
                }

                /*
                 * BUG FIX: The following code detects a "Double CGI"
                 * situation so that we can handle the nonconforming system.
                 * This problem was found when accessing cgi.ebay.com, and it
                 * turns out to be a wider spread problem as well.
                 *
                 * If "Double CGI" is in effect, duplicate headers are
                 * ignored.
                 *
                 * FIXME: Might need to change this to a more robust check.
                 */
                if (linelen >= 5 && strncasecmp (line, "HTTP/", 5) == 0) {
                        double_cgi = TRUE;
                }

                /*
                 * Append the new line to the current header field.
                 */
                tmp = (char *) saferealloc (header, len + linelen);
                if (tmp == NULL) {
                        safefree (header);
                        safefree (line);
                        return -1;
                }

                header = tmp;
                memcpy (header + len, line, linelen);
                len += linelen;

                safefree (line);
        }
}

/*
 * Extract the headers to remove.  These headers were listed in the Connection
 * and Proxy-Connection headers.
 */
static int remove_connection_headers (hashmap_t hashofheaders)
{
        static const char *headers[] = {
                "connection",
                "proxy-connection"
        };

        char *data;
        char *ptr;
        ssize_t len;
        int i;

        for (i = 0; i != (sizeof (headers) / sizeof (char *)); ++i) {
                /* Look for the connection header.  If it's not found, return. */
                len =
                    hashmap_entry_by_key (hashofheaders, headers[i],
                                          (void **) &data);
                if (len <= 0)
                        return 0;

                /*
                 * Go through the data line and replace any special characters
                 * with a NULL.
                 */
                ptr = data;
                while ((ptr = strpbrk (ptr, "()<>@,;:\\\"/[]?={} \t")))
                        *ptr++ = '\0';

                /*
                 * All the tokens are separated by NULLs.  Now go through the
                 * token and remove them from the hashofheaders.
                 */
                ptr = data;
                while (ptr < data + len) {
                        hashmap_remove (hashofheaders, ptr);

                        /* Advance ptr to the next token */
                        ptr += strlen (ptr) + 1;
                        while (ptr < data + len && *ptr == '\0')
                                ptr++;
                }

                /* Now remove the connection header it self. */
                hashmap_remove (hashofheaders, headers[i]);
        }

        return 0;
}

/*
 * If there is a Content-Length header, then return the value; otherwise, return
 * a negative number.
 */
static long get_content_length (hashmap_t hashofheaders)
{
        ssize_t len;
        char *data;
        long content_length = -1;

        len =
            hashmap_entry_by_key (hashofheaders, "content-length",
                                  (void **) &data);
        if (len > 0)
                content_length = atol (data);

        return content_length;
}

/*
 * Search for Via header in a hash of headers and either write a new Via
 * header, or append our information to the end of an existing Via header.
 *
 * FIXME: Need to add code to "hide" our internal information for security
 * purposes.
 */
static int
write_via_header (int fd, hashmap_t hashofheaders,
                  unsigned int major, unsigned int minor)
{
        ssize_t len;
        char hostname[512];
        char *data;
        int ret;

        if (config.disable_viaheader) {
                ret = 0;
                goto done;
        }

        if (config.via_proxy_name) {
                strlcpy (hostname, config.via_proxy_name, sizeof (hostname));
        } else if (gethostname (hostname, sizeof (hostname)) < 0) {
                strlcpy (hostname, "unknown", 512);
        }

        /*
         * See if there is a "Via" header.  If so, again we need to do a bit
         * of processing.
         */
        len = hashmap_entry_by_key (hashofheaders, "via", (void **) &data);
        if (len > 0) {
                ret = write_message (fd,
                                     "Via: %s, %hu.%hu %s (%s/%s)\r\n",
                                     data, major, minor, hostname, PACKAGE,
                                     VERSION);

                hashmap_remove (hashofheaders, "via");
        } else {
                ret = write_message (fd,
                                     "Via: %hu.%hu %s (%s/%s)\r\n",
                                     major, minor, hostname, PACKAGE, VERSION);
        }

done:
        return ret;
}

/*
 * Number of buckets to use internally in the hashmap.
 */
#define HEADER_BUCKETS 32

/*
 * Here we loop through all the headers the client is sending. If we
 * are running in anonymous mode, we will _only_ send the headers listed
 * (plus a few which are required for various methods).
 *	- rjkaes
 */
static int
process_client_headers (struct conn_s *connptr, hashmap_t hashofheaders)
{
        static const char *skipheaders[] = {
                "host",
                "keep-alive",
                "proxy-connection",
                "te",
                "trailers",
                "upgrade"
        };
        int i;
        hashmap_iter iter;
        int ret = 0;

        char *data, *header;

        /*
         * Don't send headers if there's already an error, if the request was
         * a stats request, or if this was a CONNECT method (unless upstream
         * proxy is in use.)
         */
        if (connptr->server_fd == -1 || connptr->show_stats
            || (connptr->connect_method && (connptr->upstream_proxy == NULL))) {
                log_message (LOG_INFO,
                             "Not sending client headers to remote machine");
                return 0;
        }

        /*
         * See if there is a "Content-Length" header.  If so, again we need
         * to do a bit of processing.
         */
        connptr->content_length.client = get_content_length (hashofheaders);

        /*
         * See if there is a "Connection" header.  If so, we need to do a bit
         * of processing. :)
         */
        remove_connection_headers (hashofheaders);

        /*
         * Delete the headers listed in the skipheaders list
         */
        for (i = 0; i != (sizeof (skipheaders) / sizeof (char *)); i++) {
                hashmap_remove (hashofheaders, skipheaders[i]);
        }

        /* Send, or add the Via header */
        ret = write_via_header (connptr->server_fd, hashofheaders,
                                connptr->protocol.major,
                                connptr->protocol.minor);
        if (ret < 0) {
                indicate_http_error (connptr, 503,
                                     "Could not send data to remote server",
                                     "detail",
                                     "A network error occurred while "
                                     "trying to write data to the remote web server.",
                                     NULL);
                goto PULL_CLIENT_DATA;
        }

        /*
         * Output all the remaining headers to the remote machine.
         */
        iter = hashmap_first (hashofheaders);
        if (iter >= 0) {
                for (; !hashmap_is_end (hashofheaders, iter); ++iter) {
                        hashmap_return_entry (hashofheaders,
                                              iter, &data, (void **) &header);

                        if (!is_anonymous_enabled ()
                            || anonymous_search (data) > 0) {
                                ret =
                                    write_message (connptr->server_fd,
                                                   "%s: %s\r\n", data, header);
                                if (ret < 0) {
                                        indicate_http_error (connptr, 503,
                                                             "Could not send data to remote server",
                                                             "detail",
                                                             "A network error occurred while "
                                                             "trying to write data to the "
                                                             "remote web server.",
                                                             NULL);
                                        goto PULL_CLIENT_DATA;
                                }
                        }
                }
        }
#if defined(XTINYPROXY_ENABLE)
        if (config.add_xtinyproxy)
                add_xtinyproxy_header (connptr);
#endif

        /* Write the final "blank" line to signify the end of the headers */
        if (safe_write (connptr->server_fd, "\r\n", 2) < 0)
                return -1;

        /*
         * Spin here pulling the data from the client.
         */
PULL_CLIENT_DATA:
        if (connptr->content_length.client > 0) {
                ret = pull_client_data (connptr,
                                        connptr->content_length.client);
        }

        return ret;
}

/*
 * Loop through all the headers (including the response code) from the
 * server.
 */
static int process_server_headers (struct conn_s *connptr)
{
        static const char *skipheaders[] = {
                "keep-alive",
                "proxy-authenticate",
                "proxy-authorization",
                "proxy-connection",
        };

        char *response_line;

        hashmap_t hashofheaders;
        hashmap_iter iter;
        char *data, *header;
        ssize_t len;
        int i;
        int ret;

#ifdef REVERSE_SUPPORT
        struct reversepath *reverse = config.reversepath_list;
#endif

        /* Get the response line from the remote server. */
retry:
        len = readline (connptr->server_fd, &response_line);
        if (len <= 0)
                return -1;

        /*
         * Strip the new line and character return from the string.
         */
        if (chomp (response_line, len) == len) {
                /*
                 * If the number of characters removed is the same as the
                 * length then it was a blank line. Free the buffer and
                 * try again (since we're looking for a request line.)
                 */
                safefree (response_line);
                goto retry;
        }

        hashofheaders = hashmap_create (HEADER_BUCKETS);
        if (!hashofheaders) {
                safefree (response_line);
                return -1;
        }

        /*
         * Get all the headers from the remote server in a big hash
         */
        if (get_all_headers (connptr->server_fd, hashofheaders) < 0) {
                log_message (LOG_WARNING,
                             "Could not retrieve all the headers from the remote server.");
                hashmap_delete (hashofheaders);
                safefree (response_line);

                indicate_http_error (connptr, 503,
                                     "Could not retrieve all the headers",
                                     "detail",
                                     PACKAGE_NAME " "
                                     "was unable to retrieve and process headers from "
                                     "the remote web server.", NULL);
                return -1;
        }

        /*
         * At this point we've received the response line and all the
         * headers.  However, if this is a simple HTTP/0.9 request we
         * CAN NOT send any of that information back to the client.
         * Instead we'll free all the memory and return.
         */
        if (connptr->protocol.major < 1) {
                hashmap_delete (hashofheaders);
                safefree (response_line);
                return 0;
        }

        /* Send the saved response line first */
        ret = write_message (connptr->client_fd, "%s\r\n", response_line);
        safefree (response_line);
        if (ret < 0)
                goto ERROR_EXIT;

        /*
         * If there is a "Content-Length" header, retrieve the information
         * from it for later use.
         */
        connptr->content_length.server = get_content_length (hashofheaders);

        /*
         * See if there is a connection header.  If so, we need to to a bit of
         * processing.
         */
        remove_connection_headers (hashofheaders);

        /*
         * Delete the headers listed in the skipheaders list
         */
        for (i = 0; i != (sizeof (skipheaders) / sizeof (char *)); i++) {
                hashmap_remove (hashofheaders, skipheaders[i]);
        }

        /* Send, or add the Via header */
        ret = write_via_header (connptr->client_fd, hashofheaders,
                                connptr->protocol.major,
                                connptr->protocol.minor);
        if (ret < 0)
                goto ERROR_EXIT;

#ifdef REVERSE_SUPPORT
        /* Write tracking cookie for the magical reverse proxy path hack */
        if (config.reversemagic && connptr->reversepath) {
                ret = write_message (connptr->client_fd,
                                     "Set-Cookie: " REVERSE_COOKIE
                                     "=%s; path=/\r\n", connptr->reversepath);
                if (ret < 0)
                        goto ERROR_EXIT;
        }

        /* Rewrite the HTTP redirect if needed */
        if (config.reversebaseurl &&
            hashmap_entry_by_key (hashofheaders, "location",
                                  (void **) &header) > 0) {

                /* Look for a matching entry in the reversepath list */
                while (reverse) {
                        if (strncasecmp (header,
                                         reverse->url, (len =
                                                        strlen (reverse->
                                                                url))) == 0)
                                break;
                        reverse = reverse->next;
                }

                if (reverse) {
                        ret =
                            write_message (connptr->client_fd,
                                           "Location: %s%s%s\r\n",
                                           config.reversebaseurl,
                                           (reverse->path + 1), (header + len));
                        if (ret < 0)
                                goto ERROR_EXIT;

                        log_message (LOG_INFO,
                                     "Rewriting HTTP redirect: %s -> %s%s%s",
                                     header, config.reversebaseurl,
                                     (reverse->path + 1), (header + len));
                        hashmap_remove (hashofheaders, "location");
                }
        }
#endif

        /*
         * All right, output all the remaining headers to the client.
         */
        iter = hashmap_first (hashofheaders);
        if (iter >= 0) {
                for (; !hashmap_is_end (hashofheaders, iter); ++iter) {
                        hashmap_return_entry (hashofheaders,
                                              iter, &data, (void **) &header);

                        ret = write_message (connptr->client_fd,
                                             "%s: %s\r\n", data, header);
                        if (ret < 0)
                                goto ERROR_EXIT;
                }
        }
        hashmap_delete (hashofheaders);

        /* Write the final blank line to signify the end of the headers */
        if (safe_write (connptr->client_fd, "\r\n", 2) < 0)
                return -1;

        return 0;

ERROR_EXIT:
        hashmap_delete (hashofheaders);
        return -1;
}

/*
 * Switch the sockets into nonblocking mode and begin relaying the bytes
 * between the two connections. We continue to use the buffering code
 * since we want to be able to buffer a certain amount for slower
 * connections (as this was the reason why I originally modified
 * tinyproxy oh so long ago...)
 *	- rjkaes
 */
static void relay_connection (struct conn_s *connptr)
{
        fd_set rset, wset;
        struct timeval tv;
        time_t last_access;
        int ret;
        double tdiff;
        int maxfd = max (connptr->client_fd, connptr->server_fd) + 1;
        ssize_t bytes_received;

        socket_nonblocking (connptr->client_fd);
        socket_nonblocking (connptr->server_fd);

        last_access = time (NULL);

        for (;;) {
                FD_ZERO (&rset);
                FD_ZERO (&wset);

                tv.tv_sec =
                    config.idletimeout - difftime (time (NULL), last_access);
                tv.tv_usec = 0;

                if (buffer_size (connptr->sbuffer) > 0)
                        FD_SET (connptr->client_fd, &wset);
                if (buffer_size (connptr->cbuffer) > 0)
                        FD_SET (connptr->server_fd, &wset);
                if (buffer_size (connptr->sbuffer) < MAXBUFFSIZE)
                        FD_SET (connptr->server_fd, &rset);
                if (buffer_size (connptr->cbuffer) < MAXBUFFSIZE)
                        FD_SET (connptr->client_fd, &rset);

                ret = select (maxfd, &rset, &wset, NULL, &tv);

                if (ret == 0) {
                        tdiff = difftime (time (NULL), last_access);
                        if (tdiff > config.idletimeout) {
                                log_message (LOG_INFO,
                                             "Idle Timeout (after select) as %g > %u.",
                                             tdiff, config.idletimeout);
                                return;
                        } else {
                                continue;
                        }
                } else if (ret < 0) {
                        log_message (LOG_ERR,
                                     "relay_connection: select() error \"%s\". "
                                     "Closing connection (client_fd:%d, server_fd:%d)",
                                     strerror (errno), connptr->client_fd,
                                     connptr->server_fd);
                        return;
                } else {
                        /*
                         * All right, something was actually selected so mark it.
                         */
                        last_access = time (NULL);
                }

                if (FD_ISSET (connptr->server_fd, &rset)) {
                        bytes_received =
                            read_buffer (connptr->server_fd, connptr->sbuffer);
                        if (bytes_received < 0)
                                break;

                        connptr->content_length.server -= bytes_received;
                        if (connptr->content_length.server == 0)
                                break;
                }
                if (FD_ISSET (connptr->client_fd, &rset)
                    && read_buffer (connptr->client_fd, connptr->cbuffer) < 0) {
                        break;
                }
                if (FD_ISSET (connptr->server_fd, &wset)
                    && write_buffer (connptr->server_fd, connptr->cbuffer) < 0) {
                        break;
                }
                if (FD_ISSET (connptr->client_fd, &wset)
                    && write_buffer (connptr->client_fd, connptr->sbuffer) < 0) {
                        break;
                }
        }

        /*
         * Here the server has closed the connection... write the
         * remainder to the client and then exit.
         */
        socket_blocking (connptr->client_fd);
        while (buffer_size (connptr->sbuffer) > 0) {
                if (write_buffer (connptr->client_fd, connptr->sbuffer) < 0)
                        break;
        }
        shutdown (connptr->client_fd, SHUT_WR);

        /*
         * Try to send any remaining data to the server if we can.
         */
        socket_blocking (connptr->server_fd);
        while (buffer_size (connptr->cbuffer) > 0) {
                if (write_buffer (connptr->server_fd, connptr->cbuffer) < 0)
                        break;
        }

        return;
}

/*
 * Establish a connection to the upstream proxy server.
 */
static int
connect_to_upstream (struct conn_s *connptr, struct request_s *request)
{
#ifndef UPSTREAM_SUPPORT
        /*
         * This function does nothing if upstream support was not compiled
         * into tinyproxy.
         */
        return -1;
#else
        char *combined_string;
        int len;

        struct upstream *cur_upstream = connptr->upstream_proxy;

        if (!cur_upstream) {
                log_message (LOG_WARNING,
                             "No upstream proxy defined for %s.",
                             request->host);
                indicate_http_error (connptr, 404,
                                     "Unable to connect to upstream proxy.");
                return -1;
        }

        connptr->server_fd =
            opensock (cur_upstream->host, cur_upstream->port,
                      connptr->server_ip_addr);

        if (connptr->server_fd < 0) {
                log_message (LOG_WARNING,
                             "Could not connect to upstream proxy.");
                indicate_http_error (connptr, 404,
                                     "Unable to connect to upstream proxy",
                                     "detail",
                                     "A network error occurred while trying to "
                                     "connect to the upstream web proxy.",
                                     NULL);
                return -1;
        }

        log_message (LOG_CONN,
                     "Established connection to upstream proxy \"%s\" "
                     "using file descriptor %d.",
                     cur_upstream->host, connptr->server_fd);

        /*
         * We need to re-write the "path" part of the request so that we
         * can reuse the establish_http_connection() function. It expects a
         * method and path.
         */
        if (connptr->connect_method) {
                len = strlen (request->host) + 7;

                combined_string = (char *) safemalloc (len);
                if (!combined_string) {
                        return -1;
                }

                snprintf (combined_string, len, "%s:%d", request->host,
                          request->port);
        } else {
                len = strlen (request->host) + strlen (request->path) + 14;
                combined_string = (char *) safemalloc (len);
                if (!combined_string) {
                        return -1;
                }

                snprintf (combined_string, len, "http://%s:%d%s", request->host,
                          request->port, request->path);
        }

        if (request->path)
                safefree (request->path);
        request->path = combined_string;

        return establish_http_connection (connptr, request);
#endif
}

static int
get_request_entity(struct conn_s *connptr)
{
        int ret;
        fd_set rset;
        struct timeval tv;

        FD_ZERO (&rset);
        FD_SET (connptr->client_fd, &rset);
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        ret = select (connptr->client_fd + 1, &rset, NULL, NULL, &tv);

        if (ret == -1) {
                log_message (LOG_ERR,
                             "Error calling select on client fd %d: %s",
                             connptr->client_fd, strerror(errno));
        } else if (ret == 0) {
               log_message (LOG_INFO, "no entity");
        } else if (ret == 1 && FD_ISSET (connptr->client_fd, &rset)) {
                ssize_t nread;
                nread = read_buffer (connptr->client_fd, connptr->cbuffer);
                if (nread < 0) {
                        log_message (LOG_ERR,
                                     "Error reading readble client_fd %d",
                                     connptr->client_fd);
                        ret = -1;
                } else {
                        log_message (LOG_INFO,
                                     "Read request entity of %d bytes",
                                     nread);
                        ret = 0;
                }
        } else {
                log_message (LOG_ERR, "strange situation after select: "
                             "ret = %d, but client_fd (%d) is not readable...",
                             ret, connptr->client_fd);
                ret = -1;
        }

        return ret;
}


/*
 * This is the main drive for each connection. As you can tell, for the
 * first few steps we are using a blocking socket. If you remember the
 * older tinyproxy code, this use to be a very confusing state machine.
 * Well, no more! :) The sockets are only switched into nonblocking mode
 * when we start the relay portion. This makes most of the original
 * tinyproxy code, which was confusing, redundant. Hail progress.
 * 	- rjkaes
 */
void handle_connection (int fd)
{
        ssize_t i;
        struct conn_s *connptr;
        struct request_s *request = NULL;
        hashmap_t hashofheaders = NULL;

        char sock_ipaddr[IP_LENGTH];
        char peer_ipaddr[IP_LENGTH];
        char peer_string[HOSTNAME_LENGTH];

        getpeer_information (fd, peer_ipaddr, peer_string);

        if (config.bindsame)
                getsock_ip (fd, sock_ipaddr);

        log_message (LOG_CONN, config.bindsame ?
                     "Connect (file descriptor %d): %s [%s] at [%s]" :
                     "Connect (file descriptor %d): %s [%s]",
                     fd, peer_string, peer_ipaddr, sock_ipaddr);

        connptr = initialize_conn (fd, peer_ipaddr, peer_string,
                                   config.bindsame ? sock_ipaddr : NULL);
        if (!connptr) {
                close (fd);
                return;
        }
        
        set_readtimeout(connptr->client_fd, config.idletimeout);
        set_writetimeout(connptr->client_fd, config.idletimeout);

        if (check_acl (peer_ipaddr, peer_string, config.access_list) <= 0) {
                update_stats (STAT_DENIED);
                indicate_http_error (connptr, 403, "Access denied",
                                     "detail",
                                     "The administrator of this proxy has not configured "
                                     "it to service requests from your host.",
                                     NULL);
                goto fail;
        }

        if (read_request_line (connptr) < 0) {
                update_stats (STAT_BADCONN);
                indicate_http_error (connptr, 408, "Timeout",
                                     "detail",
                                     "Server timeout waiting for the HTTP request "
                                     "from the client.", NULL);
                goto fail;
        }

        /*
         * The "hashofheaders" store the client's headers.
         */
        hashofheaders = hashmap_create (HEADER_BUCKETS);
        if (hashofheaders == NULL) {
                update_stats (STAT_BADCONN);
                indicate_http_error (connptr, 503, "Internal error",
                                     "detail",
                                     "An internal server error occurred while processing "
                                     "your request. Please contact the administrator.",
                                     NULL);
                goto fail;
        }

        /*
         * Get all the headers from the client in a big hash.
         */
        if (get_all_headers (connptr->client_fd, hashofheaders) < 0) {
                log_message (LOG_WARNING,
                             "Could not retrieve all the headers from the client");
                indicate_http_error (connptr, 400, "Bad Request",
                                     "detail",
                                     "Could not retrieve all the headers from "
                                     "the client.", NULL);
                update_stats (STAT_BADCONN);
                goto fail;
        }

        /*
         * Add any user-specified headers (AddHeader directive) to the
         * outgoing HTTP request.
         */
        for (i = 0; i < vector_length (config.add_headers); i++) {
                http_header_t *header = (http_header_t *)
                        vector_getentry (config.add_headers, i, NULL);

                hashmap_insert (hashofheaders,
                                header->name,
                                header->value, strlen (header->value) + 1);
        }

        request = process_request (connptr, hashofheaders);
        if (!request) {
                if (!connptr->show_stats) {
                        update_stats (STAT_BADCONN);
                }
                goto fail;
        }
        update_reqpeer(request->host);

        connptr->upstream_proxy = UPSTREAM_HOST (request->host);
        if (connptr->upstream_proxy != NULL) {
                if (connect_to_upstream (connptr, request) < 0) {
                        goto fail;
                }
        } else {
                connptr->server_fd = opensock (request->host, request->port,
                                               connptr->server_ip_addr);
                if (connptr->server_fd < 0) {
                        indicate_http_error (connptr, 500, "Unable to connect",
                                             "detail",
                                             PACKAGE_NAME " "
                                             "was unable to connect to the remote web server.",
                                             "error", strerror (errno), NULL);
                        goto fail;
                }

                log_message (LOG_CONN,
                             "Established connection to host \"%s\" using "
                             "file descriptor %d.", request->host,
                             connptr->server_fd);


                if (!connptr->connect_method)
                        establish_http_connection (connptr, request);
        }

        set_readtimeout(connptr->server_fd, config.idletimeout);
        set_writetimeout(connptr->server_fd, config.idletimeout);

        if (process_client_headers (connptr, hashofheaders) < 0) {
                update_stats (STAT_BADCONN);
                goto fail;
        }

        if (!(connptr->connect_method && (connptr->upstream_proxy == NULL))) {
                if (process_server_headers (connptr) < 0) {
                        update_stats (STAT_BADCONN);
                        goto fail;
                }
        } else {
                if (send_ssl_response (connptr) < 0) {
                        log_message (LOG_ERR,
                                     "handle_connection: Could not send SSL greeting "
                                     "to client.");
                        update_stats (STAT_BADCONN);
                        goto fail;
                }
        }

        relay_connection (connptr);
        update_donepeer(request->host);

        log_message (LOG_INFO,
                     "Closed connection between local client (fd:%d) "
                     "and remote client (fd:%d)",
                     connptr->client_fd, connptr->server_fd);

        goto done;

fail:
        /*
         * First, get the body if there is one.
         * If we don't read all there is from the socket first,
         * it is still marked for reading and we won't be able
         * to send our data properly.
         */
        if (get_request_entity (connptr) < 0) {
                log_message (LOG_WARNING,
                             "Could not retrieve request entity");
                indicate_http_error (connptr, 400, "Bad Request",
                                     "detail",
                                     "Could not retrieve the request entity "
                                     "the client.", NULL);
                update_stats (STAT_BADCONN);
        }

        if (connptr->error_variables) {
                send_http_error_message (connptr);
        } else if (connptr->show_stats) {
                showstats (connptr);
        }

done:
        free_request_struct (request);
        hashmap_delete (hashofheaders);
        destroy_conn (connptr);
        return;
}
