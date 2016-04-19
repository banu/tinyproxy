/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 2000 Robert James Kaes <rjkaes@users.sourceforge.net>
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

/* This module handles the statistics for tinyproxy. There are only two
 * public API functions. The reason for the functions, rather than just a
 * external structure is that tinyproxy is now multi-threaded and we can
 * not allow more than one child to access the statistics at the same
 * time. This is prevented by a mutex. If there is a need for more
 * statistics in the future, just add to the structure, enum (in the header),
 * and the switch statement in update_stats().
 */

#include "main.h"

#include "log.h"
#include "heap.h"
#include "html-error.h"
#include "stats.h"
#include "utils.h"
#include "conf.h"
#include "hashmap.h"

struct peer_s {
        char host[36];
        int  count;
};

struct stat_s {
        unsigned long int num_reqs;
        unsigned long int num_badcons;
        unsigned long int num_open;
        unsigned long int num_refused;
        unsigned long int num_denied;
        struct peer_s     peers[100];
};

static struct stat_s *stats;
static int MAX_ITEM_LEN = 48;

/*
 * Initialize the statistics information to zero.
 */
void init_stats (void)
{
        stats = (struct stat_s *) malloc_shared_memory (sizeof (struct stat_s));
        if (stats == MAP_FAILED)
                return;

        memset (stats, 0, sizeof (struct stat_s));
}

/*
 * Display the statics of the tinyproxy server.
 */
int
showstats (struct conn_s *connptr)
{
        char *message_buffer;


        message_buffer = (char *) safemalloc (MAXBUFFSIZE);
        if (!message_buffer)
                return -1;
        memset(message_buffer, 0, MAXBUFFSIZE);
         
        char item[MAX_ITEM_LEN];
        int idx = 0;
        
        for(; idx<sizeof(stats->peers)/sizeof(struct peer_s); ++idx)
        {
            if (strlen(stats->peers[idx].host) == 0){
                continue;
            }
            if (idx >= MAXBUFFSIZE/MAX_ITEM_LEN){
                break;
            }
            if (idx == 0){
                strcat(message_buffer, "{\"domain\":{");
            }
            memset(item, 0, MAX_ITEM_LEN);
            snprintf(item, MAX_ITEM_LEN, "\"%s\":%d,",  stats->peers[idx].host, stats->peers[idx].count);
            strcat(message_buffer, item);
        }

        if (strlen(message_buffer) > 0 && strlen(message_buffer) + 2 < MAXBUFFSIZE){
            message_buffer[strlen(message_buffer)-1] = '}';
            strcat(message_buffer, ",");
        }else if (strlen(message_buffer) == 0){
            message_buffer[0] = '{';
        }

        do {
            memset(item, 0, MAX_ITEM_LEN);
            snprintf(item, MAX_ITEM_LEN, "\"%s\":%d,",  "connreqs", stats->num_reqs);
            if (strlen(message_buffer) + strlen(item) >= MAXBUFFSIZE){
                break;
            }
            strcat(message_buffer, item);
            memset(item, 0, MAX_ITEM_LEN);
            snprintf(item, MAX_ITEM_LEN, "\"%s\":%d,",  "connbads", stats->num_badcons);
            if (strlen(message_buffer) + strlen(item) >= MAXBUFFSIZE){
                break;
            }
            strcat(message_buffer, item);
            memset(item, 0, MAX_ITEM_LEN);
            snprintf(item, MAX_ITEM_LEN, "\"%s\":%d,",  "connopens", stats->num_open);
            if (strlen(message_buffer) + strlen(item) >= MAXBUFFSIZE){
                break;
            }
            strcat(message_buffer, item);
            memset(item, 0, MAX_ITEM_LEN);
            snprintf(item, MAX_ITEM_LEN, "\"%s\":%d,",  "connrefused", stats->num_refused);
            if (strlen(message_buffer) + strlen(item) >= MAXBUFFSIZE){
                break;
            }
            strcat(message_buffer, item);
            memset(item, 0, MAX_ITEM_LEN);
            snprintf(item, MAX_ITEM_LEN, "\"%s\":%d",  "conndenied", stats->num_denied);
            if (strlen(message_buffer) + strlen(item) >= MAXBUFFSIZE){
                break;
            }
            strcat(message_buffer, item);
        } while(0);

        int httpcode = 200;
        if (strlen(message_buffer) + 1 < MAXBUFFSIZE){
            strcat(message_buffer, "}");
        }else{
            httpcode = 500;
        }
        
        if (send_http_json_message (connptr, httpcode, "OK", message_buffer) < 0) {
                safefree (message_buffer);
                return 0;
        }

        memset(stats, 0, sizeof(struct stat_s));
        safefree (message_buffer);
        return 0;
}

/*
 * Update the value of the statistics. The update_level is defined in
 * stats.h
 */
int update_stats (status_t update_level)
{
        switch (update_level) {
        case STAT_BADCONN:
                ++stats->num_badcons;
                break;
        case STAT_OPEN:
                ++stats->num_open;
                ++stats->num_reqs;
                break;
        case STAT_CLOSE:
                --stats->num_open;
                break;
        case STAT_REFUSE:
                ++stats->num_refused;
                break;
        case STAT_DENIED:
                ++stats->num_denied;
                break;
        default:
                return -1;
        }

        return 0;
}

int update_reqpeer(char* host)
{
    struct peer_s* empty_peer = NULL;
    int idx = 0;

    for(; idx<sizeof(stats->peers)/sizeof(struct peer_s); ++idx)
    {
        if (strlen(stats->peers[idx].host) == 0 && stats->peers[idx].count == 0 && empty_peer == NULL){
            empty_peer = &stats->peers[idx];
            break;
        }
        if (0 == strncmp(host, stats->peers[idx].host, 35)){
            stats->peers[idx].count += 1;
            log_message(LOG_CONN, host);
            return 0;
        }
    }

    if (empty_peer == NULL){
        return  -1;
    }
    
    strncpy(empty_peer->host, host, 35);
    empty_peer->count = 1;
    return 1;
}
