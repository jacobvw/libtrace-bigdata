#include "module_maxmind.h"

#include <errno.h>
#include <maxminddb.h>
#include <stdlib.h>
#include <string.h>

typedef struct module_maxmind_config {
    bd_cb_set *callbacks;
    bool enabled;
    char *database;
    bool coordinates;
    bool geohash;
    bool city;
    bool country;
} mod_max_conf;
static mod_max_conf *config;

typedef struct module_maxmind_storage {
    MMDB_s mmdb;
} mod_max_stor;

/* Geohash structures */
typedef struct IntervalStruct {
    double high;
    double low;
} Interval;
/* Normal 32 characer map used for geohashing */
static char char_map[33] =  "0123456789bcdefghjkmnpqrstuvwxyz";
static char* module_maxmind_geohash_encode(double lat, double lng, int precision);

void *module_maxmind_starting_cb(void *tls) {

    int mmdb_status;
    mod_max_stor *storage;

    storage = (mod_max_stor *)malloc(sizeof(mod_max_stor));
    if (storage == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "module_maxmind_starting()\n");
        exit(BD_OUTOFMEMORY);
    }

    mmdb_status = MMDB_open(config->database, MMDB_MODE_MMAP, &(storage->mmdb));
    if (mmdb_status != MMDB_SUCCESS) {
        logger(LOG_CRIT, "Unable to open maxmind database %s - %s\n",
            config->database, MMDB_strerror(mmdb_status));

        if (MMDB_IO_ERROR == mmdb_status) {
            logger(LOG_CRIT, "Maxmind IO error: %s\n", strerror(errno));
        }

        exit(BD_FILTER_INIT);
    }

    return storage;
}

int module_maxmind_result_cb(bd_bigdata_t *bigdata, void *mls, bd_result_set *result) {

    mod_max_stor *storage = (mod_max_stor *)mls;
    char *ip = NULL;
    int gai_error;
    int mmdb_error;
    MMDB_lookup_result_s mmdb_result;
    MMDB_entry_data_s entry_data;
    int status;
    char buf[100];
    char buf2[100];
    double longitude;
    double latitude;

    /* try to find a IP address in this result */
    for (int i = 0; i < result->num_results; i++) {
        if (result->results[i].type == BD_TYPE_IP_STRING) {
            // get the IP
            ip = result->results[i].value.data_string;

            if (ip != NULL) {

                mmdb_result = MMDB_lookup_string(&(storage->mmdb), ip, &gai_error, &mmdb_error);
                if (mmdb_result.found_entry) {

                    // If coordinates are set to output
                    if (config->coordinates || config->geohash) {

                        // get the longitude
                        status = MMDB_get_value(&(mmdb_result.entry), &entry_data,
                            "location", "longitude", NULL);
                        if (status == MMDB_SUCCESS) {
                            if (entry_data.has_data) {
                                // insert longitude into the result set
                                snprintf(buf, sizeof(buf), "%s_longitude",
                                    result->results[i].key);
                                longitude = entry_data.double_value;
                                if (config->coordinates) {
                                    bd_result_set_insert_double(result, buf,
                                        longitude);
                                }
                            }
                        }

                        // get the latitude
                        status = MMDB_get_value(&(mmdb_result.entry), &entry_data,
                            "location", "latitude", NULL);
                        if (status == MMDB_SUCCESS) {
                            if (entry_data.has_data) {
                                snprintf(buf, sizeof(buf), "%s_latitude",
                                    result->results[i].key);
                                latitude = entry_data.double_value;
                                if (config->coordinates) {
                                    bd_result_set_insert_double(result, buf,
                                        latitude);
                                }
                            }
                        }

                        // calculate the geohash if set
                        if (config->geohash) {
                            // calculate the geohash
                            char *geohash = module_maxmind_geohash_encode(latitude, longitude, 6);
                            // insert geohash into result set
                            snprintf(buf, sizeof(buf), "%s_geohash",
                                result->results[i].key);
                            bd_result_set_insert_tag(result, buf, geohash);
                            // grafana worldmap panel needs a value for each one??
                            snprintf(buf, sizeof(buf), "%s_geohash_value",
                                result->results[i].key);
                            bd_result_set_insert_uint(result, buf, 1);
                            free(geohash);
                        }
                    }

                    // If city name is set to output
                    if (config->city) {
                        status = MMDB_get_value(&(mmdb_result.entry), &entry_data,
                            "city", "names", "en", NULL);
                        if (status == MMDB_SUCCESS) {
                            if (entry_data.has_data) {
                                snprintf(buf, sizeof(buf), "%s_city",
                                    result->results[i].key);
                                snprintf(buf2, entry_data.data_size + 1, "%s",
                                    entry_data.utf8_string);
                                bd_result_set_insert_string(result, buf, buf2);
                            }
                        }
                    }

                    // If country name is set to output
                    if (config->country) {
                        status = MMDB_get_value(&(mmdb_result.entry), &entry_data,
                            "country", "names", "en", NULL);
                        if (status == MMDB_SUCCESS) {
                            if (entry_data.has_data) {
                                snprintf(buf, sizeof(buf), "%s_country",
                                    result->results[i].key);
                                snprintf(buf2, entry_data.data_size + 1, "%s",
                                    entry_data.utf8_string);
                                bd_result_set_insert_string(result, buf, buf2);
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}

int module_maxmind_stopping_cb(void *tls, void *mls) {

    mod_max_stor *storage = (mod_max_stor *)mls;

    MMDB_close(&(storage->mmdb));
    free(storage);

    return 0;
}

int module_maxmind_config_cb(yaml_parser_t *parser, yaml_event_t *event, int *level) {

    int enter_level = *level;
    bool first_pass = 1;

    while (enter_level != *level || first_pass) {
        first_pass = 0;
        switch(event->type) {
            case YAML_SCALAR_EVENT:
                if (strcmp((char *)event->data.scalar.value, "enabled") == 0) {
                    consume_event(parser, event, level);
                    if (strcmp((char *)event->data.scalar.value, "1") == 0 ||
                        strcmp((char *)event->data.scalar.value, "yes") == 0 ||
                        strcmp((char *)event->data.scalar.value, "true") == 0 ||
                        strcmp((char *)event->data.scalar.value, "t") == 0) {

                        config->enabled = 1;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "database") == 0) {
                    consume_event(parser, event, level);
                    config->database = strdup((char *)event->data.scalar.value);
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "coordinates") == 0) {
                    consume_event(parser, event, level);
                    config->coordinates = 1;
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "geohash") == 0) {
                    consume_event(parser, event, level);
                    config->geohash = 1;
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "city") == 0) {
                    consume_event(parser, event, level);
                    config->city = 1;
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "country") == 0) {
                    consume_event(parser, event, level);
                    config->country = 1;
                    break;
                }

                consume_event(parser, event, level);
                break;
            default:
                consume_event(parser, event, level);
                break;
        }
    }

    if (config->enabled) {

        // register starting, result and stopping callbacks
        bd_register_reporter_start_event(config->callbacks, module_maxmind_starting_cb);
        bd_register_reporter_filter_event(config->callbacks, module_maxmind_result_cb);
        bd_register_reporter_stop_event(config->callbacks, module_maxmind_stopping_cb);

        logger(LOG_INFO, "Maxmind Plugin Enabled\n");

    }

    return 0;
}

int module_maxmind_init(bd_bigdata_t *bigdata) {

    config = (mod_max_conf *)malloc(sizeof(mod_max_conf));
    if (config == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "module_maxmind_init()\n");
        exit(BD_OUTOFMEMORY);
    }

    config->enabled = 0;
    config->database = NULL;
    config->coordinates = 0;
    config->geohash = 0;
    config->city = 0;
    config->country = 0;

    // create callback set
    config->callbacks = bd_create_cb_set("maxmind");
    // define configuration callback
    bd_register_config_event(config->callbacks, module_maxmind_config_cb);
    // register the callback set
    bd_register_cb_set(bigdata, config->callbacks);

    return 0;
}

/*
 *  geohash.c
 *  libgeohash
 *
 *  Created by Derek Smith on 10/6/09.
 *  Copyright (c) 2010, SimpleGeo
 *      All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer. Redistributions in binary form must 
 *  reproduce the above copyright notice, this list of conditions and the following 
 *  disclaimer in the documentation and/or other materials provided with the distribution.
 *  Neither the name of the SimpleGeo nor the names of its contributors may be used
 *  to endorse or promote products derived from this software without specific prior 
 *  written permission. 
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 *  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
 *  THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
 *  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
 *  AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
 *  OF THE POSSIBILITY OF SUCH DAMAGE.
 */
static char* module_maxmind_geohash_encode(double lat, double lng, int precision) {
    
    if(precision < 1 || precision > 12)
        precision = 6;
    
    char* hash = NULL;
    
    if(lat <= 90.0 && lat >= -90.0 && lng <= 180.0 && lng >= -180.0) {
        
        hash = (char*)malloc(sizeof(char) * (precision + 1));
        if (hash == NULL) {
            logger(LOG_CRIT, "Unable to allocate memory. func. "
                "module_maxmind_geohash_encode()\n");
            exit(BD_OUTOFMEMORY);
        }
        hash[precision] = '\0';
        
        precision *= 5.0;
        
        Interval lat_interval = {90, -90};
        Interval lng_interval = {180, -180};

        Interval *interval;
        double coord, mid;
        int is_even = 1;
        unsigned int hashChar = 0;
        int i;
        for(i = 1; i <= precision; i++) {
         
            if(is_even) {
            
                interval = &lng_interval;
                coord = lng;                
                
            } else {
                
                interval = &lat_interval;
                coord = lat;   
            }
            
            mid = (interval->low + interval->high) / 2.0;
            hashChar = hashChar << 1;
            
            if(coord > mid) {
                
                interval->low = mid;
                hashChar |= 0x01;
                
            } else
                interval->high = mid;
            
            if(!(i % 5)) {
                
                hash[(i - 1) / 5] = char_map[hashChar];
                hashChar = 0;

            }
            
            is_even = !is_even;
        }
     
        
    }
    
    return hash;
}
