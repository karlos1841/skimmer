/*
 * g++ -std=c++11 -pedantic -Wall -Wextra skimmer.cpp -o skimmer -lssl -lcrypto
 * Author: karol.wozniak@it.emca.pl
 *
 * CHANGELOG
 * 1.0    - initial release
 * 1.0.1  - resetting descriptor on sendData function's start and end to prevent it from leaking in some situations
 * 1.0.2  - rewritten readResponse and sendData + bugfix in process_pid
 * 1.0.3  - code cleanup
 * 1.0.4  - configuration options moved to file
 * 1.0.5  - added logstash api + bugfix in readResponse
 * 1.0.6  - added index_freq option
 * 1.0.6a - changed _cat/master to accept text/plain response
 * 1.0.6b - fixed zombie state
 * 1.0.7  - added new metrics
 * 1.0.8  - added SSL support + rewritten json deserializer + other changes
*/
#define _XOPEN_SOURCE 700 // POSIX 2008
#include <iostream>
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <climits>
#include <unordered_map>
#include <sstream>
#include <fstream>
#include <typeinfo>
#include <ctime>
#include <algorithm>
#include <unistd.h>
#include <mntent.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <glob.h>
#include <math.h>
#include <openssl/ssl.h>

#define IP_MAX      16
#define BUFFER      1024
#define MIN_PORT    1
#define MAX_PORT    65535

/*** OS METRICS USING LINUX/POSIX LIBRARIES ***/
// returns associative array with hostname and ip address of this machine
std::unordered_map<std::string, std::string> hostname_ip();

// retrieves mountpoints from /etc/fstab excluding swap and returns associative array with filesystem statistics
std::unordered_map<std::string, uint64_t> fs_stats();

// returns associative array with swap usage
std::unordered_map<std::string, uint64_t> swap_stats();

// returns associative array with pid of the process given in the argument
std::unordered_map<std::string, std::string> process_pid(const char *);

// returns associative array with the number of zombie processes
std::unordered_map<std::string, uint64_t> zombie_count();

// returns associative array with network stats from /sys/class/net/*/statistics/
std::unordered_map<std::string, uint64_t> net_stats();

// returns associative array with cpu percentage when in busy,iowait state in 1s interval
std::unordered_map<std::string, uint64_t> cpu_stats();

// returns associative array with virtual memory stats
std::unordered_map<std::string, uint64_t> vm_stats();

// returns associative array with systemd service status
std::unordered_map<std::string, std::string> systemd_service_status(const std::string &, bool);

/********************************/
/********************************/
/*** GENERIC HELPER FUNCTIONS ***/
int getCommandOutput(const std::string &command, std::string &output)
{
    FILE *f = NULL;
    if((f = popen(command.c_str(), "r")) == NULL) return -1;

    int c = fgetc(f);
    while(c != EOF && c != '\n')
    {
        output.push_back(c);
        c = fgetc(f);
    }

    return pclose(f);
}

int node_hostname_ip(std::string &nodeHostname, std::string &nodeIP)
{
    char hostname[HOST_NAME_MAX];
    if(gethostname(hostname, HOST_NAME_MAX) != 0)
        return -1;
    nodeHostname = hostname;

	struct addrinfo hints, *info;
	struct sockaddr_in *s;
    char ip[IP_MAX];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;

	if(getaddrinfo(hostname, NULL, &hints, &info) != 0)
		return -1;

	s = (struct sockaddr_in *)info->ai_addr;
    snprintf(ip, sizeof(ip), "%s", inet_ntoa(s->sin_addr));
	freeaddrinfo(info);
    nodeIP = ip;
    return 0;
}

unsigned long hostnameToIP(const char *hostname)
{
	struct addrinfo hints, *info;
	struct sockaddr_in *s;
	unsigned long IP = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;

	if(getaddrinfo(hostname, NULL, &hints, &info) != 0)
		return 0;

	s = (struct sockaddr_in *)info->ai_addr;
	IP = s->sin_addr.s_addr;
	freeaddrinfo(info);

	return IP;
}

// remove headers from webserver's response
const char *remove_headers(char **response)
{
	const char *content = *response;
	char *tmp_ptr = NULL;
	while(strstr(content, "\r\n\r\n") != NULL)
	{
		content += 4;
	}
	tmp_ptr = (char *)calloc(strlen(content) + 1, sizeof(char));
	strncpy(tmp_ptr, content, strlen(content));

	// free old memory
	free(*response);
	// assign new memory
	*response = tmp_ptr;

	return *response;
}

unsigned short getHttpStatus(const char *response)
{
	std::string dest(response);
	char *ptr;
	ptr = strtok((char *)dest.c_str(), " ");
	ptr = strtok(NULL, " ");
	if(ptr == NULL)
		return 0;
	//printf("%s", ptr);

	return strtol(ptr, NULL, 0);
}

// 0 - SSL
// 1 - plain
int isSSL(const char *host, unsigned short port)
{
    int socket_descriptor;
    struct sockaddr_in server_info;
    int status_code = -1;

    if((socket_descriptor = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        memset(&server_info, 0, sizeof(server_info));
	    server_info.sin_family = AF_INET;
	    server_info.sin_port = htons(port);
	    if((server_info.sin_addr.s_addr = hostnameToIP(host)) != 0)
	    {
	        if(connect(socket_descriptor, (struct sockaddr *)&server_info, sizeof(server_info)) != -1)
	        {
                SSL_CTX *ssl_ctx;
                if((ssl_ctx = SSL_CTX_new(SSLv23_client_method())) != NULL)
                {
                    SSL *conn;
                    if((conn = SSL_new(ssl_ctx)) != NULL)
                    {
                        if(SSL_set_fd(conn, socket_descriptor) != 0)
                        {
                            // handshake successfully completed
                            if(SSL_connect(conn) == 1)
                                status_code = 0;
                            else
                                status_code = 1;
                        }
                        // This is blocking BIO, loop SSL_shutdown until it successfully completes
	                    while(SSL_shutdown(conn) == 0);
	                    SSL_free(conn);
                    }
                    SSL_CTX_free(ssl_ctx);
                }
            }
        }
    }

    close(socket_descriptor);
	return status_code;
}

// returns NULL on error, on success - address to dynamically allocated buffer containing response
// remember to free the memory using the pointer returned from this function
char *readResponse(const char *request, const char *host, unsigned short port)
{
	char *response = NULL;
	int socket_descriptor;
	struct sockaddr_in server_info;
    ssize_t request_s = strlen(request);
    ssize_t write_s;
    unsigned long counter = 0;
    char *tmp;
    int bytes = 0;
    int bytes_all = 0;

	if((socket_descriptor = socket(AF_INET, SOCK_STREAM, 0)) != -1)
	{
    	memset(&server_info, 0, sizeof(server_info));
	    server_info.sin_family = AF_INET;
	    server_info.sin_port = htons(port);
	    if((server_info.sin_addr.s_addr = hostnameToIP(host)) != 0)
	    {
	        if(connect(socket_descriptor, (struct sockaddr *)&server_info, sizeof(server_info)) != -1)
	        {
                write_s = write(socket_descriptor, request, request_s);
                if(write_s == request_s)
                {
                    do
                    {
                        counter += 1;
                        bytes_all += bytes;
                        tmp = (char *)realloc(response, BUFFER * counter);
                        if(tmp == NULL)
                        {
                            //"[Error] unable to reallocate memory"
                            free(response);
                            response = NULL;
                            break;
                        }

                        response = tmp;
                        // extended memory initialized to 0
                        memset(response + BUFFER * (counter - 1), 0, BUFFER);

                    } while((bytes = read(socket_descriptor, response + bytes_all, BUFFER)) > 0);
                }
            }
        }
    }

	close(socket_descriptor);
	return response;
}

char *readSSLResponse(const char *request, const char *host, unsigned short port)
{
	char *response = NULL;
	int socket_descriptor;
	struct sockaddr_in server_info;
    ssize_t request_s = strlen(request);
    ssize_t write_s;
    unsigned long counter = 0;
    char *tmp;
    int bytes = 0;
    int bytes_all = 0;

	//printf("%s\n", request);

    if((socket_descriptor = socket(AF_INET, SOCK_STREAM, 0)) != -1)
	{
    	memset(&server_info, 0, sizeof(server_info));
	    server_info.sin_family = AF_INET;
	    server_info.sin_port = htons(port);
	    if((server_info.sin_addr.s_addr = hostnameToIP(host)) != 0)
	    {
	        if(connect(socket_descriptor, (struct sockaddr *)&server_info, sizeof(server_info)) != -1)
	        {
                SSL_CTX *ssl_ctx;
                if((ssl_ctx = SSL_CTX_new(SSLv23_client_method())) != NULL)
                {
                    SSL *conn;
                    if((conn = SSL_new(ssl_ctx)) != NULL)
                    {
                        if(SSL_set_fd(conn, socket_descriptor) != 0)
                        {
                            if(SSL_connect(conn) == 1)
                            {
                                write_s = SSL_write(conn, request, request_s);
                                if(write_s == request_s)
                                {
                                    do
                                    {
                                        counter += 1;
                                        bytes_all += bytes;
                                        tmp = (char *)realloc(response, BUFFER * counter);
                                        if(tmp == NULL)
                                        {
                                            //"[Error] unable to reallocate memory"
                                            free(response);
                                            response = NULL;
                                            break;
                                        }

                                        response = tmp;
                                        // extended memory initialized to 0
                                        memset(response + BUFFER * (counter - 1), 0, BUFFER);

                                    } while((bytes = SSL_read(conn, response + bytes_all, BUFFER)) > 0);
                                }
                            }
                        }
                        // This is blocking BIO, loop SSL_shutdown until it successfully completes
	                    while(SSL_shutdown(conn) == 0);
	                    SSL_free(conn);
                    }
                    SSL_CTX_free(ssl_ctx);
                }
            }
        }
    }

	close(socket_descriptor);
	return response;
}

int sendData(const char *data, const char *host, unsigned short port)
{
	int socket_descriptor;
	struct sockaddr_in server_info;
	ssize_t status, total;
	int status_code = -1;

	if((socket_descriptor = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        memset(&server_info, 0, sizeof(server_info));
        server_info.sin_family = AF_INET;
        server_info.sin_port = htons(port);
        if((server_info.sin_addr.s_addr = hostnameToIP(host)) != 0)
        {
            if(connect(socket_descriptor, (struct sockaddr *)&server_info, sizeof(server_info)) != -1)
            {
                total = strlen(data);
                status = write(socket_descriptor, data, total);
                if(status == total)
                    status_code = 0;
            }
        }
    }

	close(socket_descriptor);
	return status_code;
}

int sendSSLData(const char *data, const char *host, unsigned short port)
{
	int socket_descriptor;
	struct sockaddr_in server_info;
	ssize_t status, total;
	int status_code = -1;

	if((socket_descriptor = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        memset(&server_info, 0, sizeof(server_info));
        server_info.sin_family = AF_INET;
        server_info.sin_port = htons(port);
        if((server_info.sin_addr.s_addr = hostnameToIP(host)) != 0)
        {
            if(connect(socket_descriptor, (struct sockaddr *)&server_info, sizeof(server_info)) != -1)
            {
                SSL_CTX *ssl_ctx;
                if((ssl_ctx = SSL_CTX_new(SSLv23_client_method())) != NULL)
                {
                    SSL *conn;
                    if((conn = SSL_new(ssl_ctx)) != NULL)
                    {
                        if(SSL_set_fd(conn, socket_descriptor) != 0)
                        {
                            if(SSL_connect(conn) == 1)
                            {
                                total = strlen(data);
                                status = SSL_write(conn, data, total);
                                if(status == total)
                                    status_code = 0;
                            }
                        }
                        // This is blocking BIO, loop SSL_shutdown until it successfully completes
                        while(SSL_shutdown(conn) == 0);
                        SSL_free(conn);
                    }
                    SSL_CTX_free(ssl_ctx);
                }
            }
        }
    }

	close(socket_descriptor);
	return status_code;
}

const char *extract_json_value(const char *response, const char **json_key)
{
    const char *value = response;
    size_t buf_len = 0;
    for(int i = 0; json_key[i] != NULL; i++)
    {
        buf_len = strlen(json_key[i]) + 4;
        char *buf = (char *)malloc(buf_len * sizeof(char));
        if(buf == NULL) return NULL;
        snprintf(buf, buf_len, "\"%s\":", json_key[i]);

        value = strstr(value, buf);
        free(buf);
        if(value == NULL) return NULL;
    }

    if(buf_len == 0)
        return NULL;

    value += buf_len - 1;
    return value;
}

template<typename T>
std::ostream &operator<<(std::ostream &stream, const std::unordered_map<std::string, T> &map)
{
    if(typeid(std::string) == typeid(T))
    {
        stream << "{";
        for(auto x = map.begin(); x != map.end(); )
        {
            stream << "\"" << x->first << "\"" << ": " << "\"" << x->second << "\"";
            if(++x != map.end()) stream << ",";
        }
        stream << "}";
    }
    else
    {
        stream << "{";
        for(auto x = map.begin(); x != map.end(); )
        {
            stream << "\"" << x->first << "\"" << ": " << x->second;
            if(++x != map.end()) stream << ",";
        }
        stream << "}";
    }
    return stream;
}
template std::ostream &operator<<(std::ostream &stream, const std::unordered_map<std::string, std::string> &map);
template std::ostream &operator<<(std::ostream &stream, const std::unordered_map<std::string, uint64_t> &map);

template<typename T>
std::string &operator<<(std::string &output, const std::unordered_map<std::string, T> &map)
{
    std::stringstream ss;
    if(typeid(std::string) == typeid(T))
    {
        ss << "{";
        for(auto x = map.begin(); x != map.end(); )
        {
            ss << "\"" << x->first << "\"" << ": " << "\"" << x->second << "\"";
            if(++x != map.end()) ss << ",";
        }
        ss << "}";
    }
    else
    {
        ss << "{";
        for(auto x = map.begin(); x != map.end(); )
        {
            ss << "\"" << x->first << "\"" << ": " << x->second;
            if(++x != map.end()) ss << ",";
        }
        ss << "}";
    }
    output += ss.str();
    return output;
}
template std::string &operator<<(std::string &output, const std::unordered_map<std::string, std::string> &map);
template std::string &operator<<(std::string &output, const std::unordered_map<std::string, uint64_t> &map);

template<typename T>
std::string &operator+(std::string &sum, const std::unordered_map<std::string, T> &map)
{
    if(map.empty())
        return sum;

    std::string tmp;
    tmp << map;
    if(!sum.empty())
    {
        sum.pop_back();
        sum += ",";
        sum += tmp.erase(0, 1);
    }
    else
    {
        sum += tmp;
    }

    return sum;
}
template std::string &operator+(std::string &sum, const std::unordered_map<std::string, std::string> &map);
template std::string &operator+(std::string &sum, const std::unordered_map<std::string, uint64_t> &map);
/*** END OF GENERIC HELPER FUNCTIONS ***/
/***************************************/
/***************************************/


/***************************************/
/***************************************/
/*********** NODE BASE CLASS ***********/
// methods common for both node and cluster stats
class Node
{
    int master_node_ip();

    protected:
    std::string masterNodeIP;
    std::string nodeIP;
    std::string nodeHostname;
    std::string base64auth;
    const char *elasticsearchIP;
    unsigned short elasticsearchPort;
    std::unordered_map<std::string, std::string> api_timestamp(const char *);
    char *(*get_data)(const char *, const char *, unsigned short);
    int (*send_data)(const char *, const char *, unsigned short);

    public:
    Node(const std::string &_base64auth, const std::string &_elasticsearchIP, unsigned short _elasticsearchPort): base64auth(_base64auth), elasticsearchIP(_elasticsearchIP.c_str()), elasticsearchPort(_elasticsearchPort)
    {
        int SSL = isSSL(elasticsearchIP, elasticsearchPort);
        if(SSL == 0)
        {
            get_data = &readSSLResponse;
            send_data = &sendSSLData;
        }
        else if(SSL == 1)
        {
            get_data = &readResponse;
            send_data = &sendData;
        }
        else
            throw std::runtime_error("Failed to construct Node object: Unable to communicate with cluster");

        if(node_hostname_ip(nodeHostname, nodeIP) == -1)
            throw std::runtime_error("Failed to construct Node object: Hostname/IP unknown");
        if(master_node_ip() == -1)
            throw std::runtime_error("Failed to construct Node object: Unable to determine master node");
    };

    int sendDataToElasticsearch(const std::string &data, const std::string &index, const std::string &type);
};

int Node::sendDataToElasticsearch(const std::string &data, const std::string &index, const std::string &type)
{
    // ISO8601 UTC timestamp
	struct tm *timeinfo;
	time_t rawtime = time(NULL);
	char timestamp[30];
	timeinfo = gmtime(&rawtime);
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", timeinfo);
    std::string data_str = data;
    data_str.pop_back();
    std::string elastic_data = data_str + ",\"@timestamp\": " + "\"" + timestamp + "\"}\n";

    std::string elastic_request = "POST /" + index + "/" + type + " HTTP/1.0\r\n" +
	"Content-type: application/json\r\n" +
    "Authorization: Basic " + base64auth + "\r\n" +
	"Content-length: " + std::to_string(elastic_data.size()) + "\r\n\r\n" +
	elastic_data;

    std::cout << elastic_request << std::endl;

    return send_data(elastic_request.c_str(), elasticsearchIP, elasticsearchPort);
}

std::unordered_map<std::string, std::string> Node::api_timestamp(const char *response)
{
    std::unordered_map<std::string, std::string> timestamp;
    const char *timestamp_ptr = NULL;
    if((timestamp_ptr = strstr(response, "timestamp\":")) == NULL) return timestamp;
    timestamp_ptr += strlen("timestamp\":");

    // epoch is composed of 13 digits in elasticsearch, we only need 10
    char time_buf[11];
    snprintf(time_buf, sizeof(time_buf), "%s", timestamp_ptr);

    char time_str[30];
    struct tm *timeinfo;
    time_t epoch = strtol(time_buf, NULL, 0);
    timeinfo = gmtime(&epoch);
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", timeinfo);
    timestamp.insert({"timestamp_api", time_str});

    return timestamp;
}

int Node::master_node_ip()
{
    std::string elastic_request = "GET /_cat/master HTTP/1.0\r\nAccept: text/plain\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
    const char *response = get_data(elastic_request.c_str(), elasticsearchIP, elasticsearchPort);
    if(response == NULL) return -1;
    if(getHttpStatus(response) != 200) return -1;
    response = remove_headers((char **)&response);

    std::istringstream istream(response);
    std::string tmp;
    istream >> tmp >> tmp >> masterNodeIP;

    free((char *)response);
    return 0;
}
/******* END OF NODE BASE CLASS *******/
/**************************************/
/**************************************/


/**************************************/
/**************************************/
/********* CLUSTER API CLASS **********/
class ClusterStats : public Node
{
    const char *api_response;
    const char *api_health_response;
    const char *pending_tasks_response;

    std::unordered_map<std::string, uint64_t> api_stats();
    std::unordered_map<std::string, float> api_health();
    std::unordered_map<std::string, uint64_t> pending_tasks(); 
    

    public:
    ClusterStats(const std::string &_base64auth, const std::string &_elasticsearchIP, unsigned short _elasticsearchPort): Node(_base64auth, _elasticsearchIP, _elasticsearchPort)
    {
        if(nodeIP != masterNodeIP)
            throw std::runtime_error("Failed to construct ClusterStats object: It is not a master node");

        std::string elastic_request = "GET /_cluster/stats HTTP/1.0\r\nContent-type: application/json\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
        api_response = get_data(elastic_request.c_str(), elasticsearchIP, elasticsearchPort);
        elastic_request = "GET /_cluster/health HTTP/1.0\r\nContent-type: application/json\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
	    api_health_response = get_data(elastic_request.c_str(), elasticsearchIP, elasticsearchPort);
        elastic_request = "GET /_cluster/pending_tasks HTTP/1.0\r\nContent-type: application/json\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
        pending_tasks_response = get_data(elastic_request.c_str(), elasticsearchIP, elasticsearchPort);
        if(api_response == NULL || api_health_response == NULL || pending_tasks_response == NULL)
            throw std::runtime_error("Failed to construct ClusterStats object: NULL response");
    };
    ~ClusterStats(){free((char *)api_response); free((char *)api_health_response); free((char *)pending_tasks_response);};

    std::string get_api_stats()
    {
        std::string json_output;
        json_output = json_output + api_timestamp(api_response) + hostname_ip() + api_stats() + api_health() + pending_tasks();

        return json_output;
    };
};

std::unordered_map<std::string, float> ClusterStats::api_health()
{
    std::unordered_map<std::string, float> stats;
    if(getHttpStatus(api_health_response) != 200) return stats;
    api_health_response = remove_headers((char **)&api_health_response);
    const char *value = NULL;

    const int col = 7;
    const int row = 2;
    const char *keys[col][row] = 
    {
        {"active_shards_percent_as_number", NULL},
        {"status", NULL},
        {"number_of_nodes", NULL},
        {"initializing_shards", NULL},
        {"unassigned_shards", NULL},
        {"active_primary_shards", NULL},
        {"active_shards", NULL}
    };

    for(int i = 0; i < col; i++)
    {
        if((value = extract_json_value(api_health_response, keys[i])) != NULL)
        {
            if(i == 0)
                stats.insert({"cluster_stats_availability", strtof(value, NULL)});
            else if(i == 1)
            {
                std::string cluster_health_status(value);
                float status = -1;
                if(cluster_health_status.find("green") != std::string::npos)
                    status = 2;
                else if(cluster_health_status.find("yellow") != std::string::npos)
                    status = 1;
                else if(cluster_health_status.find("red") != std::string::npos)
                    status = 0;

                stats.insert({"cluster_health_status", status});
            }
            else
                stats.insert({"cluster_health_" + std::string(keys[i][0]), strtof(value, NULL)});
        }
    }

    return stats;
}

std::unordered_map<std::string, uint64_t> ClusterStats::api_stats()
{
    std::unordered_map<std::string, uint64_t> stats;
    if(getHttpStatus(api_response) != 200) return stats;
    api_response = remove_headers((char **)&api_response);
    const char *value = NULL;

    const int col = 43;
    const int row = 10;
    const char *keys[col][row] =
    {
        {"nodes", "count", "total", NULL},
        {"nodes", "os", "mem", "total_in_bytes", NULL},
        {"nodes", "jvm", "mem", "heap_used_in_bytes", NULL},
        {"nodes", "jvm", "mem", "heap_max_in_bytes", NULL},
        {"indices", "count", NULL},
        {"indices", "shards", "total", NULL},
        {"indices", "shards", "index", "shards", "min", NULL},
        {"indices", "shards", "index", "shards", "max", NULL},
        {"indices", "shards", "index", "primaries", "min", NULL},
        {"indices", "shards", "index", "primaries", "max", NULL},
        {"indices", "shards", "index", "replication", "min", NULL},
        {"indices", "shards", "index", "replication", "max", NULL},
        {"indices", "docs", "count", NULL},
        {"indices", "docs", "deleted", NULL},
        {"indices", "store", "size_in_bytes", NULL},
        {"indices", "store", "throttle_time_in_millis", NULL},
        {"indices", "fielddata", "memory_size_in_bytes", NULL},
        {"indices", "fielddata", "evictions", NULL},
        {"indices", "query_cache", "memory_size_in_bytes", NULL},
        {"indices", "query_cache", "total_count", NULL},
        {"indices", "query_cache", "hit_count", NULL},
        {"indices", "query_cache", "miss_count", NULL},
        {"indices", "query_cache", "cache_size", NULL},
        {"indices", "query_cache", "cache_count", NULL},
        {"indices", "query_cache", "evictions", NULL},
        {"indices", "segments", "count", NULL},
        {"indices", "segments", "memory_in_bytes", NULL},
        {"indices", "segments", "terms_memory_in_bytes", NULL},
        {"indices", "segments", "stored_fields_memory_in_bytes", NULL},
        {"indices", "segments", "term_vectors_memory_in_bytes", NULL},
        {"indices", "segments", "norms_memory_in_bytes", NULL},
        {"indices", "segments", "doc_values_memory_in_bytes", NULL},
        {"indices", "segments", "index_writer_memory_in_bytes", NULL},
        {"indices", "segments", "index_writer_max_memory_in_bytes", NULL},
        {"indices", "segments", "version_map_memory_in_bytes", NULL},
        {"indices", "segments", "fixed_bit_set_memory_in_bytes", NULL},
        {"nodes", "os", "available_processors", NULL},
        {"nodes", "os", "allocated_processors", NULL},
        {"nodes", "process", "cpu", "percent", NULL},
        {"nodes", "process", "open_file_descriptors", "min", NULL},
        {"nodes", "process", "open_file_descriptors", "max", NULL},
        {"nodes", "fs", "total_in_bytes", NULL},
        {"nodes", "fs", "free_in_bytes", NULL}
    };

    for(int i = 0; i < col; i++)
    {
        if((value = extract_json_value(api_response, keys[i])) != NULL)
        {
            std::string description = "cluster_stats";
            for(int j = 0; keys[i][j] != NULL; j++)
            {
                description += "_";
                description += keys[i][j];
            }

            stats.insert({description, strtol(value, NULL, 0)});
        }
    }

    return stats;
}

std::unordered_map<std::string, uint64_t> ClusterStats::pending_tasks()
{
    std::unordered_map<std::string, uint64_t> stats;
    
    if(getHttpStatus(pending_tasks_response) != 200) return stats;
    pending_tasks_response = remove_headers((char **)&pending_tasks_response);
    std::string json_response(this->pending_tasks_response);
    
    std::size_t found = -1;
    uint64_t pending_tasks_total = -1;
    while((found = json_response.find('{', found + 1)) != std::string::npos) 
    {
        ++pending_tasks_total;
    }

    stats.insert({"pending_tasks_total", pending_tasks_total});

    found = -1;
    uint64_t pending_tasks_urgent = 0;
    while((found = json_response.find("URGENT", found + 1)) != std::string::npos) 
    {
        ++pending_tasks_urgent;
    }

    stats.insert({"pending_tasks_urgent", pending_tasks_urgent});

    found = -1;
    uint64_t pending_tasks_high = 0;
    while((found = json_response.find("HIGH", found + 1)) != std::string::npos) 
    {
        ++pending_tasks_high;
    }

    stats.insert({"pending_tasks_high", pending_tasks_high});

    return stats;
}

/****** END OF CLUSTER API CLASS ******/
/**************************************/
/**************************************/


/**************************************/
/**************************************/
/*********** NODE API CLASS ***********/
class NodeStats : public Node
{
    // API
    const char *api_response;

    std::unordered_map<std::string, uint64_t> api_stats();

    public:
        NodeStats(const std::string &_base64auth, const std::string &_elasticsearchIP, unsigned short _elasticsearchPort): Node(_base64auth, _elasticsearchIP, _elasticsearchPort)
        {
            const std::string elastic_request = "GET /_nodes/" + nodeIP + "/stats HTTP/1.0\r\nContent-type: application/json\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
            api_response = get_data(elastic_request.c_str(), elasticsearchIP, elasticsearchPort);
            if(api_response == NULL)
                throw std::runtime_error("Failed to construct NodeStats object: NULL response");
        };
        ~NodeStats(){free((char *)api_response);};

        std::string get_api_stats()
        {
            std::string json_output;
            json_output = json_output + api_timestamp(api_response) + hostname_ip() + api_stats();

            return json_output;
        };
};

std::unordered_map<std::string, uint64_t> NodeStats::api_stats()
{
    std::unordered_map<std::string, uint64_t> stats;
    if(getHttpStatus(api_response) != 200) return stats;
    api_response = remove_headers((char **)&api_response);
    const char *value = NULL;

    const int col = 63;
    const int row = 10;
    const char *keys[col][row] =
    {
        {"indices", "docs", "count", NULL},
        {"indices", "docs", "deleted", NULL},
        {"indices", "store", "size_in_bytes", NULL},
        {"indices", "store", "throttle_time_in_millis", NULL},
        {"indices", "indexing", "index_total", NULL},
        {"indices", "indexing", "index_time_in_millis", NULL},
        {"indices", "indexing", "index_current", NULL},
        {"indices", "indexing", "index_failed", NULL},
        {"indices", "indexing", "delete_total", NULL},
        {"indices", "indexing", "delete_time_in_millis", NULL},
        {"indices", "indexing", "delete_current", NULL},
        {"indices", "indexing", "noop_update_total", NULL},
        {"indices", "indexing", "is_throttled", NULL},
        {"indices", "indexing", "throttle_time_in_millis", NULL},
        {"indices", "get", "missing_total", NULL},
        {"indices", "get", "missing_time_in_millis", NULL},
        {"indices", "search", "open_contexts", NULL},
        {"indices", "search", "query_total", NULL},
        {"indices", "search", "query_time_in_millis", NULL},
        {"indices", "search", "query_current", NULL},
        {"indices", "search", "fetch_total", NULL},
        {"indices", "search", "fetch_time_in_millis", NULL},
        {"indices", "search", "fetch_current", NULL},
        {"indices", "search", "scroll_total", NULL},
        {"indices", "search", "scroll_time_in_millis", NULL},
        {"indices", "search", "scroll_current", NULL},
        {"indices", "segments", "count", NULL},
        {"indices", "segments", "memory_in_bytes", NULL},
        {"indices", "segments", "terms_memory_in_bytes", NULL},
        {"indices", "segments", "stored_fields_memory_in_bytes", NULL},
        {"indices", "segments", "term_vectors_memory_in_bytes", NULL},
        {"indices", "segments", "norms_memory_in_bytes", NULL},
        {"indices", "segments", "doc_values_memory_in_bytes", NULL},
        {"indices", "segments", "index_writer_memory_in_bytes", NULL},
        {"indices", "segments", "index_writer_max_memory_in_bytes", NULL},
        {"indices", "segments", "version_map_memory_in_bytes", NULL},
        {"indices", "segments", "fixed_bit_set_memory_in_bytes", NULL},
        {"indices", "refresh", "total", NULL},
        {"indices", "refresh", "total_time_in_millis", NULL},
        {"indices", "flush", "total", NULL},
        {"indices", "flush", "total_time_in_millis", NULL},
        {"os", "cpu", "percent", NULL},
        {"os", "mem", "total_in_bytes", NULL},
        {"os", "mem", "free_in_bytes", NULL},
        {"os", "swap", "total_in_bytes", NULL},
        {"os", "swap", "free_in_bytes", NULL},
        {"process", "open_file_descriptors", NULL},
        {"process", "max_file_descriptors", NULL},
        {"process", "cpu", "percent", NULL},
        {"process", "mem", "total_virtual_in_bytes", NULL},
        {"jvm", "mem", "heap_used_in_bytes", NULL},
        {"jvm", "mem", "heap_used_percent", NULL},
        {"jvm", "mem", "heap_max_in_bytes", NULL},
        {"jvm", "mem", "heap_committed_in_bytes", NULL},
        {"jvm", "gc", "collectors", "young", "collection_count", NULL},
        {"jvm", "gc", "collectors", "young", "collection_time_in_millis", NULL},
        {"jvm", "gc", "collectors", "old", "collection_count", NULL},
        {"jvm", "gc", "collectors", "old", "collection_time_in_millis", NULL},
        {"thread_pool", "bulk", "rejected", NULL},
        {"thread_pool", "index", "rejected", NULL},
        {"thread_pool", "search", "rejected", NULL},
        {"fs", "total", "total_in_bytes", NULL},
        {"fs", "total", "free_in_bytes", NULL}
    };

    for(int i = 0; i < col; i++)
    {
        if((value = extract_json_value(api_response, keys[i])) != NULL)
        {
            std::string description = "node_stats";
            for(int j = 0; keys[i][j] != NULL; j++)
            {
                description += "_";
                description += keys[i][j];
            }

            if(description == "node_stats_indices_indexing_is_throttled")
            {
                char bool_max[6];
                size_t bool_size = strcspn(value, ",");
                snprintf(bool_max, bool_size + 1, "%s", value);
                uint64_t indices_indexing_is_throttled = (std::string(bool_max) == "true") ? 1 : 0;
                stats.insert({"node_stats_indices_indexing_is_throttled", indices_indexing_is_throttled});
            }
            else
                stats.insert({description, strtol(value, NULL, 0)});
        }
    }

    return stats;
}
/******** END OF NODE API CLASS ********/
/***************************************/
/***************************************/

/**************************************/
/**************************************/
/********* LOGSTASH API CLASS *********/

class LogstashStats
{
    // API
    const char *api_response;
    const char *logstashIP;
    unsigned short logstashPort;

    std::unordered_map<std::string, uint64_t> api_stats();
    std::unordered_map<std::string, float> cpu_load();

    public:
        LogstashStats(const std::string &_logstashIP, unsigned short _logstashPort): logstashIP(_logstashIP.c_str()), logstashPort(_logstashPort)
        {
            const std::string logstash_request = "GET /_node/stats/?human=false HTTP/1.0\r\nContent-type: application/json\r\n\r\n";
            api_response = readResponse(logstash_request.c_str(), logstashIP, logstashPort);
            if(api_response == NULL)
                throw std::runtime_error("Failed to construct LogstashStats object: NULL response");
            if(getHttpStatus(api_response) != 200)
                throw std::runtime_error("Failed to construct LogstashStats object: Got != 200 status code");
            else if(api_response != NULL)
                api_response = remove_headers((char **)&api_response);
        };
        ~LogstashStats(){free((char *)api_response);};

        std::string get_api_stats()
        {
            std::string json_output;
            json_output = json_output + hostname_ip() + api_stats() + cpu_load();

            return json_output;
        };
};

std::unordered_map<std::string, float> LogstashStats::cpu_load()
{
    std::unordered_map<std::string, float> stats;
    const char *value = NULL;

    const int col = 3;
    const int row = 4;
    const char *keys[col][row] =
    {
        {"cpu", "load_average", "1m", NULL},
        {"cpu", "load_average", "5m", NULL},
        {"cpu", "load_average", "15m", NULL}
    };

    for(int i = 0; i < col; i++)
    {
        if((value = extract_json_value(api_response, keys[i])) != NULL)
        {
            std::string description = "logstash_stats";
            for(int j = 0; keys[i][j] != NULL; j++)
            {
                description += "_";
                description += keys[i][j];
            }

            stats.insert({description, strtof(value, NULL)});
        }
    }

    return stats;
}

std::unordered_map<std::string, uint64_t> LogstashStats::api_stats()
{
    std::unordered_map<std::string, uint64_t> stats;
    const char *value = NULL;

    const int col = 23;
    const int row = 10;
    const char *keys[col][row] =
    {
        {"jvm", "threads", "count", NULL},
        {"jvm", "threads", "peak_count", NULL},
        {"mem", "heap_used_percent", NULL},
        {"mem", "heap_committed_in_bytes", NULL},
        {"mem", "heap_max_in_bytes", NULL},
        {"mem", "heap_used_in_bytes", NULL},
        {"mem", "non_heap_used_in_bytes", NULL},
        {"mem", "non_heap_committed_in_bytes", NULL},
        {"gc", "collectors", "old", "collection_time_in_millis", NULL},
        {"gc", "collectors", "old", "collection_count", NULL},
        {"gc", "collectors", "young", "collection_time_in_millis", NULL},
        {"gc", "collectors", "young", "collection_count", NULL},
        {"process", "open_file_descriptors", NULL},
        {"process", "peak_open_file_descriptors", NULL},
        {"process", "max_file_descriptors", NULL},
        {"process", "mem", "total_virtual_in_bytes", NULL},
        {"cpu", "total_in_millis", NULL},
        {"cpu", "percent", NULL},
        {"events", "in", NULL},
        {"events", "filtered", NULL},
        {"events", "out", NULL},
        {"events", "duration_in_millis", NULL},
        {"events", "queue_push_duration_in_millis", NULL}
    };

    for(int i = 0; i < col; i++)
    {
        if((value = extract_json_value(api_response, keys[i])) != NULL)
        {
            std::string description = "logstash_stats";
            for(int j = 0; keys[i][j] != NULL; j++)
            {
                description += "_";
                description += keys[i][j];
            }

            stats.insert({description, strtol(value, NULL, 0)});
        }
    }

    return stats;
}

/****** END OF LOGSTASH API CLASS ******/
/***************************************/
/***************************************/

/***************************************/
/***************************************/
/************ OS FUNCTIONS *************/
std::unordered_map<std::string, std::string> hostname_ip()
{
    std::unordered_map<std::string, std::string> address;
    std::string hostname, ip;

    if(node_hostname_ip(hostname, ip) == -1) return address;
    address.insert({"source_node_host", hostname});
    address.insert({"source_node_ip", ip});
    return address;
}

std::unordered_map<std::string, uint64_t> fs_stats()
{
    std::unordered_map<std::string, uint64_t> fs;
    FILE* file = NULL;
    if((file = fopen("/etc/fstab", "r")) == NULL)
        return fs;

    struct mntent* fstab;
    struct statfs buf;

    while((fstab = getmntent(file)) != NULL)
    {
        if(!strcmp(fstab->mnt_type, "swap")) continue;
        if(statfs(fstab->mnt_dir, &buf) != 0) break;

        uint64_t space_total = buf.f_bsize * buf.f_blocks;
        uint64_t space_free = buf.f_bsize * buf.f_bfree;
        uint64_t space_used = space_total - space_free;
        std::string space_total_str = "node_stats_" + std::string(fstab->mnt_dir) + "_space_total_in_bytes";
        std::string space_free_str = "node_stats_" + std::string(fstab->mnt_dir) + "_space_free_in_bytes";
        std::string space_used_str = "node_stats_" + std::string(fstab->mnt_dir) + "_space_used_in_bytes";
        fs.insert({space_total_str, space_total});
        fs.insert({space_free_str, space_free});
        fs.insert({space_used_str, space_used});

        uint64_t inode_total = buf.f_files;
        uint64_t inode_free = buf.f_ffree;
        uint64_t inode_used = inode_total - inode_free;
        std::string inode_total_str = "node_stats_" + std::string(fstab->mnt_dir) + "_inode_total";
        std::string inode_free_str = "node_stats_" + std::string(fstab->mnt_dir) + "_inode_free";
        std::string inode_used_str = "node_stats_" + std::string(fstab->mnt_dir) + "_inode_used";
        fs.insert({inode_total_str, inode_total});
        fs.insert({inode_free_str, inode_free});
        fs.insert({inode_used_str, inode_used});
    }


    endmntent(file);
    // on CentOS7 double free error
    //fclose(file);
    return fs;
}

std::unordered_map<std::string, uint64_t> swap_stats()
{
    std::unordered_map<std::string, uint64_t> swap;
    std::ifstream ifs("/proc/swaps");
    std::string line;
    // store the first line after header
    std::getline(ifs, line);
    if(!std::getline(ifs, line)) return swap;

    std::istringstream iss(line);
    std::string tmp;
    uint64_t swap_total, swap_used, swap_free;
    iss >> tmp >> tmp >> swap_total >> swap_used;
    swap_free = swap_total - swap_used;

    swap.insert({"node_stats_swap_space_total_in_kilobytes", swap_total});
    swap.insert({"node_stats_swap_space_free_in_kilobytes", swap_free});
    swap.insert({"node_stats_swap_space_used_in_kilobytes", swap_used});

    ifs.close();
    return swap;
}

std::unordered_map<std::string, std::string> process_pid(const char *name)
{
    std::unordered_map<std::string, std::string> process;
    DIR *dir;
    std::ifstream cmdline;
    std::string line;
    std::size_t found;
    std::string pid_str = "node_stats_" + std::string(name) + "_pid";
    char filename[300];
    struct dirent *ent;
    if((dir = opendir("/proc")) == NULL) return process;

    while((ent = readdir(dir)) != NULL)
    {
        if(ent->d_type != DT_DIR) continue;
        //std::cout << ent->d_name << std::endl;
        snprintf(filename, 7, "/proc/");
        strcat(filename, ent->d_name);
        strcat(filename, "/cmdline");
        cmdline.open(filename);
        /*** read /proc/pid/cmdline if present ***/
        if(!cmdline.good()) continue;
        std::getline(cmdline, line);
        cmdline.close();

        /*** if /proc/pid/cmdline starts with process name then save pid ***/
        if((found = line.find(name)) != std::string::npos && found == 0)
        {
            process.insert({pid_str, ent->d_name});
            break;
        }
    }

    closedir(dir);
    return process;
}

std::unordered_map<std::string, uint64_t> zombie_count()
{
    std::unordered_map<std::string, uint64_t> zombie;
    DIR *dir;
    std::ifstream stat;
    std::string line;
    uint64_t count = 0;
    std::istringstream iss;
    std::string tmp, third_field;
    char filename[300];
    struct dirent *ent;
    if((dir = opendir("/proc")) == NULL) return zombie;

    while((ent = readdir(dir)) != NULL)
    {
        if(ent->d_type != DT_DIR) continue;
        //std::cout << ent->d_name << std::endl;
        snprintf(filename, 7, "/proc/");
        strcat(filename, ent->d_name);
        strcat(filename, "/stat");
        stat.open(filename);
        /*** read /proc/pid/stat if present ***/
        if(!stat.good()) continue;
        std::getline(stat, line);
        stat.close();

        /*** if third field is Z then increment the count ***/
        iss.str(line);
        iss >> tmp >> tmp >> third_field;
        //std::cout << third_field << std::endl;
        if(third_field == "Z") ++count;
    }

    zombie.insert({"node_stats_zombie_processes_count", count});
    closedir(dir);
    return zombie;
}

std::unordered_map<std::string, uint64_t> net_stats()
{
    std::unordered_map<std::string, uint64_t> net;
    DIR *dir, *dir2;
    struct dirent *ent, *ent2;
    std::string path = "/sys/class/net/";
    std::string path2;
    std::ifstream file;
    std::string line;
    std::istringstream iss;
    uint64_t value;

    if((dir = opendir(path.c_str())) == NULL) return net;
    while((ent = readdir(dir)) != NULL)
    {
        path2 = path + ent->d_name + "/statistics/";
        if((dir2 = opendir(path2.c_str())) == NULL) continue;
        while((ent2 = readdir(dir2)) != NULL)
        {
            if(!(strcmp(ent2->d_name, ".") && strcmp(ent2->d_name, ".."))) continue;
            file.open(path2 + ent2->d_name);
            if(!file.good()) continue;
            std::getline(file, line);
            file.close();
            iss.str(line);
            iss >> value;
            iss.clear();
            net.insert({"node_stats_" + std::string(ent->d_name) + "_" + std::string(ent2->d_name), value});
        }
        closedir(dir2);
    }

    closedir(dir);
    return net;
}

std::unordered_map<std::string, uint64_t> cpu_stats()
{
    std::unordered_map<std::string, uint64_t> processor;
    std::string line;
    std::ifstream stat;
    uint64_t idle_time[2];
    uint64_t busy_time[2];
    uint64_t total_time[2];
    uint64_t iowait_time[2];
    const struct timespec req = {1, 0};
    struct timespec rem;

    for(int i = 0; i < 2; i++)
    {
        stat.open("/proc/stat");
        if(!std::getline(stat, line)) return processor;
        stat.close();

        std::istringstream istream(line);
        std::string cpu;
        uint64_t user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
        istream >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal >> guest >> guest_nice;

        iowait_time[i] = iowait;
        idle_time[i] = idle + iowait;
        busy_time[i] = user + nice + system + irq + softirq + steal + guest + guest_nice;
        total_time[i] = idle_time[i] + busy_time[i];

        if(i == 0) nanosleep(&req, &rem);
    }

    uint64_t busy_time_percent = 100 * (busy_time[1] - busy_time[0]) / (total_time[1] - total_time[0]);
    uint64_t iowait_percent = 100 * (iowait_time[1] - iowait_time[0]) / (total_time[1] - total_time[0]);
    processor.insert({"node_stats_cpu_busy_percent", busy_time_percent});
    processor.insert({"node_stats_cpu_iowait_percent", iowait_percent});
    return processor;
}

std::unordered_map<std::string, uint64_t> vm_stats()
{
    std::unordered_map<std::string, uint64_t> vm;
    std::ifstream file;
    std::string line, match;
    std::istringstream iss;
    uint64_t value[2];
    const struct timespec req = {1, 0};
    struct timespec rem;

    for(int i = 0; i < 2; i++)
    {
        file.open("/proc/vmstat");
        if(!file.good()) return vm;
        while(std::getline(file, line))
        {
            iss.str(line);
            iss >> match >> value[i];
            iss.clear();
            if(match == "pgpgout") break;
        }
        file.close();
        if(i == 0) nanosleep(&req, &rem);
    }

    vm.insert({"node_stats_pgpgout_per_sec", value[1] - value[0]});
    return vm;
}

std::unordered_map<std::string, std::string> systemd_service_status(const std::string &service, bool skip_unknown = true)
{
    std::unordered_map<std::string, std::string> service_status;
    std::string status;
    if(getCommandOutput("systemctl is-active " + service, status) != -1)
    {
	if(skip_unknown)
	{
		if(status != "unknown") service_status.insert({"node_stats_systemd_service_" + service, status});
	}
	else
	{
		service_status.insert({"node_stats_systemd_service_" + service, status});
	}
    }

    return service_status;
}

std::unordered_map<std::string, std::string> is_address_in_use(const std::string &ip, const int port, bool skip_unused = true)
{
	std::unordered_map<std::string, std::string> port_status;
	int socket_descriptor;
	struct sockaddr_in server_info;

	if((socket_descriptor = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		//const char *msg = "[Error] could not create socket";
		return port_status;
	}

	memset(&server_info, 0, sizeof(server_info));
	server_info.sin_family = AF_INET;
	server_info.sin_port = htons(port);
	if((server_info.sin_addr.s_addr = hostnameToIP(ip.c_str())) == 0)
	{
		//const char *msg = "[Error] incorrect address was given";
		return port_status;
	}
	errno = 0;
	bind(socket_descriptor, (struct sockaddr *)&server_info, sizeof(server_info));
	switch(errno)
	{
		case 0:
			if(!skip_unused)
				port_status.insert({"node_stats_tcp_port_" + std::to_string(port), "unused"});
		break;
		case EADDRINUSE:
			port_status.insert({"node_stats_tcp_port_" + std::to_string(port), "in_use"});
		break;
	}

	close(socket_descriptor);
	return port_status;
}
/********* END OF OS FUNCTIONS *********/
/***************************************/
/***************************************/

int writeToLog(const char *filename, const char *message)
{
        FILE *logFile = fopen(filename, "a");
        if(logFile == NULL){fprintf(stderr, "cannot open log file\n");return -1;}
        struct tm *timeinfo;
        time_t rawtime = time(NULL);

        // stores time information
        char time_buffer[20];

        timeinfo = localtime(&rawtime);
        strftime(time_buffer, sizeof(time_buffer), "%d-%m-%Y %H:%M:%S", timeinfo);
        fprintf(logFile, "%s: %s\n", time_buffer, message);

        fclose(logFile);
        return 0;
}

void appendDateNow(std::string &arg, const char *dateFormat)
{
	struct tm *timeinfo;
	time_t rawtime = time(NULL);
	char timestamp[20];
	timeinfo = gmtime(&rawtime);
	strftime(timestamp, sizeof(timestamp), dateFormat, timeinfo);
	arg = arg + "-" + timestamp;
}

int isStrCsv(const std::string &str, const char delim)
{
        const int exit_failure = -1;
        const int exit_success = 0;

        // one column without delim
        unsigned column_num_ref = 1;

        if(str.empty()) return exit_failure;

        std::istringstream iss(str);
        std::string line;
        while(std::getline(iss, line))
        {
            // count number of columns
            unsigned column_num = 1;
            int i = 0;
            for(char c: line)
            {
                if(c == delim)
                    column_num += 1;

                ++i;
            }
            if(column_num == 1)
                return exit_failure;

            // the first line is reference
            if(column_num_ref == 1)
                column_num_ref = column_num;
            if(column_num != column_num_ref)
                return exit_failure;
        }

        return exit_success;
}

// -1 cannot open file
// 1 file empty
// 0 file exists and not empty
int isFileEmpty(const char *filename, std::string &fContent)
{
    std::ifstream file;
    file.open(filename);
    if(!file.good()) return -1;
    unsigned long fsize = 0;
    file.seekg(0, file.end);
    fsize = file.tellg();
    file.seekg(0, file.beg);

    std::stringstream ss;
    ss << file.rdbuf();
    fContent = ss.str();
    file.close();

    if(fsize == 0) return 1;
    return 0;
}

std::vector<std::string>* checkCsv(const char *csvDir, const char *logFile)
{
    bool found;
    std::string csvPath;
    static std::vector<std::string> * const csvList = new std::vector<std::string>;
    DIR *dir;
    struct dirent *ent;
    if((dir = opendir(csvDir)) == NULL) return csvList;

    while((ent = readdir(dir)) != NULL)
    {
        if(ent->d_type != DT_REG) continue;
        found = false;
        csvPath = std::string(csvDir) + "/" + std::string(ent->d_name);
        for(const std::string &tmp: *csvList)
        {
            if(tmp == csvPath)
            {
                found = true;
                break;
            }
        }
        if(found == false)
        {
            (*csvList).push_back(csvPath);
            std::string msg, fileContent;
            switch (isFileEmpty(csvPath.c_str(), fileContent))
            {
                case -1:
                    msg = "Could not open file for reading: " + csvPath;
                    writeToLog(logFile, msg.c_str());
                break;
                case 0:
                    if(isStrCsv(fileContent, ',') == -1)
                    {
                        msg = "The following file has failed csv validation: " + csvPath;
                        writeToLog(logFile, msg.c_str());
                    }
                    else
                    {
                        msg = "The following file has passed csv validation: " + csvPath;
                        writeToLog(logFile, msg.c_str());
                    }
                break;
                case 1:
                    msg = "The following file is empty: " + csvPath;
                    writeToLog(logFile, msg.c_str());
                break;
            }
        }
    }

    closedir(dir);
    return csvList;
}

void checkCsvByPattern(const char *csvDirPattern, const char *logFile)
{
    glob_t pglob;
    std::vector<std::string> csvInAllDirs;
    std::vector<std::string> *csvList;

    if(glob(csvDirPattern, GLOB_NOSORT | GLOB_ONLYDIR, NULL, &pglob) != 0) return;

    // gather csv from all directories
    for(size_t i = 0; i < pglob.gl_pathc; i++)
    {
        DIR *dir;
        struct dirent *ent;
        std::string csvPath;
        if((dir = opendir(pglob.gl_pathv[i])) == NULL) return;
        while((ent = readdir(dir)) != NULL)
        {
            if(ent->d_type != DT_REG) continue;
            csvPath = std::string(pglob.gl_pathv[i]) + "/" + std::string(ent->d_name);
            csvInAllDirs.push_back(csvPath);
        }
        closedir(dir);
    }

    // check if dirs contain proper csvs
    for(size_t i = 0; i < pglob.gl_pathc; i++)
        csvList = checkCsv(pglob.gl_pathv[i], logFile);

    // free memory
    globfree(&pglob);
    for(size_t i = 0; i < (*csvList).size(); i++)
    {
        if(std::find(csvInAllDirs.begin(), csvInAllDirs.end(), (*csvList).at(i)) == csvInAllDirs.end())
        {
            (*csvList).erase((*csvList).begin() + i);
            --i;
        }
    }

    // TODO: delete vector on SIGTERM in main
}

void printHelp()
{
	std::cout << "Usage for skimmer version 1.0.8" << std::endl;
    std::cout << "\t\t-h print this help message" << std::endl;
    std::cout << "\t\t-c path to configuration file" << std::endl;
    std::cout << "\t\t-s print sample configuration file" << std::endl;
}

void printSampleConfig()
{
    std::cout << "\t\t# index name in elasticsearch" << std::endl;
    std::cout << "\t\tindex_name = skimmer" << std::endl;
    std::cout << "\t\tindex_freq = monthly" << std::endl << std::endl;

    std::cout << "\t\t# type in elasticsearch index" << std::endl;
    std::cout << "\t\tindex_type = _doc" << std::endl << std::endl;

    std::cout << "\t\t# user and password to elasticsearch api" << std::endl;
    std::cout << "\t\telasticsearch_auth = logserver:logserver" << std::endl << std::endl;

    std::cout << "\t\t# available outputs" << std::endl;
    std::cout << "\t\telasticsearch_address = 127.0.0.1:9200" << std::endl;
    std::cout << "\t\t# logstash_address = 127.0.0.1:6110" << std::endl << std::endl;

    std::cout << "\t\t# retrieve from api" << std::endl;
    std::cout << "\t\t# logstash_api = 127.0.0.1:9600" << std::endl << std::endl;

    std::cout << "\t\t# path to log file" << std::endl;
    std::cout << "\t\tlog_file = /tmp/skimmer.log" << std::endl << std::endl;

    std::cout << "\t\t# daemonize" << std::endl;
    std::cout << "\t\tdaemonize = true" << std::endl << std::endl;

    std::cout << "\t\t# comma separated OS statistics selected from the list [zombie,vm,fs,swap,net,cpu]" << std::endl;
    std::cout << "\t\tos_stats = zombie,vm,fs,swap,net,cpu" << std::endl << std::endl;

    std::cout << "\t\t# comma separated process names to print their pid" << std::endl;
    std::cout << "\t\tprocesses = /usr/sbin/sshd,/usr/sbin/rsyslogd" << std::endl << std::endl;

    std::cout << "\t\t# comma separated systemd services to print their status" << std::endl;
    std::cout << "\t\tsystemd_services = elasticsearch,logstash" << std::endl << std::endl;

    std::cout << "\t\t# comma separated port numbers to print if address is in use" << std::endl;
    std::cout << "\t\tport_numbers = 9200,9300,9600" << std::endl << std::endl;

    std::cout << "\t\t# path to directory containing files needed to be csv validated" << std::endl;
    std::cout << "\t\tcsv_path = /tmp/csv_dir" << std::endl;
}

struct Args
{
    std::string indexName;
    std::string indexType;
    std::string base64auth;
    std::string logFile;
    std::string elasticsearchIP;
    size_t elasticsearchPort;
    std::string logstashIP;
    size_t logstashPort;
    std::string logstashIPApi;
    size_t logstashPortApi;
    bool daemonize;
	std::string indexFreq;

    std::vector<std::string> systemdS;
    std::vector<std::string> os;
    std::vector<std::string> process;
    std::vector<int> portInUse;
    std::string csvDir;

    // default values
    Args():
        indexName("skimmer"),
        indexType("_doc"),
        base64auth("bG9nc2VydmVyOmxvZ3NlcnZlcg=="), // logserver:logserver
        logFile("/tmp/skimmer.log"),
        elasticsearchIP("127.0.0.1"),
        elasticsearchPort(9200),
        daemonize(false)
    {};

    void base64Encode(const char* message);
    int readConfig(const char *filename);
    int readArgs(int argc, char *argv[]);
};

int Args::readConfig(const char *filename)
{
    std::string content;
    std::string line;
    std::string value;
    std::size_t found;
    const std::string opt[] = {
        "index_name",
        "index_freq",
        "index_type",
        "elasticsearch_auth",
        "elasticsearch_address",
        "logstash_address",
        "logstash_api",
        "log_file",
        "daemonize",
        "os_stats",
        "processes",
        "systemd_services",
        "port_numbers",
        "csv_path"
    };


    if(isFileEmpty(filename, content) != 0) return -1;
    std::istringstream iss(content);
    while(std::getline(iss, line))
    {
        int index = -1;
        for(const std::string &i: opt)
        {
            index += 1;

            if(!((found = line.find(i)) != std::string::npos && found == 0))
                continue;

            std::istringstream iline(line);
            if(!std::getline(iline, value, '='))
                continue;
            std::getline(iline, value);
            value.erase(std::remove(value.begin(), value.end(), ' '), value.end());

            switch(index)
            {
                case 0:
                    indexName = value;
                break;
                case 1:
                    indexFreq = value;
                break;
                case 2:
                    indexType = value;
                break;
                case 3:
                    base64Encode(value.c_str());
                break;
                case 4:
                    {
                        std::istringstream iarg(value);
                        std::string token;
                        if(!std::getline(iarg, token, ':'))
                            continue;
                        elasticsearchIP = token;

                        std::getline(iarg, token);
                        try
                        {
                            elasticsearchPort = std::stoi(token);
                        }
                        catch(const std::invalid_argument& err)
                        {
                            elasticsearchIP.clear();
                        }
                    }
                break;
                case 5:
                    {
                        std::istringstream iarg(value);
                        std::string token;
                        if(!std::getline(iarg, token, ':'))
                            continue;
                        logstashIP = token;

                        std::getline(iarg, token);
                        try
                        {
                            logstashPort = std::stoi(token);
                        }
                        catch(const std::invalid_argument& err)
                        {
                            logstashIP.clear();
                        }
                    }
                break;
                case 6:
                    {
                        std::istringstream iarg(value);
                        std::string token;
                        if(!std::getline(iarg, token, ':'))
                            continue;
                        logstashIPApi = token;

                        std::getline(iarg, token);
                        try
                        {
                            logstashPortApi = std::stoi(token);
                        }
                        catch(const std::invalid_argument& err)
                        {
                            logstashIPApi.clear();
                        }
                    }
                break;
                case 7:
                    logFile = value;
                break;
                case 8:
                    if(value == "true")
                        daemonize = true;
                break;
                case 9:
                    {
                        std::istringstream iarg(value);
                        std::string token;
                        while(std::getline(iarg, token, ','))
                            os.push_back(token);
                    }
                break;
                case 10:
                    {
                        std::istringstream iarg(value);
                        std::string token;
                        while(std::getline(iarg, token, ','))
                            process.push_back(token);
                    }
                break;
                case 11:
                    {
                        std::istringstream iarg(value);
			            std::string token;
				        while(std::getline(iarg, token, ','))
					        systemdS.push_back(token);
                    }
                break;
                case 12:
                    {
                        std::istringstream iarg(value);
				        std::string token;
				        while(std::getline(iarg, token, ','))
				        {
				            try
				            {
					            portInUse.push_back(std::stoi(token));
				            }
					        catch(const std::invalid_argument& err)
					        {
                                portInUse.clear();
				            }
			            }
                    }
                break;
                case 13:
                    csvDir = value;
                break;
            }
        }
    }

	std::string tmp = indexName;
    if(indexFreq == "daily")
        appendDateNow(tmp, "%Y.%m.%d");
    else if(indexFreq == "monthly")
        appendDateNow(tmp, "%Y.%m");
    std::string msg = "Configuration Options: \nIndex Name: " + tmp +
                        "\nIndex Type: " + indexType +
                        "\nElasticsearch Auth: " + base64auth +
                        "\nDaemonize: " + std::to_string(daemonize) +
                        "\n";

    if(!elasticsearchIP.empty())
    {
        msg += "Output Elasticsearch IP: " + elasticsearchIP +
                "\nOutput Elasticsearch Port: " + std::to_string(elasticsearchPort) +
                "\n";
    }
    if(!logstashIP.empty())
    {
        msg += "Output Logstash IP: " + logstashIP +
                "\nOutput Logstash Port: " + std::to_string(logstashPort) +
                "\n";
    }

    if(!logstashIPApi.empty())
    {
        msg += "API Logstash IP: " + logstashIPApi +
                "\nAPI Logstash Port: " + std::to_string(logstashPortApi) +
                "\n";
    }

    writeToLog(logFile.c_str(), msg.c_str());
    return 0;
}

void Args::base64Encode(const char* message)
{
	BIO *bio, *b64;
	FILE* stream;
    char *buffer;
	int encodedSize = 4*ceil((double)strlen(message)/3);
	buffer = (char *)malloc(encodedSize+1);

	stream = fmemopen(buffer, encodedSize+1, "w");
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(stream, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, message, strlen(message));
	BIO_flush(bio);
	BIO_free_all(bio);
	fclose(stream);
    base64auth = buffer;
    free(buffer);
}

int Args::readArgs(int argc, char *argv[])
{
    int opt;

    while((opt = getopt(argc, argv, "hsc:")) != -1)
    {
	    switch(opt)
	    {
		    case 'h':
			    printHelp();
                return -1;
            case 's':
                printSampleConfig();
                return -1;
            case 'c':
                return readConfig(optarg);
		    default:
			    printHelp();
                return -1;
	    }
    }

    printHelp();
    return -1;
}

void reap_zombie(int signum)
{
    waitpid(-1, NULL, 0);
}

int main(int argc, char *argv[])
{
    // readable error messages
    SSL_load_error_strings();
    // initialize library
    SSL_library_init();

    Args arg;
    if(arg.readArgs(argc, argv)) return -1;


    // child code
    if(fork() == 0)
    {
        do {
        pid_t pid = fork();
        if(pid == 0) 
        {
			if(arg.indexFreq == "daily")
                appendDateNow(arg.indexName, "%Y.%m.%d");
            else if(arg.indexFreq == "monthly")
                appendDateNow(arg.indexName, "%Y.%m");

            // Stats common for all nodes
            std::string ip = hostname_ip()["source_node_ip"];
            std::string os_stats;
            os_stats = os_stats + hostname_ip();

            for(const std::string &str: arg.os)
	        {
                if(str == "zombie")
                {
                    os_stats = os_stats + zombie_count();
                }
                else if(str == "vm")
                {
                    os_stats = os_stats + vm_stats();
                }
                else if(str == "fs")
                {
                    os_stats = os_stats + fs_stats();
                }
                else if(str == "swap")
                {
                    os_stats = os_stats + swap_stats();
                }
                else if(str == "net")
                {
                    os_stats = os_stats + net_stats();
                }
                else if(str == "cpu")
                {
                    os_stats = os_stats + cpu_stats();
                }
	        }
            for(const std::string &str: arg.process)
	        {
		        os_stats = os_stats + process_pid(str.c_str());
	        }
	        for(const std::string &str: arg.systemdS)
	        {
		        os_stats = os_stats + systemd_service_status(str);
	        }
	        for(int port: arg.portInUse)
	        {
		        os_stats = os_stats + is_address_in_use(ip, port);
	        }

            if(!arg.csvDir.empty()) checkCsvByPattern(arg.csvDir.c_str(), arg.logFile.c_str());

            // send os and elasticsearch api data
            try
            {
                // NODE DATA
                NodeStats node(arg.base64auth, arg.elasticsearchIP, arg.elasticsearchPort);

                node.sendDataToElasticsearch(os_stats, arg.indexName, arg.indexType);
                node.sendDataToElasticsearch(node.get_api_stats(), arg.indexName, arg.indexType);

                if(!arg.logstashIP.empty())
                {
                    sendData(os_stats.c_str(), arg.logstashIP.c_str(), arg.logstashPort);
                    sendData(node.get_api_stats().c_str(), arg.logstashIP.c_str(), arg.logstashPort);
                }

                // CLUSTER DATA
                ClusterStats cluster(arg.base64auth, arg.elasticsearchIP, arg.elasticsearchPort);

                cluster.sendDataToElasticsearch(cluster.get_api_stats(), arg.indexName, arg.indexType);

                if(!arg.logstashIP.empty())
                    sendData(cluster.get_api_stats().c_str(), arg.logstashIP.c_str(), arg.logstashPort);
            }
            catch(const std::runtime_error &error)
            {
                std::cerr << error.what() << std::endl;
            }

            // send logstash api data
            if(!arg.logstashIPApi.empty())
            {
                try
                {
                    Node node(arg.base64auth, arg.elasticsearchIP, arg.elasticsearchPort);
                    LogstashStats object(arg.logstashIPApi, arg.logstashPortApi);

                    node.sendDataToElasticsearch(object.get_api_stats(), arg.indexName, arg.indexType);

                    if(!arg.logstashIP.empty())
                        sendData(object.get_api_stats().c_str(), arg.logstashIP.c_str(), arg.logstashPort);
                }
                catch(const std::runtime_error &error)
                {
                    std::cerr << error.what() << std::endl;
                }
            }

            exit(0); // exit child
        }
        else
        {
	    if(arg.daemonize)
            {
                struct sigaction s;
                s.sa_handler = reap_zombie;
                sigaction(SIGCHLD, &s, NULL);
                unsigned int sec_to_sleep = 60;
                while((sec_to_sleep = sleep(sec_to_sleep)) != 0);
            }
            else
                waitpid(pid, NULL, 0);
        }
        } while(arg.daemonize);
    }

    // orphaning child
    return 0;
}
