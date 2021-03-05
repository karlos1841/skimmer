/*
 * Linux
 * g++ -std=c++11 -pedantic -Wall -Wextra $(pkg-config dbus-1 --cflags) skimmer.cpp -o skimmer -lssl -lcrypto -pthread -ldbus-1
 *
 * Windows
 * g++ -std=c++11 -pedantic -Wall -Wextra skimmer.cpp -o skimmer -lws2_32
 *
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
 * 1.0.9  - rewritten code responsible for config reading + more verbose log file + elasticsearch class overhaul
 *          + by default reporting unknown systemd service status and unused ports
 * 1.0.9a - fixed not reporting used ports on single interfaces + added debug logging option in config file
 *          + source_node_ip field is an elasticsearch array now
 * 1.0.10 - added PSexec module responsible for running powershell scripts remotely, rewritten main function to use threads for each module, reorganized sample config file,
 *          abandoned daemonize option, fixed segfault occuring on some systems when retrieving local ip addresses, added new metrics described in issue#126
 * 1.0.10a- fixed timestamp appending to index name
 * 1.0.11 - new metrics added
 * 1.0.12 - rewritten querying service status to use dbus api
 * 1.0.13 - fixed negative indexing rate value
 * 1.0.14 - added expected_data_nodes metric and kafka monitoring - consumers lag metric
 * 1.0.14a- fixed MSVC compiler warnings and other changes for PSexec module
 * 1.0.15 - added interval option, indices stats monitoring and nlohmann/json library
 * 1.0.15a- indices stats monitoring broken up into multiple documents
 * 1.0.16 - fixes in indices stats monitoring
 * 1.0.17 - added _cat/tasks monitoring, _cat/shards monitoring with its own interval option: system_health_check_interval, improved performance, time units in config and other changes
*/
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <wchar.h>
#include <locale.h>
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#define _XOPEN_SOURCE 700 // POSIX 2008
#include <vector>
#include <climits>
#include <map>
#include <unordered_map>
#include <sstream>
#include <fstream>
#include <typeinfo>
#include <ctime>
#include <chrono>
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
#include <sys/time.h>
#include <glob.h>
#include <math.h>
#include <openssl/ssl.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <dbus/dbus.h>

#include "json.hpp"
using json = nlohmann::json;
#endif

#define IP_MAX      16
#define BUFFER      1024
#define MIN_PORT    1
#define MAX_PORT    65535
#define MODULES     2
#define VERSION     "1.0.17"

// PSexec module
// marks end of connection
#define END         8
const char end[END] = {0};

// Common functions
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

#ifdef _WIN32
int writeToFile(FILE *f, const char *str)
{
    if(fputs(str, f) < 0)
        return -1;

    return 0;
}

wchar_t *readWcFromFile(FILE* f)
{
    wchar_t *buffer = NULL;
    wchar_t *ptr = NULL;
    size_t counter = 0;
    int count = 0;
    int count_all = 0;

    do
    {
        counter += 1;
        count_all += count;
        ptr = (wchar_t *)realloc(buffer, BUFFER * sizeof(wchar_t) * counter);
        if(ptr == NULL) { free(buffer); return NULL; }

        buffer = ptr;
        // extended memory initialized to 0
        wmemset(buffer + BUFFER * (counter - 1), 0, BUFFER);

    } while( (count = fread(buffer + count_all, sizeof(wchar_t), BUFFER, f)) > 0 );

    return buffer;
}

int writeWcToSocket(SOCKET *s, const wchar_t *str)
{
    /* Build buffer to send over network
     * otherwise in my experience Windows sends 1 byte segments
     * event though Nagle's algorithm is enabled
    */

    char *buffer = (char *)calloc(BUFFER, sizeof(char));
    char *ptr = NULL;
    size_t counter = 2;
    size_t len = 0;

    while(*str)
    {
        if(len >= BUFFER * (counter - 1))
        {
            ptr = (char *)realloc(buffer, BUFFER * counter);
            if(ptr == NULL) { free(buffer); return -1; }
            buffer = ptr;

            // init buffer
            memset(buffer + BUFFER * (counter - 1), 0, BUFFER);
            ++counter;
        }

        // convert wchar_t to multibyte char and write to buffer updating len
        size_t pReturnValue;
        if(wcrtomb_s(&pReturnValue, buffer + len, sizeof(wchar_t), *str, NULL) != 0) return -1;
        len += pReturnValue;
        ++str;
    }

    // send data
    if(send(*s, buffer, len, 0) < 0) return -1;
    free(buffer);

    // mark end of data
    if(send(*s, end, END, 0) != END) return -1;

    return 0;
}

char *readFromSocket(SOCKET *s)
{
    char *buffer = NULL;
    char *ptr = NULL;
    size_t counter = 0;
    int bytes = 0;
    int bytes_all = 0;

    do
    {
        // stop reading if we get END 0 bytes in a separate segment
        if(buffer != NULL && strncmp(buffer + bytes_all, end, END) == 0) break;

        counter += 1;
        bytes_all += bytes;

        ptr = (char *)realloc(buffer, BUFFER * counter);
        if(ptr == NULL) {free(buffer); return NULL;}

        buffer = ptr;
        // extended memory initialized to 0
        memset(buffer + BUFFER * (counter - 1), 0, BUFFER);

    } while((bytes = recv(*s, buffer + bytes_all, BUFFER, 0)) > 0);

    return buffer;
}

void printHelp()
{
    std::cout << "Usage for skimmer version " << VERSION << " <PSexec module>" << std::endl;
    std::cout << "\t-i server's ip" << std::endl;
    std::cout << "\t-p server's port" << std::endl;
    std::cout << "\t-d how often (in seconds) to send SYN packet when setting up connection for the first time (default 60)" << std::endl;
}

struct PS_PATH
{
    char *ps1;          // full path to skimmer.ps1 which contains command to execute
    char *dat;          // full path to skimmer.dat where result from running skimmer.ps1 is stored
    char *appdata;      // path to appdata where skimmer related files are stored

    PS_PATH(): ps1(NULL), dat(NULL), appdata(NULL)
    {
        // get APPDATA path
        size_t appdata_len;
        if(_dupenv_s(&appdata, &appdata_len, "APPDATA") != 0) throw nullptr;

        // path to skimmer.ps1
        const char* ps1_suffix = "\\skimmer.ps1";
        size_t ps1_buf = appdata_len + strlen(ps1_suffix) + 1;
        ps1 = (char *)malloc(ps1_buf * sizeof(char));
        if(ps1 == NULL) throw nullptr;
        snprintf(ps1,
                ps1_buf,
                "%s%s",
                appdata,
                ps1_suffix);

        // path to skimmer.dat
        const char* dat_suffix = "\\skimmer.dat";
        size_t dat_buf = appdata_len + strlen(dat_suffix) + 1;
        dat = (char *)malloc(dat_buf * sizeof(char));
        if(dat == NULL) throw nullptr;
        snprintf(dat,
                dat_buf,
                "%s%s",
                appdata,
                dat_suffix);
    }
    ~PS_PATH()
    {
        free(appdata);
        free(dat);
        free(ps1);
    }
};

struct PS_STATE
{
    SOCKET s;
    WSADATA wsa;
    int wsa_state;
    bool new_conn;

    PS_STATE(): s(INVALID_SOCKET), wsa_state(-1), new_conn(true) {}
};

class PS_CLIENT
{
    PS_STATE *state;

    char *command;      // command/script sent from remote host
    wchar_t *output;    // contents of skimmer.dat
    char *ps_command;   // powershell command to run locally

    public:
        PS_CLIENT(PS_STATE *state, const char *host, unsigned int port): state(state), command(NULL), output(NULL), ps_command(NULL)
        {
            // clean up if it's a new connection
            if(state->new_conn)
            {
                if(state->s != INVALID_SOCKET)
                    closesocket(state->s);
                if(state->wsa_state == 0)
                    WSACleanup();

                state->s = INVALID_SOCKET;
                state->wsa_state = -1;

                // establish connection
                struct sockaddr_in server_info;
                if((state->wsa_state = WSAStartup(MAKEWORD(2,2), &state->wsa)) != 0) throw nullptr;
                if((state->s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) throw nullptr;

                memset(&server_info, 0, sizeof(server_info));
                server_info.sin_family = AF_INET;
                server_info.sin_port = htons(port);

                if((server_info.sin_addr.s_addr = hostnameToIP(host)) == 0) throw nullptr;

                if(connect(state->s, (struct sockaddr *)&server_info, sizeof(server_info)) != 0) throw nullptr;

                fprintf(stderr, "Established connection to server\n");
            }
        }

        int run(const PS_PATH &path)
        {
            // get command/script from remote host
            command = readFromSocket(&state->s);

            // abort if an error occurred or peer closed the connection by sending only one segment of END 0 bytes
            if(command == NULL || strncmp(command, end, END) == 0) return -1;

            // write command/script to skimmer.ps1
            FILE *f_ps1;
            if(fopen_s(&f_ps1, path.ps1, "w") != 0) return -1;
            if(writeToFile(f_ps1, command) != 0) { fclose(f_ps1); return -1; }
            fclose(f_ps1);

            // run skimmer.ps1 and redirect output to skimmer.dat
            size_t ps_buf = strlen(path.ps1) + strlen(path.dat) + BUFFER;
            ps_command = (char *)malloc(ps_buf * sizeof(char));
            if(ps_command == NULL) return -1;
            snprintf(ps_command,
                    ps_buf,
                    "powershell -executionpolicy bypass -command \"& %s 2>&1 | Out-File -Encoding utf8 -FilePath %s\"",
                    path.ps1,
                    path.dat);
            system(ps_command);

            // read skimmer.dat to memory
            FILE *f_dat;
            if(fopen_s(&f_dat, path.dat, "rt,ccs=UTF-8") != 0) return -1;
            output = readWcFromFile(f_dat);
            fclose(f_dat);
            if(output == NULL) return -1;

            // send skimmer.dat to server
            if(writeWcToSocket(&state->s, (const wchar_t *)output) != 0) return -1;

            return 0;
        }

        ~PS_CLIENT()
        {
            free(ps_command);
            free(output);
            free(command);
        }
};

int main(int argc, char *argv[])
{
    setlocale(LC_ALL, "");
    int delay = 60;
    char hostname[BUFFER] = {0};
    unsigned int port = 0;

    for(int i = 1; i < argc; i++)
    {
        if(!(strcmp("-i", argv[i])))
        {
            if(argv[i + 1] != NULL)
                snprintf(hostname, BUFFER, "%s", argv[i + 1]);
            else
                break;
        }
        else if(!(strcmp("-p", argv[i])))
        {
            if(argv[i + 1] != NULL)
            {
                char port_s[6];
                snprintf(port_s, 6, "%s", argv[i + 1]);
                port = strtol(port_s, NULL, 0);
            }
            else
                break;
        }
        else if(!(strcmp("-d", argv[i])))
        {
            if(argv[i + 1] != NULL)
            {
                char delay_s[10];
                snprintf(delay_s, 10, "%s", argv[i + 1]);
                delay = strtol(delay_s, NULL, 0);
            }
            else
                break;
        }
    }

    if((strcmp(hostname, "")) == 0 || port == 0)
    {
        printHelp();
        return -1;
    }

    fprintf(stderr, "Skimmer version %s started\n", VERSION);
    fprintf(stderr, "Server: %s\n", hostname);
    fprintf(stderr, "Port: %d\n", port);

    PS_PATH path;
    PS_STATE state;

    for(;;)
    {
        try
        {
            PS_CLIENT client(&state, hostname, port);
            if(client.run(path) != 0) {
                // establish a new connection on error
                state.new_conn = true;
            }
            else {
                // maintain connection
                state.new_conn = false;
            }
        }
        catch(...)
        {
            Sleep(delay * 1000);
        }
    }

    return 0;
}

#else
typedef enum {
    INFO,
    DEBUG,
    ERROR
} LOG_LEVEL;

struct PS {
    char *response;
    int port;
    size_t exec_step;
    const char *path;
    char *script;
};
struct PS ps;

pthread_mutex_t mutex;
pthread_t threads[MODULES];

/*** OS METRICS USING LINUX/POSIX LIBRARIES ***/
// returns associative arrays with hostname and ip address of this machine
std::unordered_map<std::string, std::string> get_hostname();
std::map<std::string, std::string> get_ip();

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
class DBus
{
    DBusConnection *connection;
    DBusError error;

    std::string object_parse(const std::string &object);

    public:
        DBus(): connection(NULL)
        {
            // init error
            dbus_error_init(&error);
            // connect to system bus
            connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
            if(connection == NULL) throw nullptr;
        };
        ~DBus()
        {
            dbus_connection_unref(connection);
            if(dbus_error_is_set(&error)) dbus_error_free(&error);
        };

        std::string get_error()
        {
            if(dbus_error_is_set(&error))
                return std::string(error.name) + ": " + std::string(error.message);

            return "";
        };

        const char *get_systemd_object_state(const std::string &object);
};

std::string DBus::object_parse(const std::string &object)
{
    std::string object_parsed;
    // the most common replacements
    char replace[] = {'.', '-', '_', '@'};
    const char *replace_with[] = { "_2e", "_2d", "_5f", "_40" };

    for(char c: object)
    {
        bool replaced = false;
        size_t index = 0;
        for(char r: replace)
        {
            if(c == r)
            {
                object_parsed += replace_with[index];
                replaced = true;
                break;
            }
            index += 1;
        }

        if(!replaced)
            object_parsed.push_back(c);
    }

    return object_parsed;
}

const char *DBus::get_systemd_object_state(const std::string &object)
{
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;
    std::string systemd_service_path = "org.freedesktop.systemd1";
    std::string systemd_object_path = "/org/freedesktop/systemd1/unit/" + object_parse(object);

    // build method call
    msg = dbus_message_new_method_call(systemd_service_path.c_str(), systemd_object_path.c_str(), "org.freedesktop.DBus.Properties", "Get");

    // pass arguments to method
    const char *msg_interface = "org.freedesktop.systemd1.Unit";
    const char *msg_property = "ActiveState";
    dbus_message_append_args(msg, DBUS_TYPE_STRING, &msg_interface, DBUS_TYPE_STRING, &msg_property, DBUS_TYPE_INVALID);

    // send and wait for reply
    reply = dbus_connection_send_with_reply_and_block(connection, msg, DBUS_TIMEOUT_USE_DEFAULT, &error);
    if(reply == NULL) return NULL;

    // decode reply
    DBusMessageIter iter;
    dbus_message_iter_init(reply, &iter);
    if(DBUS_TYPE_VARIANT != dbus_message_iter_get_arg_type(&iter)) return NULL;

    DBusMessageIter sub;
    dbus_message_iter_recurse(&iter, &sub);

    const char *result = NULL;
    dbus_message_iter_get_basic(&sub, &result);

    // decrement ref
    dbus_message_unref(msg);
    dbus_message_unref(reply);

    return result;
}

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

int node_hostname_ip(std::string &nodeHostname, std::vector<std::string> &nodeIP)
{
    // get hostname
    char hostname[HOST_NAME_MAX];
    if(gethostname(hostname, HOST_NAME_MAX) != 0) return -1;
    nodeHostname = hostname;


    // get all ip addresses
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];
    if(getifaddrs(&ifaddr) == -1) return -1;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if(ifa->ifa_addr != NULL)
        {
            if(ifa->ifa_addr->sa_family == AF_INET)
            {
                if(getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0) break;
                nodeIP.push_back(host);
            }
        }
    }
    freeifaddrs(ifaddr);
    return 0;
}

// remove headers from webserver's response
const char *remove_headers(char **response)
{
	const char *content = *response;
	char *tmp_ptr = NULL;
	while(strstr(content, "\r\n\r\n") != NULL) content += 4;
	// remove empty lines
	const char *s = NULL;
	while((s = strpbrk(content, "\r\n")) != NULL && s == content) content += 1;
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

int writeToLog(LOG_LEVEL level, const char *filename, const char *message)
{
    pthread_mutex_lock(&mutex);
    FILE *logFile = fopen(filename, "a");
    if(logFile == NULL){fprintf(stderr, "cannot open log file\n"); pthread_mutex_unlock(&mutex); return -1;}
    struct tm *timeinfo;
    time_t rawtime = time(NULL);

    // stores time information
    char time_buffer[20];

    timeinfo = localtime(&rawtime);
    strftime(time_buffer, sizeof(time_buffer), "%d-%m-%Y %H:%M:%S", timeinfo);
    switch (level)
    {
        case INFO:
            fprintf(logFile, "[INFO] %s: %s\n", time_buffer, message);
            break;
        case DEBUG:
            fprintf(logFile, "[DEBUG] %s: %s\n", time_buffer, message);
            break;
        case ERROR:
            fprintf(logFile, "[ERROR] %s: %s\n", time_buffer, message);
            break;
    }

    fclose(logFile);
    pthread_mutex_unlock(&mutex);
    return 0;
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

template<typename T>
std::string &operator<<(std::string &output, const std::map<std::string, T> &map)
{
    std::stringstream ss;
    ss << "{";
    for(auto x = map.begin(); x != map.end(); )
    {
        ss << "\"" << x->first << "\"" << ": " << x->second;
        if(++x != map.end()) ss << ",";
    }
    ss << "}";
    output += ss.str();
    return output;
}

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

template<typename T>
std::string &operator<<(std::string &output, const std::vector<T> &vec)
{
    std::stringstream ss;
    if(output.empty()) {
        if(typeid(std::string) == typeid(T)) {
            ss << "[";
            for(auto x = vec.begin(); x != vec.end(); )
            {
                ss << "\"" << *x << "\"";
                if(++x != vec.end()) ss << ",";
            }
            ss << "]";
        }
        else {
            ss << "[";
            for(auto x = vec.begin(); x != vec.end(); )
            {
                ss << *x;
                if(++x != vec.end()) ss << ",";
            }
            ss << "]";
        }
    }
    else {
        output.pop_back();
        if(typeid(std::string) == typeid(T)) {
            ss << ",";
            for(auto x = vec.begin(); x != vec.end(); )
            {
                ss << "\"" << *x << "\"";
                if(++x != vec.end()) ss << ",";
            }
            ss << "]";
        }
        else {
            ss << ",";
            for(auto x = vec.begin(); x != vec.end(); )
            {
                ss << *x;
                if(++x != vec.end()) ss << ",";
            }
            ss << "]";
        }
    }
    output += ss.str();
    return output;
}

template<typename T>
std::string &operator+(std::string &sum, const std::map<std::string, T> &map)
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
/*** END OF GENERIC HELPER FUNCTIONS ***/
/***************************************/
/***************************************/

struct PreviousAPICall {
     double previousDocumentsCount = 0.00;
     double previousIndexingRate = 0.00;
     std::chrono::time_point<std::chrono::high_resolution_clock> previousCallTime;
     bool initialized = false;
};

/***************************************/
/***************************************/
/******* ELASTICSEARCH API CLASS *******/
class ElasticsearchStats
{
    std::pair<std::string, unsigned short> API;
    std::vector<std::string> nodesIP;
    std::string masterNodeIP;
    std::string thisHostname;
    std::string thisIP;
    std::string base64auth;
    std::vector<std::string> indices;
    std::unordered_map<std::string, std::string> api_timestamp(const char *);
    char *(*get_data)(const char *, const char *, unsigned short);
    int (*send_data)(const char *, const char *, unsigned short);

    // populate nodesIP with IP of all nodes in the cluster
    int nodes_ip();

    // populate masterNodeIP with IP of a master node
    int master_node_ip();

    // stats
    const char *node_response;
    const char *cluster_response;
    const char *cluster_health_response;
    const char *cluster_pending_tasks_response;
    const char *cluster_tasks_response;
    const char *cluster_shards_response;
    std::vector<const char *> indices_response;

    std::unordered_map<std::string, long double> node_stats();
    std::unordered_map<std::string, double> cluster_stats(PreviousAPICall &previousAPICall);
    std::unordered_map<std::string, long double> cluster_health();
    std::unordered_map<std::string, uint64_t> cluster_pending_tasks();
    void cluster_tasks(std::vector<std::string> &);
    void cluster_shards(std::vector<std::string> &);
    std::unordered_map<std::string, long double> indices_stats(size_t);

    public:
    ElasticsearchStats(const std::pair<std::string, unsigned short> &_API, const std::string &_base64auth, const std::vector<std::string> &_indices):
    API(_API), base64auth(_base64auth), indices(_indices)
    {
        // Init
        node_response = NULL;
        cluster_response = NULL;
        cluster_health_response = NULL;
        cluster_pending_tasks_response = NULL;
        cluster_tasks_response = NULL;
        cluster_shards_response = NULL;
        for(size_t i = 0; i < indices.size(); i++) indices_response.push_back(NULL);

        // API
        if(!API.first.empty()) {

            // determine whether to use SSL or plain
            int SSL = isSSL(API.first.c_str(), API.second);
            if(SSL == 0) { get_data = &readSSLResponse; send_data = &sendSSLData; }
            else if(SSL == 1) { get_data = &readResponse; send_data = &sendData; }
            else throw std::runtime_error("Failed to construct ElasticsearchStats object: Unable to communicate with cluster");

            // determine IP of all nodes in the cluster
            if(nodes_ip() == -1) throw std::runtime_error("Failed to construct ElasticsearchStats object: Unable to determine nodes in the cluster");
            // determine master node IP
            if(master_node_ip() == -1) throw std::runtime_error("Failed to construct ElasticsearchStats object: Unable to determine master node");

            // determine this IP
            std::vector<std::string> IP;
            if(node_hostname_ip(thisHostname, IP) == -1) throw std::runtime_error("Failed to construct ElasticsearchStats object: Hostname/IP unknown");
            for(const std::string &i: IP) {
                for(const std::string &j: nodesIP) {
                    if(i == j) {
                        thisIP = i;
                        break;
                    }
                }
            }

            // retrieve nodes stats
            std::string elastic_request = "GET /_nodes/" + thisIP + "/stats HTTP/1.0\r\nContent-type: application/json\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
            node_response = get_data(elastic_request.c_str(), API.first.c_str(), API.second);

            // retrieve cluster stats
            if(thisIP == masterNodeIP) {
                elastic_request = "GET /_cluster/stats HTTP/1.0\r\nContent-type: application/json\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
                cluster_response = get_data(elastic_request.c_str(), API.first.c_str(), API.second);
                elastic_request = "GET /_cluster/health HTTP/1.0\r\nContent-type: application/json\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
                cluster_health_response = get_data(elastic_request.c_str(), API.first.c_str(), API.second);
                elastic_request = "GET /_cluster/pending_tasks HTTP/1.0\r\nContent-type: application/json\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
                cluster_pending_tasks_response = get_data(elastic_request.c_str(), API.first.c_str(), API.second);
                elastic_request = "GET /_cat/tasks?format=json HTTP/1.0\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
                cluster_tasks_response = get_data(elastic_request.c_str(), API.first.c_str(), API.second);
                elastic_request = "GET /_cat/shards?format=json HTTP/1.0\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
                cluster_shards_response = get_data(elastic_request.c_str(), API.first.c_str(), API.second);
            }

            // retrieve indices stats
            for(size_t i = 0; i < indices.size(); i++)
            {
                elastic_request = "GET /" + indices[i] + "/_stats HTTP/1.0\r\nContent-type: application/json\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
                indices_response[i] = get_data(elastic_request.c_str(), API.first.c_str(), API.second);
            }
        }
    };
    ~ElasticsearchStats(){
        free((char *)node_response); free((char *)cluster_response); free((char *)cluster_health_response); free((char *)cluster_pending_tasks_response); free((char *)cluster_tasks_response); free((char *)cluster_shards_response);
        for(size_t i = 0; i < indices.size(); i++) free((char *)indices_response[i]);
    };

    std::string get_node_stats()
    {
        if(node_response == NULL) return "";

        std::string json_output;
        json_output = json_output + api_timestamp(node_response) + node_stats();

        return json_output;
    };

    std::string get_cluster_stats(PreviousAPICall &previousAPICall)
    {
        if(cluster_response == NULL || cluster_health_response == NULL || cluster_pending_tasks_response == NULL) return "";

        std::string json_output;
        json_output = json_output + api_timestamp(cluster_response) + cluster_stats(previousAPICall) + cluster_health() + cluster_pending_tasks();

        return json_output;
    };

    std::vector<std::string> get_indices_stats()
    {
        std::vector<std::string> json_output;
        if(indices.empty()) return json_output;

        for(size_t i = 0; i < indices.size(); i++)
        {
            std::unordered_map<std::string, long double> output = indices_stats(i);
            std::unordered_map<std::string, std::string> index = {{"index", indices[i]}};
            if(!output.empty()) {
                std::string tmp;
                json_output.push_back(tmp + api_timestamp(node_response) + output + index);
            }
        }

        return json_output;
    };

    std::vector<std::string> get_cluster_tasks()
    {
        std::vector<std::string> json_output;
        if(cluster_tasks_response == NULL) return json_output;

        std::vector<std::string> cluster_tasks_output;
        cluster_tasks(cluster_tasks_output);
        for(std::string& output: cluster_tasks_output)
        {
            json_output.push_back(output);
        }

        return json_output;
    }

    std::vector<std::string> get_cluster_shards(const size_t interval, const size_t system_health_check_interval)
    {
        static size_t total = 0;
        std::vector<std::string> json_output;

        total += interval;
        if(cluster_shards_response == NULL || total < system_health_check_interval) return json_output;
        total = 0;

        std::vector<std::string> cluster_shards_output;
        cluster_shards(cluster_shards_output);
        for(std::string& output: cluster_shards_output)
        {
            json_output.push_back(output);
        }

        return json_output;
    }
};

int ElasticsearchStats::nodes_ip()
{
    std::string elastic_request = "GET /_cat/nodes?h=ip HTTP/1.0\r\nAccept: text/plain\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
    const char *response = get_data(elastic_request.c_str(), API.first.c_str(), API.second);
    if(response == NULL) return -1;
    if(getHttpStatus(response) != 200) { free((char *)response); return -1; }
    response = remove_headers((char **)&response);

    std::istringstream istream(response);
    std::string tmp;
    while(istream >> tmp) {
        nodesIP.push_back(tmp);
    }

    free((char *)response);
    return 0;
}

int ElasticsearchStats::master_node_ip()
{
    std::string elastic_request = "GET /_cat/master?h=ip HTTP/1.0\r\nAccept: text/plain\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
    const char *response = get_data(elastic_request.c_str(), API.first.c_str(), API.second);
    if(response == NULL) return -1;
    if(getHttpStatus(response) != 200) { free((char *)response); return -1; }
    response = remove_headers((char **)&response);

    std::istringstream istream(response);
    istream >> masterNodeIP;

    free((char *)response);
    return 0;
}

std::unordered_map<std::string, std::string> ElasticsearchStats::api_timestamp(const char *response)
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

std::unordered_map<std::string, long double> ElasticsearchStats::node_stats()
{
    std::unordered_map<std::string, long double> stats;
    if(getHttpStatus(node_response) != 200) return stats;
    node_response = remove_headers((char **)&node_response);
    const char *value = NULL;

    const int col = 70;
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
        {"indices", "merges", "total_time_in_millis", NULL},
        {"indices", "merges", "total", NULL},
        {"os", "cpu", "percent", NULL},
        {"os", "mem", "total_in_bytes", NULL},
        {"os", "mem", "free_in_bytes", NULL},
        {"os", "swap", "total_in_bytes", NULL},
        {"os", "swap", "free_in_bytes", NULL},
        {"io_stats", "total", "operations", NULL},
        {"io_stats", "total", "read_operations", NULL},
        {"io_stats", "total", "write_operations", NULL},
        {"io_stats", "total", "read_kilobytes", NULL},
        {"io_stats", "total", "write_kilobytes", NULL},
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
        if((value = extract_json_value(node_response, keys[i])) != NULL)
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
                stats.insert({description, strtold(value, NULL)});
        }
    }

    // custom metrics
    try {
    if(stats.at("node_stats_indices_flush_total") != 0)
        stats.insert({"node_stats_indices_flush_duration", stats.at("node_stats_indices_flush_total_time_in_millis") / stats.at("node_stats_indices_flush_total")});

    if(stats.at("node_stats_jvm_gc_collectors_old_collection_count") != 0)
        stats.insert({"node_stats_jvm_gc_collectors_old_collection_duration", stats.at("node_stats_jvm_gc_collectors_old_collection_time_in_millis") / stats.at("node_stats_jvm_gc_collectors_old_collection_count")});
    else if(stats.at("node_stats_jvm_gc_collectors_old_collection_count") == 0 && stats.at("node_stats_jvm_gc_collectors_old_collection_time") == 0)
        stats.insert({"node_stats_jvm_gc_collectors_old_collection_duration", 0});

    if(stats.at("node_stats_jvm_gc_collectors_young_collection_count") != 0)
        stats.insert({"node_stats_jvm_gc_collectors_young_collection_duration", stats.at("node_stats_jvm_gc_collectors_young_collection_time_in_millis") / stats.at("node_stats_jvm_gc_collectors_young_collection_count")});

    if(stats.at("node_stats_indices_indexing_index_total") != 0)
        stats.insert({"node_stats_indices_indexing_index_duration", stats.at("node_stats_indices_indexing_index_time_in_millis") / stats.at("node_stats_indices_indexing_index_total")});

    if(stats.at("node_stats_indices_refresh_total") != 0)
        stats.insert({"node_stats_indices_refresh_duration", stats.at("node_stats_indices_refresh_total_time_in_millis") / stats.at("node_stats_indices_refresh_total")});

    if(stats.at("node_stats_indices_merges_total") != 0)
        stats.insert({"node_stats_indices_merges_duration", stats.at("node_stats_indices_merges_total_time_in_millis") / stats.at("node_stats_indices_merges_total")});
    else if(stats.at("node_stats_indices_merges_total") == 0)
        stats.insert({"node_stats_indices_merges_duration", 0});

    if(stats.at("node_stats_os_cpu_percent") >= 90)
        stats.insert({"node_stats_expected_data_nodes", 2});
    else
        stats.insert({"node_stats_expected_data_nodes", 1});
    }
    catch (const std::out_of_range& oor) {
        // handle oor
    }

    return stats;
}

std::unordered_map<std::string, long double> ElasticsearchStats::cluster_health()
{
    std::unordered_map<std::string, long double> stats;
    if(getHttpStatus(cluster_health_response) != 200) return stats;
    cluster_health_response = remove_headers((char **)&cluster_health_response);
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
        if((value = extract_json_value(cluster_health_response, keys[i])) != NULL)
        {
            if(i == 0)
                stats.insert({"cluster_stats_availability", strtold(value, NULL)});
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
                stats.insert({"cluster_health_" + std::string(keys[i][0]), strtold(value, NULL)});
        }
    }

    return stats;
}

std::unordered_map<std::string, double> ElasticsearchStats::cluster_stats(PreviousAPICall &previousAPICall)
{
    std::unordered_map<std::string, double> stats;
    if(getHttpStatus(cluster_response) != 200) return stats;
    auto currentAPICallTime = std::chrono::high_resolution_clock::now();
    cluster_response = remove_headers((char **)&cluster_response);
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
        if((value = extract_json_value(cluster_response, keys[i])) != NULL)
        {
            std::string description = "cluster_stats";
            for(int j = 0; keys[i][j] != NULL; j++)
            {
                description += "_";
                description += keys[i][j];
            }

            double numberValue = strtol(value, NULL, 0);
            stats.insert({description, numberValue});

            if(description == "cluster_stats_indices_docs_count")
            {
                if(previousAPICall.previousDocumentsCount > 0 && previousAPICall.initialized)
                {
                     double timeDifference = (std::chrono::duration<double, std::milli>(currentAPICallTime - previousAPICall.previousCallTime).count()) / 1000;
                     double indexingRate = (double)(numberValue - previousAPICall.previousDocumentsCount) / timeDifference;
                     if(indexingRate < 0.00)
                     {
                         indexingRate = previousAPICall.previousIndexingRate;
                     }
                     stats.insert({"cluster_stats_indices_docs_per_sec", indexingRate});
                     previousAPICall.previousIndexingRate = indexingRate;
                }

                previousAPICall.previousDocumentsCount = numberValue;
                previousAPICall.previousCallTime = currentAPICallTime;
                previousAPICall.initialized = true;
            }
        }
    }

    return stats;
}

std::unordered_map<std::string, uint64_t> ElasticsearchStats::cluster_pending_tasks()
{
    std::unordered_map<std::string, uint64_t> stats;

    if(getHttpStatus(cluster_pending_tasks_response) != 200) return stats;
    cluster_pending_tasks_response = remove_headers((char **)&cluster_pending_tasks_response);
    std::string json_response(this->cluster_pending_tasks_response);

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

void ElasticsearchStats::cluster_tasks(std::vector<std::string> &stats)
{
    if(getHttpStatus(cluster_tasks_response) != 200) return;
    cluster_tasks_response = remove_headers((char **)&cluster_tasks_response);

    try
    {
        json response = json::parse(cluster_tasks_response);
        for (const auto &e: response.items()) stats.push_back(e.value().dump());
    }
    catch(const json::parse_error& e) {}
}

void ElasticsearchStats::cluster_shards(std::vector<std::string> &stats)
{
    if(getHttpStatus(cluster_shards_response) != 200) return;
    cluster_shards_response = remove_headers((char **)&cluster_shards_response);

    try
    {
        json response = json::parse(cluster_shards_response);
        for (const auto &e: response.items()) stats.push_back(e.value().dump());
    }
    catch(const json::parse_error& e) {}
}

std::unordered_map<std::string, long double> ElasticsearchStats::indices_stats(size_t i)
{
    std::unordered_map<std::string, long double> stats;
    std::string description = "indices_stats";

    if(getHttpStatus(indices_response[i]) != 200) return stats;
    indices_response[i] = remove_headers((char **)&indices_response[i]);

    try
    {
        json response = json::parse(indices_response[i]);

        for (const auto &e: response["_all"]["total"]["docs"].items())
        {
            stats.insert({
                description + "_all_total_docs_" + e.key(),
                e.value()
            });
        }

        for (const auto &e: response["_all"]["total"]["store"].items())
        {
            stats.insert({
                description + "_all_total_store_" + e.key(),
                e.value()
            });
        }

        for (const auto &e: response["_all"]["total"]["indexing"].items())
        {
            if(e.key() == "is_throttled")
            {
                stats.insert({
                    description + "_all_total_indexing_" + e.key(),
                    (e.value() == true) ? 1 : 0
                });
            }
            else
            {
                stats.insert({
                    description + "_all_total_indexing_" + e.key(),
                    e.value()
                });
            }
        }

        for (const auto &e: response["_all"]["total"]["get"].items())
        {
            stats.insert({
                description + "_all_total_get_" + e.key(),
                e.value()
            });
        }

        for (const auto &e: response["_all"]["total"]["search"].items())
        {
            stats.insert({
                description + "_all_total_search_" + e.key(),
                e.value()
            });
        }

        for (const auto &e: response["_all"]["total"]["merges"].items())
        {
            stats.insert({
                description + "_all_total_merges_" + e.key(),
                e.value()
            });
        }

        for (const auto &e: response["_all"]["total"]["segments"].items())
        {
            if(e.key() == "file_sizes") continue;
            stats.insert({
                description + "_all_total_segments_" + e.key(),
                e.value()
            });
        }
    }
    catch(const json::parse_error& e) {}

    return stats;
}

int sendDataToElasticsearch(bool debug, const std::pair<std::string, unsigned short> &OUTPUT, const std::string &index, const std::string &type, const std::string &base64auth, std::string &_data, const char *logfile)
{
    if(_data.empty()) return -1;
    if(OUTPUT.first.empty()) return -1;
    // update data
    const std::string data = _data + get_hostname() + get_ip();

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

    if(debug) {
        std::string msg = "Sent the following request to " + OUTPUT.first + " on port " + std::to_string(OUTPUT.second) + ":\n";
        msg += elastic_request;
        writeToLog(DEBUG, logfile, msg.c_str());
    }

    char *response = NULL;
    if(isSSL(OUTPUT.first.c_str(), OUTPUT.second))
        response = readResponse(elastic_request.c_str(), OUTPUT.first.c_str(), OUTPUT.second);
    else
        response = readSSLResponse(elastic_request.c_str(), OUTPUT.first.c_str(), OUTPUT.second);

    if(response == NULL) { writeToLog(ERROR, logfile, "Got NULL response"); ; return -1; }

    if(debug) {
        std::string msg = "Got the following response back:\n" + std::string(response);
        writeToLog(DEBUG, logfile, msg.c_str());
    }
    free(response);
    return 0;
}
/*** END OF ELASTICSEARCH API CLASS ***/
/**************************************/
/**************************************/


/**************************************/
/**************************************/
/********* LOGSTASH API CLASS *********/
class LogstashStats
{
    // API
    const char *api_response;
    std::pair<std::string, unsigned short> API;

    std::unordered_map<std::string, uint64_t> api_stats();
    std::unordered_map<std::string, long double> cpu_load();

    public:
        LogstashStats(const std::pair<std::string, unsigned short> &_API): API(_API)
        {
            // Init
            api_response = NULL;

            // API
            if(!API.first.empty()) {

                const std::string logstash_request = "GET /_node/stats/?human=false HTTP/1.0\r\nContent-type: application/json\r\n\r\n";
                api_response = readResponse(logstash_request.c_str(), API.first.c_str(), API.second);
                if(api_response == NULL) throw std::runtime_error("Failed to construct LogstashStats object: NULL response");

                if(getHttpStatus(api_response) != 200)
                {
                    free((char *)api_response); api_response = NULL;
                    throw std::runtime_error("Failed to construct LogstashStats object: Got != 200 status code");
                }
                else api_response = remove_headers((char **)&api_response);
            }
        };
        ~LogstashStats(){free((char *)api_response);};

        std::string get_api_stats()
        {
            if(api_response == NULL) return "";

            std::string json_output;
            json_output = json_output + api_stats() + cpu_load();

            return json_output;
        };
};

enum class Positions
{
  GROUP = 0,
  TOPIC = 1,
  LAG = 5,
  CONSUMER_ID = 6
};

enum class Positions_Deprecated
{
  TOPIC = 0,
  LAG = 4,
  CONSUMER_ID = 5
};

class KafkaStats
{
  std::string log_file = "";

  std::string path = "";
  std::string server_address = "";
  std::string monitored_topics = "";
  std::string monitored_groups = "";

  bool outdated_version = false;
  std::vector<std::string> commands;

  std::string command = "";

  std::string get_kafka_command_output(const std::string &command)
  {
    char buffer[256];
    std::string command_output = "";

    FILE* pipe = popen((command + " 2>&1").c_str(), "r");
    if (!pipe)
    {
      writeToLog(ERROR, this->log_file.c_str(), "Failed to retrieve Kafka stats!");
      return "";
    }

    while (!feof(pipe))
    {
      if (fgets(buffer, 256, pipe) != NULL)
        command_output += buffer;
    }

    pclose(pipe);

    return command_output;
  }

  std::vector<std::string> get_consumer_groups_stats()
  {
    std::vector<std::string> stats;

    if(!this->outdated_version)
    {
      parse_kafka_lag(this->get_kafka_command_output(this->command), stats);

      return stats;
    }

    if(this->commands.empty())
      return stats;

    const std::string group_arg = "--group ";
    for(const auto &command : this->commands)
    {
      std::string group = command.substr(command.find(group_arg) + group_arg.length());
      parse_kafka_lag(this->get_kafka_command_output(command), stats, group);
    }

    return stats;
  }

  void parse_kafka_lag(const std::string &kafka_output, std::vector<std::string> &stats,
    const std::string &current_group = "undefined")
  {
    std::unordered_map<std::string, std::string> stat;
    const std::string kafka_stats_prefix = "kafka_";

    if(kafka_output.empty())
      return;

    std::stringstream stringstream(kafka_output);
    std::string line;

    std::string group;
    std::string topic;
    std::string lag;
    std::string consumer_id;

    int counter = 0;
    while(std::getline(stringstream, line))
    {
      if(line != "" && line.find("Error") == std::string::npos && line.find("TOPIC") == std::string::npos
        && line.find("has no active members") == std::string::npos && line.find("WARN") == std::string::npos)
      {
        std::istringstream istringstream(line);
        for(std::string value; istringstream >> value; )
        {
          if(this->outdated_version)
          {
            switch(static_cast<Positions_Deprecated>(counter))
             {
               case Positions_Deprecated::TOPIC:
               {
                 topic = value;
                 break;
               }
               case Positions_Deprecated::LAG:
               {
                 (value == "" || value == "-") ? lag = "0" : lag = value;
                 break;
               }
               case Positions_Deprecated::CONSUMER_ID:
               {
                 consumer_id = value;
                 break;
               }
             }
          }
          else
          {
            switch(static_cast<Positions>(counter))
            {
              case Positions::GROUP:
              {
                group = value;
                break;
              }
              case Positions::TOPIC:
              {
                topic = value;
                break;
              }
              case Positions::LAG:
              {
                (value == "" || value == "-") ? lag = "0" : lag = value;
                break;
              }
              case Positions::CONSUMER_ID:
              {
                consumer_id = value;
                break;
              }
            }
          }

          ++counter;
        }

        if(this->monitored_topics.find(topic) != std::string::npos || this->monitored_topics == "")
        {
           stat.insert({kafka_stats_prefix + "group", current_group != "undefined" ? current_group : group});
           stat.insert({kafka_stats_prefix + "topic", topic});
           stat.insert({kafka_stats_prefix + "lag", lag});
           stat.insert({kafka_stats_prefix + "consumer_id", consumer_id});

           std::string json_s;
           json_s << stat;

           try
           {
               json json_r = json::parse(json_s);
               json_r[kafka_stats_prefix + "consumer_id"] = strtol(json_r[kafka_stats_prefix + "consumer_id"].get<std::string>().c_str(), NULL, 0);
               stats.push_back(json_r.dump());
           }
           catch(const json::parse_error& e)
           {
               stats.push_back(json_s);
           }

           stat.clear();
        }
      }

      counter = 0;
    }
  }

public:

  KafkaStats(std::string &_log_file, std::string &_path, std::string &_server_address,
    std::string &_monitored_topics, std::string &_monitored_groups, bool &_outdated_version)
    : log_file(_log_file), path(_path), server_address(_server_address),
    monitored_topics(_monitored_topics), monitored_groups(_monitored_groups),
    outdated_version(_outdated_version)
  {
    std::string command_prefix = this->path;
    command_prefix += command_prefix.at(command_prefix.length() - 1) == '/' ? "bin/kafka-consumer-groups.sh " : "/bin/kafka-consumer-groups.sh ";
    command_prefix += "--bootstrap-server " + this->server_address + " --describe --verbose";

    if(this->monitored_groups != "")
    {
      std::stringstream groups(this->monitored_groups);
      std::string group;
      while(std::getline(groups, group, ','))
      {
        if(this->outdated_version)
        {
          std::string command = command_prefix + " --group " + group;
          this->commands.push_back(command);
        }
        else
          command_prefix += " --group " + group;
      }
    }
    else if(!this->outdated_version)
    {
      command_prefix += " --all-groups";
    }

    if(!this->outdated_version)
      this->command = command_prefix;
  }

  std::unordered_map<std::string, std::string> get_timestamp()
  {
      std::unordered_map<std::string, std::string> timestamp;
      char time_str[30];
      struct tm *timeinfo;
      time_t current_time = std::time(NULL);
      timeinfo = gmtime(&current_time);
      strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", timeinfo);

      timestamp.insert({"timestamp_api", time_str});

      return timestamp;
  }

  std::vector<std::string> get_data_for_elasticsearch()
  {
    std::vector<std::string> data;
    std::vector<std::string> stats =  this->get_consumer_groups_stats();

    if(stats.empty())
    {
      return data;
    }

    for(auto &stat : stats)
    {
      std::string json_output;
      json_output = stat + this->get_timestamp();
      data.push_back(json_output);
    }

    return data;
  }
};

int sendDataToLogstash(const std::pair<std::string, unsigned short> &OUTPUT, std::string &_data)
{
    if(_data.empty()) return -1;
    if(OUTPUT.first.empty()) return -1;
    const std::string data = _data + get_hostname() + get_ip();
    return sendData(data.c_str(), OUTPUT.first.c_str(), OUTPUT.second);
}

void sendDataToLogstash(const std::pair<std::string, unsigned short> &OUTPUT, std::string &&_data)
{
    std::string data = _data;
    sendDataToLogstash(OUTPUT, data);
}

std::unordered_map<std::string, long double> LogstashStats::cpu_load()
{
    std::unordered_map<std::string, long double> stats;
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

            stats.insert({description, strtold(value, NULL)});
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
std::unordered_map<std::string, std::string> get_hostname()
{
    std::unordered_map<std::string, std::string> address;
    std::string hostname;
    std::vector<std::string> ip;

    if(node_hostname_ip(hostname, ip) == -1) return address;
    address.insert({"source_node_host", hostname});
    return address;
}

std::map<std::string, std::string> get_ip()
{
    std::map<std::string, std::string> address;
    std::string hostname, ip_s;
    std::vector<std::string> ip;

    if(node_hostname_ip(hostname, ip) == -1) return address;
    // remove 127.0.0.1 entry
    ip.erase(ip.begin());
    ip_s << ip;
    address.insert({"source_node_ip", ip_s});
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

    DBus d;
    const char *result = d.get_systemd_object_state(service + ".service");
    if(result == NULL) return service_status;

    std::string status = result;

	if(skip_unknown)
	{
		if(status != "unknown") service_status.insert({"node_stats_systemd_service_" + service, status});
	}
	else
	{
		service_status.insert({"node_stats_systemd_service_" + service, status});
	}

    return service_status;
}

bool is_address_in_use(const std::string &ip, const int port)
{
    bool port_status = false;
	int socket_descriptor;
	struct sockaddr_in server_info;

	if((socket_descriptor = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		//const char *msg = "[Error] could not create socket";
		return false;
	}

	memset(&server_info, 0, sizeof(server_info));
	server_info.sin_family = AF_INET;
	server_info.sin_port = htons(port);
	if((server_info.sin_addr.s_addr = hostnameToIP(ip.c_str())) != 0)
	{
	    errno = 0;
	    bind(socket_descriptor, (struct sockaddr *)&server_info, sizeof(server_info));
	    switch(errno)
	    {
		    case 0:
				port_status = false;
		    break;
		    case EADDRINUSE:
			    port_status = true;
		    break;
	    }
    }

	close(socket_descriptor);
	return port_status;
}
/********* END OF OS FUNCTIONS *********/
/***************************************/
/***************************************/

std::string appendDateNow(const std::string &arg, const char *dateFormat)
{
	struct tm *timeinfo;
	time_t rawtime = time(NULL);
	char timestamp[20];
	timeinfo = gmtime(&rawtime);
	strftime(timestamp, sizeof(timestamp), dateFormat, timeinfo);
	return arg + "-" + timestamp;
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
                    writeToLog(ERROR, logFile, msg.c_str());
                break;
                case 0:
                    if(isStrCsv(fileContent, ',') == -1)
                    {
                        msg = "The following file has failed csv validation: " + csvPath;
                        writeToLog(INFO, logFile, msg.c_str());
                    }
                    else
                    {
                        msg = "The following file has passed csv validation: " + csvPath;
                        writeToLog(INFO, logFile, msg.c_str());
                    }
                break;
                case 1:
                    msg = "The following file is empty: " + csvPath;
                    writeToLog(INFO, logFile, msg.c_str());
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

void base64Encode(const char* message, std::string &base64auth)
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

class ConfigFile
{
    std::unordered_map<std::string, std::string> config;
    void trim(std::string &str) {
        std::size_t first = str.find_first_not_of(" \t\f\v\n\r");
        if(first == std::string::npos) return;
        std::size_t last = str.find_last_not_of(" \t\f\v\n\r");
        str = str.substr(first, (last - first + 1));
    }

    public:
        ConfigFile(const std::string &filename, std::string &err) {
            std::ifstream ifs(filename);
            std::string line;

            if(!ifs.good()) { err = "Could not open config file"; return; }
            while(std::getline(ifs, line))
            {
                std::size_t found = line.find('=');
                if(found == std::string::npos) continue;

                std::string key = line.substr(0, found);
                trim(key);
                if(key[0] == '#') continue;

                std::string value = line.substr(found, std::string::npos);
                value.erase(0, 1); // erase '='
                trim(value);

                config.insert({key, value});
            }

            ifs.close();
        }

        void get_value(const std::string &key, std::string &value) {
            for(const auto &pair: config)
            {
                if(pair.first == key) {
                    value = pair.second;
                    break;
                }
            }
        }

        void get_value(const std::string &key, int &value) {
            for(const auto &pair: config)
            {
                if(pair.first == key) {
                    value = strtol(pair.second.c_str(), NULL, 0);
                    break;
                }
            }
        }

        int get_time_value(const std::string &key, size_t &value) {
            for(const auto &pair: config)
            {
                if(pair.first == key) {
                    char *endptr = NULL;
                    size_t v = strtol(pair.second.c_str(), &endptr, 0);
                    if(endptr == NULL) return -1;
                    else
                    {
                        std::string s(endptr);
                        trim(s);
                        if(s == "s") value = v;
                        else if(s == "m" || s == "min") value = v * 60;
                        else if(s == "h") value = v * 60 * 60;
                        else return -1;
                    }
                    break;
                }
            }

            return 0;
        }

        void get_value(const std::string &key, bool &value) {
            std::string v;
            for(const auto &pair: config)
            {
                if(pair.first == key) {
                    v = pair.second;
                    break;
                }
            }

            if(v == "true") value = true;
            else if(v == "false") value = false;
        }

        void get_value(const std::string &key, std::vector<std::string> &value) {
            std::string v;
            for(const auto &pair: config)
            {
                if(pair.first == key) {
                    v = pair.second;
                    break;
                }
            }

            if(v.empty()) return;

            std::istringstream iarg(v);
            std::string token;
            while(std::getline(iarg, token, ',')) {
                trim(token);
                value.push_back(token);
            }
        }

        void get_value(const std::string &key, std::vector<int> &value) {
            std::string v;
            for(const auto &pair: config)
            {
                if(pair.first == key) {
                    v = pair.second;
                    break;
                }
            }

            if(v.empty()) return;

            std::istringstream iarg(v);
            std::string token;
            while(std::getline(iarg, token, ',')) {
                value.push_back(std::stoi(token));
            }
        }

        void get_value(const std::string &key, std::pair<std::string, int> &value) {
            std::string v;
            for(const auto &pair: config)
            {
                if(pair.first == key) {
                    v = pair.second;
                    break;
                }
            }

            if(v.empty()) return;

            std::istringstream iarg(v);
            std::string token;
            std::getline(iarg, token, ':');
            value.first = token;
            std::getline(iarg, token);
            value.second = std::stoi(token);
        }
};

int writeToSocket(int *s, const char *str)
{
    if(write(*s, str, strlen(str)) < 0) return -1;

    // mark end of data
    if(write(*s, end, END) != END) return -1;

    return 0;
}

char *readFromFile(FILE* f)
{
    char *buffer = NULL;
    char *ptr = NULL;
    size_t counter = 0;
    int bytes = 0;
    int bytes_all = 0;

    do
    {
        counter += 1;
        bytes_all += bytes;
        ptr = (char *)realloc(buffer, BUFFER * counter);
        if(ptr == NULL) {free(buffer); return NULL;}

        buffer = ptr;
        // extended memory initialized to 0
        memset(buffer + BUFFER * (counter - 1), 0, BUFFER);

    } while((bytes = fread(buffer + bytes_all, sizeof(char), BUFFER, f)) > 0);

    return buffer;
}

char *readFromSocket(int *s)
{
    char *buffer = NULL;
    char *ptr = NULL;
    size_t counter = 0;
    int bytes = 0;
    int bytes_all = 0;

    do
    {
        // stop reading if we get END 0 bytes in a separate segment
        if(buffer != NULL && strncmp(buffer + bytes_all, end, END) == 0) break;

        counter += 1;
        bytes_all += bytes;

        ptr = (char *)realloc(buffer, BUFFER * counter);
        if(ptr == NULL) {free(buffer); return NULL;}

        buffer = ptr;
        // extended memory initialized to 0
        memset(buffer + BUFFER * (counter - 1), 0, BUFFER);

    } while((bytes = read(*s, buffer + bytes_all, BUFFER)) > 0);

    return buffer;
}

int acceptConnection(int *s, int *peer_s, struct sockaddr_in *peer_a, const char *host, unsigned short port)
{
    struct sockaddr_in address;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if(inet_aton(host, &address.sin_addr) == 0) return -1;

    if((*s = socket(AF_INET, SOCK_STREAM, 0)) == -1) return -1;

    if(bind(*s, (const struct sockaddr *)&address, sizeof(address)) == -1) return -1;

    if(listen(*s, SOMAXCONN) == -1) return -1;

    socklen_t peer_addr_len = sizeof(*peer_a);

    if((*peer_s = accept(*s, (struct sockaddr *)peer_a, &peer_addr_len)) == -1) return -1;

    return 0;
}

// Main module
void *Main(void *arg)
{
    ConfigFile *cf = (ConfigFile *) arg;
    bool enabled = true;
    cf->get_value("main_enabled", enabled);
    if(!enabled) return NULL;

    bool debug;
    std::string index_name, index_freq, index_type, elasticsearch_auth, log_file, csv_path,
    kafka_path, kafka_server_api, kafka_monitored_topics, kafka_monitored_groups;
    bool kafka_outdated_version;
    std::pair<std::string, int> elasticsearch_address, elasticsearch_api, logstash_address, logstash_api;
    std::vector<std::string> os_stats, processes, systemd_services, indices_stats;
    std::vector<int> port_numbers;
    size_t interval, system_health_check_interval;

    // default values
    index_name = "skimmer";
    index_freq = "monthly";
    index_type = "_doc";
    elasticsearch_auth = "logserver:logserver";
    log_file = "/tmp/skimmer.log";
    debug = false;
    kafka_outdated_version = false;
    interval = 0;
    system_health_check_interval = 0;

    // values from config file
    cf->get_value("index_name", index_name);
    cf->get_value("index_freq", index_freq);
    cf->get_value("index_type", index_type);
    cf->get_value("elasticsearch_auth", elasticsearch_auth);
    cf->get_value("elasticsearch_address", elasticsearch_address);
    cf->get_value("elasticsearch_api", elasticsearch_api);
    cf->get_value("logstash_address", logstash_address);
    cf->get_value("logstash_api", logstash_api);
    cf->get_value("log_file", log_file);
    cf->get_value("debug", debug);
    cf->get_value("os_stats", os_stats);
    cf->get_value("processes", processes);
    cf->get_value("systemd_services", systemd_services);
    cf->get_value("port_numbers", port_numbers);
    cf->get_value("csv_path", csv_path);
    cf->get_value("kafka_path", kafka_path);
    cf->get_value("kafka_server_api", kafka_server_api);
    cf->get_value("kafka_monitored_topics", kafka_monitored_topics);
    cf->get_value("kafka_monitored_groups", kafka_monitored_groups);
    cf->get_value("kafka_outdated_version", kafka_outdated_version);
    if(cf->get_time_value("interval", interval) != 0)
    {
        writeToLog(ERROR, log_file.c_str(), "Failed to parse interval option. Main module not loaded");
        return NULL;
    }
    if(interval < 10) interval = 60;

    if(cf->get_time_value("system_health_check_interval", system_health_check_interval) != 0)
    {
        writeToLog(ERROR, log_file.c_str(), "Failed to parse system_health_check_interval option. Main module not loaded");
        return NULL;
    }
    if(system_health_check_interval < interval) system_health_check_interval = 4 * 60 * 60;

    cf->get_value("indices_stats", indices_stats);

    // conversion
    std::string base64auth;
    base64Encode(elasticsearch_auth.c_str(), base64auth);

    // Module loaded
    writeToLog(INFO, log_file.c_str(), "Main module loaded");

    std::string msg;
    msg = "The following settings are used:\n";
    msg += "Index Name: " + index_name + " created " + index_freq + "\n";
    msg += "Index Type: " + index_type + "\n";
    msg += "Elasticsearch Auth: " + elasticsearch_auth + "\n";
    msg += "Interval: " + std::to_string(interval) + "\n";
    msg += "System Health Check Interval: " + std::to_string(system_health_check_interval) + "\n";

    if(!elasticsearch_address.first.empty()) msg += "Elasticsearch Output - IP: " + elasticsearch_address.first + ", Port: " + std::to_string(elasticsearch_address.second) + "\n";
    if(!elasticsearch_api.first.empty()) msg += "Elasticsearch API - IP: " + elasticsearch_api.first + ", Port: " + std::to_string(elasticsearch_api.second) + "\n";
    if(!logstash_address.first.empty()) msg += "Logstash Output - IP: " + logstash_address.first + ", Port: " + std::to_string(logstash_address.second) + "\n";
    if(!logstash_api.first.empty()) msg += "Logstash API - IP: " + logstash_api.first + ", Port: " + std::to_string(logstash_api.second) + "\n";
    if(!os_stats.empty()) { msg += "OS Statistics: "; for(const std::string &i: os_stats) { msg += i; msg += " "; } msg += "\n"; }
    if(!processes.empty()) { msg += "Processes: "; for(const std::string &i: processes) { msg += i; msg += " "; } msg += "\n"; }
    if(!systemd_services.empty()) { msg += "Systemd Services: "; for(const std::string &i: systemd_services) { msg += i; msg += " "; } msg += "\n"; }
    if(!port_numbers.empty()) { msg += "Port Numbers: "; for(const int &i: port_numbers) { msg += std::to_string(i); msg += " "; } msg += "\n"; }
    if(!csv_path.empty()) msg += "CSV Path: " + csv_path + "\n";
    if(!kafka_path.empty() && !kafka_server_api.empty())
    {
       msg += "Kafka path: " + kafka_path + "\n" + "Kafka server api: " + kafka_server_api + "\n";
       if(!kafka_monitored_topics.empty())
        msg += "Kafka monitored topics: " + kafka_monitored_topics + "\n";
       else
        msg += "Kafka monitored topics: all\n";

       if(!kafka_monitored_groups.empty())
        msg += "Kafka monitored groups: " + kafka_monitored_groups + "\n";
       else if(!kafka_outdated_version)
        msg += "Kafka monitored groups: all\n";
       else
        msg += "Kafka monitored groups: none\n";

       msg += "Kafka outdated version (before v.2.4.0): " + std::string(kafka_outdated_version ? "true" : "false") + "\n";
    }
    if(!indices_stats.empty()) { msg += "Indices stats: "; for(const std::string &i: indices_stats) { msg += i; msg += " "; } msg += "\n"; }

    writeToLog(INFO, log_file.c_str(), msg.c_str());

    PreviousAPICall previousAPICall;

    sigset_t sig;
    sigemptyset(&sig);
    sigaddset(&sig, SIGINT);
    sigaddset(&sig, SIGTERM);

    size_t uwait = interval * 1000000; // wait interval

    // infinite loop
    for(;;) {

    // start measure
    struct timeval  tv1, tv2;
    gettimeofday(&tv1, NULL);

    std::string index_name_now = index_name;
    if(index_freq == "daily")
        index_name_now = appendDateNow(index_name, "%Y.%m.%d");
    else if(index_freq == "monthly")
        index_name_now = appendDateNow(index_name, "%Y.%m");


    // Stats common for all nodes
    std::string stats_all;

    for(const std::string &str: os_stats)
	{
        if(str == "zombie")
        {
            stats_all = stats_all + zombie_count();
        }
        else if(str == "vm")
        {
            stats_all = stats_all + vm_stats();
        }
        else if(str == "fs")
        {
            stats_all = stats_all + fs_stats();
        }
        else if(str == "swap")
        {
            stats_all = stats_all + swap_stats();
        }
        else if(str == "net")
        {
            stats_all = stats_all + net_stats();
        }
        else if(str == "cpu")
        {
            stats_all = stats_all + cpu_stats();
        }
	}
    for(const std::string &str: processes)
	{
		stats_all = stats_all + process_pid(str.c_str());
	}
	for(const std::string &str: systemd_services)
	{
		stats_all = stats_all + systemd_service_status(str, false);
	}

    std::string hostname;
    std::vector<std::string> ip;
    node_hostname_ip(hostname, ip);
	for(int port: port_numbers)
	{
        std::unordered_map<std::string, std::string> port_status;
        bool flag = false;
        for(const std::string &i: ip) {
		    if(is_address_in_use(i, port)) flag = true;
        }
        if(flag) {
            port_status.insert({"node_stats_tcp_port_" + std::to_string(port), "in_use"});
        }
        else {
            port_status.insert({"node_stats_tcp_port_" + std::to_string(port), "unused"});
        }
        stats_all = stats_all + port_status;
	}

    if(!csv_path.empty()) checkCsvByPattern(csv_path.c_str(), log_file.c_str());

    // send os stats
    if(debug) {
        if(!stats_all.empty()) {
            std::string msg = "OS Stats: " + stats_all;
            writeToLog(DEBUG, log_file.c_str(), msg.c_str());
        }
        else {
            writeToLog(DEBUG, log_file.c_str(), "No OS Stats");
        }
    }
    sendDataToElasticsearch(debug, elasticsearch_address, index_name_now, index_type, base64auth, stats_all, log_file.c_str());
    sendDataToLogstash(logstash_address, stats_all);

    try {
        ElasticsearchStats elasticsearch(elasticsearch_api, base64auth, indices_stats);

        // get data
        std::string node_data = elasticsearch.get_node_stats();
        std::string cluster_data = elasticsearch.get_cluster_stats(previousAPICall);
        std::vector<std::string> indices_data = elasticsearch.get_indices_stats();
        std::vector<std::string> tasks_data = elasticsearch.get_cluster_tasks();
        std::vector<std::string> shards_data = elasticsearch.get_cluster_shards(interval, system_health_check_interval);
        if(debug) {
            if(!cluster_data.empty()) {
                std::string msg = "Elasticsearch Cluster Stats: " + cluster_data;
                writeToLog(DEBUG, log_file.c_str(), msg.c_str());
            }
            else {
                writeToLog(DEBUG, log_file.c_str(), "No Elasticsearch Cluster Stats");
            }

            if(!node_data.empty()) {
                std::string msg = "Elasticsearch Node Stats: " + node_data;
                writeToLog(DEBUG, log_file.c_str(), msg.c_str());
            }
            else {
                writeToLog(DEBUG, log_file.c_str(), "No Elasticsearch Node Stats");
            }

            for(const std::string &index_data: indices_data)
            {
                std::string msg = "Elasticsearch Index Stats: " + index_data;
                writeToLog(DEBUG, log_file.c_str(), msg.c_str());
            }

            for(const std::string &task_data: tasks_data)
            {
                std::string msg = "Elasticsearch Task Stats: " + task_data;
                writeToLog(DEBUG, log_file.c_str(), msg.c_str());
            }

            for(const std::string &shard_data: shards_data)
            {
                std::string msg = "Elasticsearch Shard Stats: " + shard_data;
                writeToLog(DEBUG, log_file.c_str(), msg.c_str());
            }
        }

        // send data to elasticsearch
        sendDataToElasticsearch(debug, elasticsearch_address, index_name_now, index_type, base64auth, node_data, log_file.c_str());
        sendDataToElasticsearch(debug, elasticsearch_address, index_name_now, index_type, base64auth, cluster_data, log_file.c_str());
        for(std::string &index_data: indices_data)
            sendDataToElasticsearch(debug, elasticsearch_address, index_name_now, index_type, base64auth, index_data, log_file.c_str());
        for(std::string &task_data: tasks_data)
            sendDataToElasticsearch(debug, elasticsearch_address, index_name_now, index_type, base64auth, task_data, log_file.c_str());
        for(std::string &shard_data: shards_data)
            sendDataToElasticsearch(debug, elasticsearch_address, index_name_now, index_type, base64auth, shard_data, log_file.c_str());

        // send data to logstash
        sendDataToLogstash(logstash_address, node_data);
        sendDataToLogstash(logstash_address, cluster_data);
        for(std::string &index_data: indices_data)
            sendDataToLogstash(logstash_address, index_data);
        for(std::string &task_data: tasks_data)
            sendDataToLogstash(logstash_address, task_data);
        for(std::string &shard_data: shards_data)
            sendDataToLogstash(logstash_address, shard_data);
    }
    catch(const std::runtime_error &error) {
        writeToLog(ERROR, log_file.c_str(), error.what());
    }

    try {
        LogstashStats logstash(logstash_api);

        // get data
        std::string logstash_data = logstash.get_api_stats();
        if(debug) {
            if(!logstash_data.empty()) {
                std::string msg = "Logstash Stats: " + logstash_data;
                writeToLog(DEBUG, log_file.c_str(), msg.c_str());
            }
            else {
                writeToLog(DEBUG, log_file.c_str(), "No Logstash Stats");
            }
        }

        // send data to elasticsearch
        sendDataToElasticsearch(debug, elasticsearch_address, index_name_now, index_type, base64auth, logstash_data, log_file.c_str());

        // send data to logstash
        sendDataToLogstash(logstash_address, logstash_data);
    }
    catch(const std::runtime_error &error) {
        writeToLog(ERROR, log_file.c_str(), error.what());
    }

    if(kafka_path != "" && kafka_server_api != "")
    {
      try
      {
        KafkaStats kafkaStats(log_file, kafka_path, kafka_server_api, kafka_monitored_topics, kafka_monitored_groups, kafka_outdated_version);

        //get data
        std::vector<std::string> kafka_stats = kafkaStats.get_data_for_elasticsearch();
        if(debug)
        {
          if(!kafka_stats.empty())
          {
            std::string msg = "Kafka Stats: ";
            for(const auto& data : kafka_stats)
              msg += data + "\n";

            writeToLog(DEBUG, log_file.c_str(), msg.c_str());
          }
          else
          {
            writeToLog(DEBUG, log_file.c_str(), "No Kafka Stats");
          }
        }
        for(auto &data : kafka_stats)
         sendDataToElasticsearch(debug, elasticsearch_address, index_name_now, index_type, base64auth, data, log_file.c_str());
     }
     catch(const std::runtime_error &error)
     {
        writeToLog(ERROR, log_file.c_str(), error.what());
     }
    }

    // stop measure
    gettimeofday(&tv2, NULL);
    size_t udiff = (tv2.tv_usec - tv1.tv_usec) + (tv2.tv_sec - tv1.tv_sec) * 1000000;
    if( udiff < uwait ) {

        struct timeval interval_val;
        interval_val.tv_sec = (uwait - udiff) / 1000000;
        interval_val.tv_usec = uwait - udiff - interval_val.tv_sec * 1000000;

        // sleep unless signal is delivered
        struct timespec interval_spec;
        TIMEVAL_TO_TIMESPEC(&interval_val, &interval_spec);
        int sig_code = sigtimedwait(&sig, NULL, &interval_spec);
        if(sig_code == SIGINT || sig_code == SIGTERM) break;
    }

    }

    return NULL;
}

// PSexec module
void *PSexec(void *arg)
{
    ConfigFile *cf = (ConfigFile *) arg;
    bool enabled = false;
    cf->get_value("ps_enabled", enabled);
    if(!enabled) return NULL;

    std::string log_file;
    bool debug;

    // default values
    log_file = "/tmp/skimmer.log";
    debug = false;
    ps.port = 10000;
    ps.exec_step = 60;
    ps.path = "/tmp/skimmer.ps1";
    std::pair<std::string, int> logstash_address = {"127.0.0.1", 6111};
    ps.script = NULL;
    ps.response = NULL;

    // values from config file
    cf->get_value("log_file", log_file);
    cf->get_value("debug", debug);
    cf->get_value("logstash_address", logstash_address);

    if(cf->get_time_value("ps_exec_step", ps.exec_step) != 0)
    {
        writeToLog(ERROR, log_file.c_str(), "Failed to parse ps_exec_step option. PSexec module not loaded");
        return NULL;
    }

    std::string ps_port, ps_path;
    cf->get_value("ps_port", ps_port);
    cf->get_value("ps_path", ps_path);
    if(!ps_port.empty()) ps.port = std::stoi(ps_port);
    if(!ps_path.empty()) ps.path = ps_path.c_str();

    FILE *f = fopen(ps.path, "r");
    if(f != NULL) {
        ps.script = readFromFile(f);
        fclose(f);
    }

    if(ps.script == NULL) return NULL;

    // Module loaded
    writeToLog(INFO, log_file.c_str(), "PSexec module loaded");

    std::string msg;
    msg = "The following settings are used:\n";
    msg += "PS Port: " + std::to_string(ps.port) + "\n";
    msg += "PS Execution Interval: " + std::to_string(ps.exec_step) + "\n";
    msg += "PS Path: " + std::string(ps.path) + "\n";
    if(!logstash_address.first.empty()) msg += "Logstash Output - IP: " + logstash_address.first + ", Port: " + std::to_string(logstash_address.second) + "\n";

    writeToLog(INFO, log_file.c_str(), msg.c_str());

    // ignore sigpipe generated by operations on closed socket
    signal(SIGPIPE, SIG_IGN);

    for(;;) {
        sigset_t sig;
        sigemptyset(&sig);
        sigaddset(&sig, SIGINT);
        sigaddset(&sig, SIGTERM);
        // unblock SIGINT && SIGTERM
        if(pthread_sigmask(SIG_UNBLOCK, &sig, NULL) != 0) return NULL;

        // wait for connection
        int s, peer_s;
        int sig_caught = 0;
        struct sockaddr_in peer_a; // info about peer
        if(acceptConnection(&s, &peer_s, &peer_a, "0.0.0.0", ps.port) != 0) return NULL;

        // block SIGINT && SIGTERM
        if(pthread_sigmask(SIG_BLOCK, &sig, NULL) != 0) return NULL;

        msg = "Got connection from " + std::string(inet_ntoa(peer_a.sin_addr));
        writeToLog(INFO, log_file.c_str(), msg.c_str());
        for(;;) {
            sig_caught = 0;
            free(ps.response);
            ps.response = NULL;

            if(writeToSocket(&peer_s, ps.script) == -1) break;

            ps.response = readFromSocket(&peer_s);
            // break connection if error occurred or peer closed the connection by sending only one segment of END 0 bytes
            if(ps.response == NULL || strncmp(ps.response, end, END) == 0) break;

            // send response to logstash
            sendDataToLogstash(logstash_address, ps.response);

            // sleep unless signal is delivered
            struct timespec exec_step;
            exec_step.tv_sec = ps.exec_step;
            exec_step.tv_nsec = 0;
            int sig_code = sigtimedwait(&sig, NULL, &exec_step);
            if(sig_code == SIGINT || sig_code == SIGTERM) { sig_caught = 1; break; }
        }

        // close connection on other end
        write(peer_s, end, END);
        close(peer_s);
        close(s);
        if(sig_caught) break;
    }

    free(ps.response);
    free(ps.script);
    return NULL;
}

void printHelp()
{
	std::cout << "Usage for skimmer version " << VERSION << std::endl;
    std::cout << "\t-h print this help message" << std::endl;
    std::cout << "\t-c path to configuration file" << std::endl;
    std::cout << "\t-s print sample configuration file" << std::endl;
}

void printSampleConfig()
{
    std::cout << "[Global] - applies to all modules" << std::endl;

    std::cout << "# path to log file" << std::endl;
    std::cout << "log_file = /var/log/skimmer/skimmer.log" << std::endl << std::endl;

    std::cout << "# enable debug logging" << std::endl;
    std::cout << "# debug = true" << std::endl << std::endl;

    std::cout << "[Main] - collect stats" << std::endl;
    std::cout << "main_enabled = true" << std::endl;

    std::cout << "# index name in elasticsearch" << std::endl;
    std::cout << "index_name = skimmer" << std::endl;
    std::cout << "index_freq = monthly" << std::endl << std::endl;

    std::cout << "# type in elasticsearch index" << std::endl;
    std::cout << "index_type = _doc" << std::endl << std::endl;

    std::cout << "# user and password to elasticsearch api" << std::endl;
    std::cout << "elasticsearch_auth = logserver:logserver" << std::endl << std::endl;

    std::cout << "# how often to collect stats (lower threshold = 10s)" << std::endl;
    std::cout << "# interval = 1min" << std::endl << std::endl;

    std::cout << "# how often to collect shards stats (lower threshold = interval)" << std::endl;
    std::cout << "# system_health_check_interval = 4h" << std::endl << std::endl;

    std::cout << "# available outputs" << std::endl;
    std::cout << "elasticsearch_address = 127.0.0.1:9200" << std::endl;
    std::cout << "# logstash_address = 127.0.0.1:6110" << std::endl << std::endl;

    std::cout << "# retrieve from api" << std::endl;
    std::cout << "elasticsearch_api = 127.0.0.1:9200" << std::endl;
    std::cout << "logstash_api = 127.0.0.1:9600" << std::endl << std::endl;

    std::cout << "# monitor individual indices from elasticsearch api" << std::endl;
    std::cout << "# comma separated list of indices" << std::endl;
    std::cout << "# indices_stats = *" << std::endl << std::endl;

    std::cout << "# monitor kafka" << std::endl;
    std::cout << "# kafka_path = /usr/share/kafka/" << std::endl;
    std::cout << "# kafka_server_api = 127.0.0.1:9092" << std::endl;
    std::cout << "# comma separated kafka topics to be monitored, empty means all available topics" << std::endl;
    std::cout << "# kafka_monitored_topics = topic1,topic2" << std::endl;
    std::cout << "# comma separated kafka groups to be monitored, empty means all available groups (if kafka_outdated_version = false)" << std::endl;
    std::cout << "# kafka_monitored_groups = group1,group2" << std::endl;
    std::cout << "# switch to true if you use outdated version of kafka - before v.2.4.0" << std::endl;
    std::cout << "# kafka_outdated_version = false" << std::endl << std::endl;

    std::cout << "# comma separated OS statistics selected from the list [zombie,vm,fs,swap,net,cpu]" << std::endl;
    std::cout << "os_stats = zombie,vm,fs,swap,net,cpu" << std::endl << std::endl;

    std::cout << "# comma separated process names to print their pid" << std::endl;
    std::cout << "processes = /usr/sbin/sshd,/usr/sbin/rsyslogd" << std::endl << std::endl;

    std::cout << "# comma separated systemd services to print their status" << std::endl;
    std::cout << "systemd_services = elasticsearch,logstash,alert,cerebro,kibana" << std::endl << std::endl;

    std::cout << "# comma separated port numbers to print if address is in use" << std::endl;
    std::cout << "port_numbers = 9200,9300,9600,5514,5044,443,5601,5602" << std::endl << std::endl;

    std::cout << "# path to directory containing files needed to be csv validated" << std::endl;
    std::cout << "# csv_path = /opt/skimmer/csv/" << std::endl << std::endl;

    std::cout << "[PSexec] - run powershell script remotely (skimmer must be installed on Windows)" << std::endl;
    std::cout << "ps_enabled = false" << std::endl;
    std::cout << "# port used to establish connection" << std::endl;
    std::cout << "# ps_port = 10000" << std::endl << std::endl;

    std::cout << "# how often to execute the script" << std::endl;
    std::cout << "# ps_exec_step = 1min" << std::endl << std::endl;

    std::cout << "# path to the script which will be sent and executed on remote end" << std::endl;
    std::cout << "# ps_path = /opt/skimmer/skimmer.ps1" << std::endl << std::endl;

    std::cout << "# available outputs" << std::endl;
    std::cout << "# ps_logstash_address = 127.0.0.1:6111" << std::endl;
}

const char *readArgs(int argc, char *argv[])
{
    int opt;

    while((opt = getopt(argc, argv, "hsc:")) != -1)
    {
	    switch(opt)
	    {
		    case 'h':
			    printHelp();
                return NULL;
            case 's':
                printSampleConfig();
                return NULL;
            case 'c':
                return optarg;
            default:
			    printHelp();
                return NULL;
	    }
    }

    printHelp();
    return NULL;
}

int main(int argc, char *argv[])
{
    // init
    setlocale(LC_ALL, "");

    // readable error messages
    SSL_load_error_strings();
    // initialize library
    SSL_library_init();

    // get config filename
    const char *filename = NULL;
    // do not return an error code here please
    if((filename = readArgs(argc, argv)) == NULL) return 0;

    // read config file
    std::string err;
    ConfigFile cf(filename, err);
    if(!err.empty()) { std::cerr << err << std::endl; return -1; }

    std::string log_file;

    // default values
    log_file = "/tmp/skimmer.log";

    // values from config file
    cf.get_value("log_file", log_file);

    // check if log is writable
    std::ofstream ofs(log_file);
    if(!ofs.good()) { std::cerr << "Could not open log file for writing" << std::endl; return -1; }
    ofs.close();

    // block SIGINT && SIGTERM
    sigset_t sig;
    sigemptyset(&sig);
    sigaddset(&sig, SIGINT);
    sigaddset(&sig, SIGTERM);
    if(pthread_sigmask(SIG_BLOCK, &sig, NULL) != 0) return -1;

    // init mutex
    pthread_mutex_init(&mutex, NULL);

    // logging
    std::string msg = "Skimmer version " + std::string(VERSION) + " started\n";
    writeToLog(INFO, log_file.c_str(), msg.c_str());

    // Main module
    pthread_create(&threads[0], NULL, Main, (void *) &cf);

    // PSexec module
    pthread_create(&threads[1], NULL, PSexec, (void *) &cf);

    // wait for threads to finish
    for (int i = 0; i < MODULES; i++)
        pthread_join(threads[i], NULL);

    // cleanup
    pthread_mutex_destroy(&mutex);

    return 0;
}
#endif
