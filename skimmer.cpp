/*
 * Linux
 * g++ -std=c++11 -pedantic -Wall -Wextra skimmer.cpp -o skimmer -lssl -lcrypto -pthread
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
#endif

#define IP_MAX      16
#define BUFFER      1024
#define MIN_PORT    1
#define MAX_PORT    65535
#define SLEEP_US    100000
#define MODULES     2
#define VERSION     "1.0.10a"

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
struct PS_CLIENT
{
    SOCKET s;
    WSADATA wsa;
    char *command;      // command/script sent from remote host
    char *ps1_path;     // full path to skimmer.ps1 which contains command to execute
    char *dat_path;     // full path to skimmer.dat where result from running skimmer.ps1 is stored
    wchar_t *output;    // contents of skimmer.dat
};
struct PS_CLIENT ps_client;

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
        len += wcrtomb(buffer + len, *str, NULL);
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

int manageConnection(int *new_conn, WSADATA *wsa, SOCKET *s, const char *host, unsigned short port, int delay)
{
    static int first = 1;

    // clean up if it's new and not the first connection
    if(*new_conn && !first) {
        closesocket(*s);
        WSACleanup();
    }

    // if connection is not new then skip this part
    if(*new_conn) {
        // turn off first connection flag
        first = 0;

        struct sockaddr_in server_info;
        if(WSAStartup(MAKEWORD(2,2), wsa) != 0) return -1;
        if((*s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) return -1;

        memset(&server_info, 0, sizeof(server_info));
        server_info.sin_family = AF_INET;
        server_info.sin_port = htons(port);

        if((server_info.sin_addr.s_addr = hostnameToIP(host)) == 0) return -1;

        if(connect(*s, (struct sockaddr *)&server_info, sizeof(server_info)) != 0)
        {
            Sleep(delay * 1000);
            return -1;
        }

        fprintf(stderr, "Established connection to server\n");
    }

    // reset to a new connection
    *new_conn = 1;

    return 0;
}

void printHelp()
{
    std::cout << "Usage for skimmer version " << VERSION << " <PSexec module>" << std::endl;
    std::cout << "\t-i server's ip" << std::endl;
    std::cout << "\t-p server's port" << std::endl;
    std::cout << "\t-d how often (in seconds) to send SYN packet when setting up connection for the first time (default 60)" << std::endl;
}

int main(int argc, char *argv[])
{
    setlocale(LC_ALL, "");
    int delay = 60;
    char hostname[BUFFER] = {0};
    unsigned short port = 0;

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

    // init
    // new connection
    int new_conn = 1;
    ps_client.command = NULL;
    ps_client.ps1_path = NULL;
    ps_client.dat_path = NULL;
    ps_client.output = NULL;

    // maintain connection
    for(;;) {
        // clean up
        free(ps_client.command);
        free(ps_client.ps1_path);
        free(ps_client.dat_path);
        free(ps_client.output);
        ps_client.command = NULL;
        ps_client.ps1_path = NULL;
        ps_client.dat_path = NULL;
        ps_client.output = NULL;

        // manage connection
        if(manageConnection(&new_conn, &ps_client.wsa, &ps_client.s, hostname, port, delay) != 0) continue;

        // get command/script from remote host
        ps_client.command = readFromSocket(&ps_client.s);
        // start a new connection if error occurred or peer closed the connection by sending only one segment of END 0 bytes
        if(ps_client.command == NULL || strncmp(ps_client.command, end, END) == 0) continue;

        // get APPDATA path
        const char *appdata = getenv("APPDATA");
        if(appdata == NULL) continue;

        // path to skimmer.ps1
        size_t file_path_s = strlen(appdata) + BUFFER;
        ps_client.ps1_path = (char *)malloc(file_path_s * sizeof(char));
        if(ps_client.ps1_path == NULL) continue;
        snprintf(ps_client.ps1_path, file_path_s, "%s\\skimmer.ps1", appdata);

        // write command/script to skimmer.ps1
        FILE *fout = fopen(ps_client.ps1_path, "w");
        if(fout == NULL) continue;
        if(writeToFile(fout, ps_client.command) != 0) { fclose(fout); continue; }
        fclose(fout);

        // path to skimmer.dat
        ps_client.dat_path = (char *)malloc(file_path_s * sizeof(char));
        if(ps_client.dat_path == NULL) continue;
        snprintf(ps_client.dat_path, file_path_s, "%s\\skimmer.dat", appdata);

        // run skimmer.ps1 and redirect output to skimmer.dat
        size_t cmd_s = strlen(ps_client.ps1_path) + strlen(ps_client.dat_path) + BUFFER;
        char *cmd = (char *)malloc(cmd_s * sizeof(char));
        if(cmd == NULL) continue;
        snprintf(cmd, cmd_s, "powershell -executionpolicy bypass -command \"& %s 2>&1 | Out-File -Encoding utf8 -FilePath %s\"", ps_client.ps1_path, ps_client.dat_path);

        system(cmd);
        free(cmd);

        // read skimmer.dat to memory
        wchar_t *dat_path_w = (wchar_t *)calloc(file_path_s, sizeof(wchar_t));
        if(dat_path_w == NULL) continue;
        mbsrtowcs(dat_path_w, (const char **)&ps_client.dat_path, file_path_s * sizeof(wchar_t) - 1, NULL);

        FILE *fin = _wfopen(dat_path_w, L"rt,ccs=UTF-8");
        if(fin == NULL) { free(dat_path_w); continue; }

        ps_client.output = readWcFromFile(fin);
        if(ps_client.output == NULL) { fclose(fin); free(dat_path_w); continue; }
        fclose(fin);
        free(dat_path_w);

        // send skimmer.dat to server
        if(writeWcToSocket(&ps_client.s, (const wchar_t *)ps_client.output) != 0) continue;

        // maintain connection
        new_conn = 0;
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

int writeToLog(LOG_LEVEL level, const char *filename, const char *message)
{
        FILE *logFile = fopen(filename, "a");
        if(logFile == NULL){fprintf(stderr, "cannot open log file\n");return -1;}
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

    std::unordered_map<std::string, long double> node_stats();
    std::unordered_map<std::string, uint64_t> cluster_stats();
    std::unordered_map<std::string, long double> cluster_health();
    std::unordered_map<std::string, uint64_t> cluster_pending_tasks();

    public:
    // usleep to avoid HTTP 429
    ElasticsearchStats(const std::pair<std::string, unsigned short> &_API, const std::string &_base64auth):
    API(_API), base64auth(_base64auth)
    {
        // Init
        node_response = NULL;
        cluster_response = NULL;
        cluster_health_response = NULL;
        cluster_pending_tasks_response = NULL;

        // API
        if(!API.first.empty()) {

            // determine whether to use SSL or plain
            int SSL = isSSL(API.first.c_str(), API.second);
            if(SSL == 0) { get_data = &readSSLResponse; send_data = &sendSSLData; }
            else if(SSL == 1) { get_data = &readResponse; send_data = &sendData; }
            else throw std::runtime_error("Failed to construct ElasticsearchStats object: Unable to communicate with cluster");

            // determine IP of all nodes in the cluster
            usleep(SLEEP_US);
            if(nodes_ip() == -1) throw std::runtime_error("Failed to construct ElasticsearchStats object: Unable to determine nodes in the cluster");
            // determine master node IP
            usleep(SLEEP_US);
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
            usleep(SLEEP_US);
            std::string elastic_request = "GET /_nodes/" + thisIP + "/stats HTTP/1.0\r\nContent-type: application/json\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
            node_response = get_data(elastic_request.c_str(), API.first.c_str(), API.second);

            // retrieve cluster stats
            if(thisIP == masterNodeIP) {
                usleep(SLEEP_US);
                elastic_request = "GET /_cluster/stats HTTP/1.0\r\nContent-type: application/json\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
                cluster_response = get_data(elastic_request.c_str(), API.first.c_str(), API.second);
                usleep(SLEEP_US);
                elastic_request = "GET /_cluster/health HTTP/1.0\r\nContent-type: application/json\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
	            cluster_health_response = get_data(elastic_request.c_str(), API.first.c_str(), API.second);
                usleep(SLEEP_US);
                elastic_request = "GET /_cluster/pending_tasks HTTP/1.0\r\nContent-type: application/json\r\nAuthorization: Basic " + base64auth + "\r\n\r\n";
                cluster_pending_tasks_response = get_data(elastic_request.c_str(), API.first.c_str(), API.second);
            }
        }
    };
    ~ElasticsearchStats(){free((char *)node_response); free((char *)cluster_response); free((char *)cluster_health_response); free((char *)cluster_pending_tasks_response);};

    std::string get_node_stats()
    {
        if(node_response == NULL) return "";

        std::string json_output;
        json_output = json_output + api_timestamp(node_response) + get_hostname() + get_ip() + node_stats();

        return json_output;
    };

    std::string get_cluster_stats()
    {
        if(cluster_response == NULL || cluster_health_response == NULL || cluster_pending_tasks_response == NULL) return "";

        std::string json_output;
        json_output = json_output + api_timestamp(cluster_response) + get_hostname() + get_ip() + cluster_stats() + cluster_health() + cluster_pending_tasks();

        return json_output;
    };
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

    if(stats.at("node_stats_jvm_gc_collectors_young_collection_count") != 0)
        stats.insert({"node_stats_jvm_gc_collectors_young_collection_duration", stats.at("node_stats_jvm_gc_collectors_young_collection_time_in_millis") / stats.at("node_stats_jvm_gc_collectors_young_collection_count")});

    if(stats.at("node_stats_indices_indexing_index_total") != 0)
        stats.insert({"node_stats_indices_indexing_index_duration", stats.at("node_stats_indices_indexing_index_time_in_millis") / stats.at("node_stats_indices_indexing_index_total")});

    if(stats.at("node_stats_indices_refresh_total") != 0)
        stats.insert({"node_stats_indices_refresh_duration", stats.at("node_stats_indices_refresh_total_time_in_millis") / stats.at("node_stats_indices_refresh_total")});
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

std::unordered_map<std::string, uint64_t> ElasticsearchStats::cluster_stats()
{
    std::unordered_map<std::string, uint64_t> stats;
    if(getHttpStatus(cluster_response) != 200) return stats;
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

            stats.insert({description, strtol(value, NULL, 0)});
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

int sendDataToElasticsearch(bool debug, const std::pair<std::string, unsigned short> &OUTPUT, const std::string &index, const std::string &type, const std::string &base64auth, const std::string &data, const char *logfile)
{
    if(data.empty()) return -1;
    if(OUTPUT.first.empty()) return -1;
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
            json_output = json_output + get_hostname() + get_ip() + api_stats() + cpu_load();

            return json_output;
        };
};

int sendDataToLogstash(const std::pair<std::string, unsigned short> &OUTPUT, const std::string &data)
{
    if(data.empty()) return -1;
    if(OUTPUT.first.empty()) return -1;
    return sendData(data.c_str(), OUTPUT.first.c_str(), OUTPUT.second);
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
            for(auto &pair: config)
            {
                if(pair.first == key) {
                    value = pair.second;
                    break;
                }
            }
        }

        void get_value(const std::string &key, bool &value) {
            std::string v;
            for(auto &pair: config)
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
            for(auto &pair: config)
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
                value.push_back(token);
            }
        }

        void get_value(const std::string &key, std::vector<int> &value) {
            std::string v;
            for(auto &pair: config)
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
            for(auto &pair: config)
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
    std::string index_name, index_freq, index_type, elasticsearch_auth, log_file, csv_path;
    std::pair<std::string, int> elasticsearch_address, elasticsearch_api, logstash_address, logstash_api;
    std::vector<std::string> os_stats, processes, systemd_services;
    std::vector<int> port_numbers;

    // default values
    index_name = "skimmer";
    index_freq = "monthly";
    index_type = "_doc";
    elasticsearch_auth = "logserver:logserver";
    log_file = "/tmp/skimmer.log";
    debug = false;

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

    // conversion
    std::string base64auth;
    base64Encode(elasticsearch_auth.c_str(), base64auth);

    // Module loaded
    pthread_mutex_lock(&mutex);
        writeToLog(INFO, log_file.c_str(), "Main module loaded");
    pthread_mutex_unlock(&mutex);

    std::string msg;
    msg = "The following settings are used:\n";
    msg += "Index Name: " + index_name + " created " + index_freq + "\n";
    msg += "Index Type: " + index_type + "\n";
    msg += "Elasticsearch Auth: " + elasticsearch_auth + "\n";

    if(!elasticsearch_address.first.empty()) msg += "Elasticsearch Output - IP: " + elasticsearch_address.first + ", Port: " + std::to_string(elasticsearch_address.second) + "\n";
    if(!elasticsearch_api.first.empty()) msg += "Elasticsearch API - IP: " + elasticsearch_api.first + ", Port: " + std::to_string(elasticsearch_api.second) + "\n";
    if(!logstash_address.first.empty()) msg += "Logstash Output - IP: " + logstash_address.first + ", Port: " + std::to_string(logstash_address.second) + "\n";
    if(!logstash_api.first.empty()) msg += "Logstash API - IP: " + logstash_api.first + ", Port: " + std::to_string(logstash_api.second) + "\n";
    if(!os_stats.empty()) { msg += "OS Statistics: "; for(const std::string &i: os_stats) { msg += i; msg += " "; } msg += "\n"; }
    if(!processes.empty()) { msg += "Processes: "; for(const std::string &i: processes) { msg += i; msg += " "; } msg += "\n"; }
    if(!systemd_services.empty()) { msg += "Systemd Services: "; for(const std::string &i: systemd_services) { msg += i; msg += " "; } msg += "\n"; }
    if(!port_numbers.empty()) { msg += "Port Numbers: "; for(const int &i: port_numbers) { msg += std::to_string(i); msg += " "; } msg += "\n"; }
    if(!csv_path.empty()) msg += "CSV Path: " + csv_path + "\n";

    pthread_mutex_lock(&mutex);
        writeToLog(INFO, log_file.c_str(), msg.c_str());
    pthread_mutex_unlock(&mutex);


    const size_t uwait = 60000000; // wait 1 minute
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
    stats_all = stats_all + get_hostname() + get_ip();

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
        std::string msg = "OS Stats: " + stats_all;
        pthread_mutex_lock(&mutex);
            writeToLog(DEBUG, log_file.c_str(), msg.c_str());
        pthread_mutex_unlock(&mutex);
    }
    pthread_mutex_lock(&mutex);
        sendDataToElasticsearch(debug, elasticsearch_address, index_name_now, index_type, base64auth, stats_all, log_file.c_str());
        sendDataToLogstash(logstash_address, stats_all);
    pthread_mutex_unlock(&mutex);

    try {
        ElasticsearchStats elasticsearch(elasticsearch_api, base64auth);

        // get data
        std::string node_data = elasticsearch.get_node_stats();
        std::string cluster_data = elasticsearch.get_cluster_stats();
        if(debug) {
            if(!cluster_data.empty()) {
                std::string msg = "Elasticsearch Cluster Stats: " + cluster_data;
                pthread_mutex_lock(&mutex);
                    writeToLog(DEBUG, log_file.c_str(), msg.c_str());
                pthread_mutex_unlock(&mutex);
            }
            else {
                pthread_mutex_lock(&mutex);
                    writeToLog(DEBUG, log_file.c_str(), "No Elasticsearch Cluster Stats");
                pthread_mutex_unlock(&mutex);
            }

            if(!node_data.empty()) {
                std::string msg = "Elasticsearch Node Stats: " + node_data;
                pthread_mutex_lock(&mutex);
                    writeToLog(DEBUG, log_file.c_str(), msg.c_str());
                pthread_mutex_unlock(&mutex);
            }
            else {
                pthread_mutex_lock(&mutex);
                    writeToLog(DEBUG, log_file.c_str(), "No Elasticsearch Node Stats");
                pthread_mutex_unlock(&mutex);
            }
        }

        pthread_mutex_lock(&mutex);
            // send data to elasticsearch
            sendDataToElasticsearch(debug, elasticsearch_address, index_name_now, index_type, base64auth, node_data, log_file.c_str());
            sendDataToElasticsearch(debug, elasticsearch_address, index_name_now, index_type, base64auth, cluster_data, log_file.c_str());

            // send data to logstash
            sendDataToLogstash(logstash_address, node_data);
            sendDataToLogstash(logstash_address, cluster_data);
        pthread_mutex_unlock(&mutex);
    }
    catch(const std::runtime_error &error) {
        pthread_mutex_lock(&mutex);
            writeToLog(ERROR, log_file.c_str(), error.what());
        pthread_mutex_unlock(&mutex);
    }

    try {
        LogstashStats logstash(logstash_api);

        // get data
        std::string logstash_data = logstash.get_api_stats();
        if(debug) {
            if(!logstash_data.empty()) {
                std::string msg = "Logstash Stats: " + logstash_data;
                pthread_mutex_lock(&mutex);
                    writeToLog(DEBUG, log_file.c_str(), msg.c_str());
                pthread_mutex_unlock(&mutex);
            }
            else {
                pthread_mutex_lock(&mutex);
                    writeToLog(DEBUG, log_file.c_str(), "No Logstash Stats");
                pthread_mutex_unlock(&mutex);
            }
        }

        pthread_mutex_lock(&mutex);
            // send data to elasticsearch
            sendDataToElasticsearch(debug, elasticsearch_address, index_name_now, index_type, base64auth, logstash_data, log_file.c_str());

            // send data to logstash
            sendDataToLogstash(logstash_address, logstash_data);
        pthread_mutex_unlock(&mutex);
    }
    catch(const std::runtime_error &error) {
        pthread_mutex_lock(&mutex);
            writeToLog(ERROR, log_file.c_str(), error.what());
        pthread_mutex_unlock(&mutex);
    }


    // stop measure
    gettimeofday(&tv2, NULL);
    size_t udiff = (tv2.tv_usec - tv1.tv_usec) + (tv2.tv_sec - tv1.tv_sec) * 1000000;
    if( (uwait - udiff) <= uwait ) {
        int sig_caught = 0;
        size_t elapsed = 0;
        sigset_t sig_p;
        // sleep the remaining microseconds of a second
        double sleep_sec = double(uwait - udiff) / 1000000;
        usleep( double( sleep_sec - size_t(sleep_sec) ) * 1000000 );

        // sleep in 1s interval to handle signals
        while(elapsed < (uwait - udiff) / 1000000) {
            sigpending(&sig_p);
            if(sigismember(&sig_p, SIGINT) == 1 || sigismember(&sig_p, SIGTERM) == 1) { sig_caught = 1; break; }
            sleep(1);
            ++elapsed;
        }
        if(sig_caught) break;
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

    std::string ps_port, ps_exec_step, ps_path;
    cf->get_value("ps_port", ps_port);
    cf->get_value("ps_exec_step", ps_exec_step);
    cf->get_value("ps_path", ps_path);
    if(!ps_port.empty()) ps.port = std::stoi(ps_port);
    if(!ps_exec_step.empty()) ps.exec_step = std::stoi(ps_exec_step);
    if(!ps_path.empty()) ps.path = ps_path.c_str();

    FILE *f = fopen(ps.path, "r");
    if(f != NULL) {
        ps.script = readFromFile(f);
        fclose(f);
    }

    if(ps.script == NULL) return NULL;

    // Module loaded
    pthread_mutex_lock(&mutex);
        writeToLog(INFO, log_file.c_str(), "PSexec module loaded");
    pthread_mutex_unlock(&mutex);

    std::string msg;
    msg = "The following settings are used:\n";
    msg += "PS Port: " + std::to_string(ps.port) + "\n";
    msg += "PS Execution Interval: " + std::to_string(ps.exec_step) + "\n";
    msg += "PS Path: " + std::string(ps.path) + "\n";
    if(!logstash_address.first.empty()) msg += "Logstash Output - IP: " + logstash_address.first + ", Port: " + std::to_string(logstash_address.second) + "\n";

    pthread_mutex_lock(&mutex);
        writeToLog(INFO, log_file.c_str(), msg.c_str());
    pthread_mutex_unlock(&mutex);

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
        pthread_mutex_lock(&mutex);
            writeToLog(INFO, log_file.c_str(), msg.c_str());
        pthread_mutex_unlock(&mutex);
        for(;;) {
            sigset_t sig_p;
            size_t elapsed = 0;
            sig_caught = 0;
            free(ps.response);
            ps.response = NULL;

            if(writeToSocket(&peer_s, ps.script) == -1) break;

            ps.response = readFromSocket(&peer_s);
            // break connection if error occurred or peer closed the connection by sending only one segment of END 0 bytes
            if(ps.response == NULL || strncmp(ps.response, end, END) == 0) break;

            // send response to logstash
            sendDataToLogstash(logstash_address, ps.response);

            // sleep in 1s interval to handle signals
            while(elapsed <= ps.exec_step) {
                sigpending(&sig_p);
                if(sigismember(&sig_p, SIGINT) == 1 || sigismember(&sig_p, SIGTERM) == 1) { sig_caught = 1; break; }
                sleep(1);
                ++elapsed;
            }

            if(sig_caught) break;
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
    std::cout << "log_file = /tmp/skimmer.log" << std::endl << std::endl;

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

    std::cout << "# available outputs" << std::endl;
    std::cout << "elasticsearch_address = 127.0.0.1:9200" << std::endl;
    std::cout << "# logstash_address = 127.0.0.1:6110" << std::endl << std::endl;

    std::cout << "# retrieve from api" << std::endl;
    std::cout << "elasticsearch_api = 127.0.0.1:9200" << std::endl;
    std::cout << "# logstash_api = 127.0.0.1:9600" << std::endl << std::endl;

    std::cout << "# comma separated OS statistics selected from the list [zombie,vm,fs,swap,net,cpu]" << std::endl;
    std::cout << "os_stats = zombie,vm,fs,swap,net,cpu" << std::endl << std::endl;

    std::cout << "# comma separated process names to print their pid" << std::endl;
    std::cout << "processes = /usr/sbin/sshd,/usr/sbin/rsyslogd" << std::endl << std::endl;

    std::cout << "# comma separated systemd services to print their status" << std::endl;
    std::cout << "systemd_services = elasticsearch,logstash" << std::endl << std::endl;

    std::cout << "# comma separated port numbers to print if address is in use" << std::endl;
    std::cout << "port_numbers = 9200,9300,9600" << std::endl << std::endl;

    std::cout << "# path to directory containing files needed to be csv validated" << std::endl;
    std::cout << "# csv_path = /tmp/csv_dir" << std::endl << std::endl;

    std::cout << "[PSexec] - run powershell script remotely (skimmer must be installed on Windows)" << std::endl;
    std::cout << "ps_enabled = false" << std::endl;
    std::cout << "# port used to establish connection" << std::endl;
    std::cout << "# ps_port = 10000" << std::endl << std::endl;

    std::cout << "# how often (in seconds) to execute the script" << std::endl;
    std::cout << "# ps_exec_step = 60" << std::endl << std::endl;

    std::cout << "# path to the script which will be sent and executed on remote end" << std::endl;
    std::cout << "# ps_path = /tmp/skimmer.ps1" << std::endl << std::endl;

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
    if((filename = readArgs(argc, argv)) == NULL) return -1;

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

    // logging
    std::string msg = "Skimmer version " + std::string(VERSION) + " started\n";
    writeToLog(INFO, log_file.c_str(), msg.c_str());

    // block SIGINT && SIGTERM
    sigset_t sig;
    sigemptyset(&sig);
    sigaddset(&sig, SIGINT);
    sigaddset(&sig, SIGTERM);
    if(pthread_sigmask(SIG_BLOCK, &sig, NULL) != 0) return -1;

    // init mutex
    pthread_mutex_init(&mutex, NULL);

    // Main module
    pthread_create(&threads[0], NULL, Main, (void *) &cf);

    // PSexec module
    pthread_create(&threads[1], NULL, PSexec, (void *) &cf);

    // wait for threads to finish
    for (int i = 0; i < MODULES; i++)
        pthread_join(threads[i], NULL);

    pthread_mutex_destroy(&mutex);

    return 0;
}
#endif