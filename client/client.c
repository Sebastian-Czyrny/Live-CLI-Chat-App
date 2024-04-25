#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <signal.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <math.h>
#include <time.h>
#include <poll.h>
#define INPUT_BUFFER_SIZE 200
#define ERROR_BUFFER_SIZE 200
#define MAX_ARG_LENGTH 30
#define MAX_ARGS 5
#define MAX_NAME 100
#define MAX_DATA 1000
#define MAX_MSG_SIZE 1200
#define RED             "\x1b[31m"
#define GREEN           "\x1b[32m"
#define YELLOW          "\x1b[33m"
#define BLUE            "\x1b[34m"
#define MAGENTA         "\x1b[35m"
#define CYAN            "\x1b[36m"
#define RESET           "\x1b[0m"
#define RED_BOLD        "\x1b[1;31m"
#define GREEN_BOLD      "\x1b[1;32m"
#define YELLOW_BOLD     "\x1b[1;33m"
#define BLUE_BOLD       "\x1b[1;34m"
#define MAGENTA_BOLD    "\x1b[1;35m"
#define CYAN_BOLD       "\x1b[1;36m"

  
  
// global variable for storing server connection info for continued use
struct client_info {
    int server_sockfd;
    char user_name[MAX_NAME + 1];
    char curr_session[MAX_NAME + 1];
    int in_session;
};

struct client_info client_data;



struct message
{
    unsigned int type;
    unsigned int size;
    unsigned char source[MAX_NAME];
    unsigned char data[MAX_DATA];
};



enum
{
    LOGIN = 0,  // client -- <password>
    LO_ACK,     // server -- <>
    LO_NAK,     // server -- <reason for failure>
    EXIT,       // client -- <>
    JOIN,       // client -- <session id>
    JN_ACK,     // server -- <session id>
    JN_NAK,     // server -- <session id, reason for failure>
    LEAVE_SESS, // client -- <>
    NEW_SESS,   // client -- <session id>
    NS_ACK,     // server -- <>
    NS_NAK,     // server    
    MESSAGE,    // client, server -- <msg data>
    QUERY,
    PRIVATE_MESSAGE,
    P_NAK,
    REGISTER,
    REG_ACK,
    REG_NAK
};


/************************************************
 * The majority of the below code was taken from:
 * Beej's Guide to Network Programming,
 * Using Internet Sockets
 *
 * By "Beej Jorgensen" Hall
 *
 * v3.1.5, Copyright © November 20,2020
 ***********************************************/
int establish_talker(char *server_name, char *port_num)
{
    int sockfd, rv;
    struct addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // set to AF_INET to use IPv4
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(server_name, port_num, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and make a socket
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1)
        {
            perror("talker: socket");
            continue;
        }
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        fprintf(stderr, "client: failed to connect\n");
        return -1;
    }
    freeaddrinfo(servinfo);
    return sockfd;
}

// initialize server sock fd to a value it can never be
void init_client_data() {
    client_data.server_sockfd = -1;
    client_data.in_session = 0;
}


// turns the struct message into a string to be sent
int compile_message(char buffer[],struct message* msg) {
    sprintf(buffer, "%d;%d;%s;%s",msg->type, msg->size, msg->source, msg->data);
    return 0;
}

// turns rcv into message object.
// size is the size, in bytes, of data that was received
int parse_message(char rcv[],int size, struct message* msg) {

    int arg_num = 1;
    int start_colon = 0;
    int arg_size;
    for (int i = 0; i < size; i++) {
        if (rcv[i] != ';') {
            continue;
        }
        arg_size = i - start_colon;
        char next_arg[arg_size + 1];
        strncpy(next_arg, rcv+start_colon, arg_size);
        next_arg[arg_size] = '\0';

        start_colon = i + 1;

        if (arg_num == 1) {
            msg->type = atoi(next_arg);
            arg_num = 2;
        }
        else if (arg_num == 2) {
            msg->size = atoi(next_arg);
            arg_num = 3;
        }
        else if (arg_num == 3) {
            strcpy((char*)msg->source, next_arg); 
            // rest of message is assumed to be data
            strncpy((char*)msg->data, rcv+start_colon, msg->size);
            msg->data[msg->size] = '\0';
            return 0;
        }
        
    }
    return 0;
}

int login(char *client_name, char *password, char *server_ip, char *server_port)
{
    if (client_data.server_sockfd > 0) {
        printf(RED_BOLD "Error:" RED" Already logged in\n" RESET);
        return 1; //already logged in
    }
    client_data.server_sockfd = establish_talker(server_ip, server_port);

    char buf[MAX_MSG_SIZE+1];
    int num_bytes;

    // send login message
    struct message msg;
    msg.type = LOGIN;
    msg.size = strlen(password);
    strcpy((char*)msg.source, client_name);
    strcpy((char*)msg.data, password);
    compile_message(buf, &msg);

    strcpy(client_data.user_name, client_name);
  
    if (send(client_data.server_sockfd, buf, strlen(buf), 0) == -1)
    {
        perror("send");
        client_data.server_sockfd = -1;
       
        return 1;
    }

    struct message rcv_msg;
    char rcv_buf[MAX_MSG_SIZE+1];
    if ((num_bytes = recv(client_data.server_sockfd, rcv_buf, MAX_MSG_SIZE, 0)) == -1)
    {
        perror("recv");
        exit(1);
    }
    rcv_buf[num_bytes] = '\0';
   
    parse_message(rcv_buf, num_bytes, &rcv_msg);
    if (rcv_msg.type == LO_ACK) {
        printf(BLUE_BOLD "Login to " GREEN_BOLD "%s:%s" BLUE_BOLD" successful\n" RESET, server_ip,server_port);
        return 0;
    }
    else if (rcv_msg.type == LO_NAK)
    {
        printf(RED_BOLD "Login to " GREEN_BOLD"%s:%s" RED_BOLD" failed:\n" RESET, server_ip, server_port);
        printf(YELLOW"%s\n" RESET, rcv_msg.data);
        if (close(client_data.server_sockfd) == -1)
        {
            perror("close");
        }
        client_data.server_sockfd = -1;
        return 1;
    }
    else {
        printf(RED_BOLD "Login to " GREEN_BOLD"%s:%s" RED_BOLD" failed:\n" RESET, server_ip, server_port);
        printf(YELLOW "Received invalid message type\n" RESET);
        if (close(client_data.server_sockfd) == -1)
        {
            perror("close");
        }
        client_data.server_sockfd = -1;
        return 1;
    }
    return 0;
}

int logout()
{
    if (client_data.server_sockfd < 0)
    {
        printf(RED_BOLD "Error:" RED" Not connected to server.\n" RESET);
        return 1;
    }
    char buf[MAX_MSG_SIZE+1];
    struct message msg;
    msg.type = EXIT;
    msg.size = 0;
    strcpy((char *)msg.source, client_data.user_name);
    msg.data[msg.size] = '\0';
    compile_message(buf, &msg);

    if (send(client_data.server_sockfd, buf, strlen(buf), 0) == -1)
    {
        perror("send");
        return 1;
    }
    printf(YELLOW_BOLD "Logged out.\n" RESET);
    client_data.server_sockfd = -1;
    client_data.in_session = 0;
    close(client_data.server_sockfd);
    return 0;
}

int joinSession(char *session_id)
{
    if (client_data.server_sockfd < 0)
    {
        printf(RED_BOLD "Error:" RED" Not connected to server.\n" RESET);
        return 1;
    }
    if (client_data.in_session == 1) {
        printf(RED_BOLD "Error:" RED" Currently in session " GREEN_BOLD"'%s'\n" RESET, client_data.curr_session);
        return 1;
    }

    // compile and send message to server
    char buf[MAX_MSG_SIZE+1];
    struct message msg;
    msg.type = JOIN;
    msg.size = strlen(session_id);
    strcpy((char *)msg.source, client_data.user_name);
    strcpy((char *)msg.data, session_id);

    compile_message(buf, &msg);

    if (send(client_data.server_sockfd, buf, strlen(buf), 0) == -1)
    {
        perror("send");
        return 1;
    }
    int num_bytes;
    char rcv_buf[MAX_MSG_SIZE+1];

    // receive message from server, check for errors
    num_bytes = recv(client_data.server_sockfd, rcv_buf, MAX_MSG_SIZE, 0);
    if (num_bytes == 0) {
        printf(RED_BOLD "Error:" RED" Connection to server is closed.\n" RESET);
        return 1;
    }
    else if (num_bytes == -1) {
        perror("recv");
        return 1;
    }
    
    // parse message from server, check response
    struct message rcv_msg;
    parse_message(rcv_buf, num_bytes, &rcv_msg);

    if (rcv_msg.type == JN_NAK) {
        printf(RED_BOLD"Error " RED"joining session " GREEN_BOLD"'%s'" RED", Reason:"YELLOW "%s\n" RESET, session_id, rcv_msg.data);

        return 1;
    }

    strcpy(client_data.curr_session, session_id);
    client_data.in_session = 1;
    printf(BLUE_BOLD "Joined session " GREEN_BOLD "'%s'\n" RESET, rcv_msg.data);

    return 0;
}

int leaveSession()
{
    if (client_data.server_sockfd < 0)
    {
        printf(RED_BOLD "Error:" RED" Not connected to server.\n" RESET);
        return 1;
    }
    if (client_data.in_session == 0) {
        printf(YELLOW"Not in any session.\n"RESET);
        return 1;
    }

    // compile and send message to server
    char buf[MAX_MSG_SIZE + 1];
    struct message msg;
    msg.type = LEAVE_SESS;
    msg.size = 0;
    strcpy((char *)msg.source, client_data.user_name);
    msg.data[msg.size] = '\0';

    compile_message(buf, &msg);

    if (send(client_data.server_sockfd, buf, strlen(buf), 0) == -1)
    {
        perror("send");
        return 1;
    }

    printf(BLUE"Left session " GREEN_BOLD"'%s'\n" RESET,client_data.curr_session);
    client_data.in_session = 0;
    return 0;
}
// Create a new conference session and join it
int createSession(char *session_id)
{
    if (client_data.server_sockfd < 0)
    {
        printf(RED_BOLD "Error:" RED" Not connected to server.\n" RESET);
        return 1;
    }
    if (client_data.in_session == 1)
    {
        printf(RED_BOLD "Error:" RED" Currently in session " GREEN_BOLD"'%s'\n" RESET, client_data.curr_session);
        return 1;
    }

    // compile and send message to server
    char buf[MAX_MSG_SIZE + 1];
    struct message msg;
    msg.type = NEW_SESS;
    msg.size = strlen(session_id);
    strcpy((char *)msg.source, client_data.user_name);
    strcpy((char *)msg.data, session_id);

    compile_message(buf, &msg);

    if (send(client_data.server_sockfd, buf, strlen(buf), 0) == -1)
    {
        perror("send");
        return 1;
    }
    int num_bytes;
    char rcv_buf[MAX_MSG_SIZE + 1];

    // receive message from server, check for errors
    num_bytes = recv(client_data.server_sockfd, rcv_buf, MAX_MSG_SIZE, 0);
    if (num_bytes == 0)
    {
        printf(RED_BOLD "Error:" RED" Connection to server is closed.\n" RESET);
        return 1;
    }
    else if (num_bytes == -1)
    {
        perror("recv");
        return 1;
    }

    // parse message from server, check response
    struct message rcv_msg;
    parse_message(rcv_buf, num_bytes, &rcv_msg);

    if (rcv_msg.type == NS_NAK)
    {
        printf(RED_BOLD"Error " RED"creating session " GREEN_BOLD"'%s'" RED", Reason:"YELLOW "%s\n" RESET, session_id, rcv_msg.data);
        return 1;
    }

    strcpy(client_data.curr_session, session_id);
    client_data.in_session = 1;
    printf(BLUE_BOLD "Created session " GREEN_BOLD"'%s'\n" RESET, session_id);

    return 0;
}


// Get the list of the connected clients and available sessions
int list()
{
    if (client_data.server_sockfd < 0)
    {
        printf(RED_BOLD "Error:" RED" Not connected to server.\n" RESET);
        return 1;
    }

    // compile and send message to server
    char buf[MAX_MSG_SIZE + 1];
    struct message msg;
    msg.type = QUERY;
    msg.size = 0;
    strcpy((char *)msg.source, client_data.user_name);
    msg.data[msg.size] = '\0';
    compile_message(buf, &msg);

    if (send(client_data.server_sockfd, buf, strlen(buf), 0) == -1)
    {
        perror("send");
        return 1;
    }
    int num_bytes;
    char rcv_buf[MAX_MSG_SIZE + 1];

    // receive message from server, check for errors
    num_bytes = recv(client_data.server_sockfd, rcv_buf, MAX_MSG_SIZE, 0);
    if (num_bytes == 0)
    {
        printf(RED_BOLD "Error:" RED" Connection to server is closed.\n" RESET);

        return 1;
    }
    else if (num_bytes == -1)
    {
        perror("recv");
        return 1;
    }

    // parse message from server, check response
    struct message rcv_msg;
    parse_message(rcv_buf, num_bytes, &rcv_msg);

    if (rcv_msg.type == QUERY)
    {
        printf(BLUE "%s" RESET, rcv_msg.data);
        return 0;
    }

    return 0;
}

// terminates the program
int quit() {
    if (client_data.server_sockfd < 0)
    {
        exit(0);
    }
    char buf[MAX_MSG_SIZE + 1];
    struct message msg;
    msg.type = EXIT;
    msg.size = 0;
    strcpy((char *)msg.source, client_data.user_name);
    msg.data[msg.size] = '\0';
    compile_message(buf, &msg);

    if (send(client_data.server_sockfd, buf, strlen(buf), 0) == -1)
    {
        perror("send");
        exit(0);
    }
    client_data.server_sockfd = -1;
    client_data.in_session = 0;
    close(client_data.server_sockfd); // not necessary, server already closed it
 
    exit(0);
}

// send message to the user
int send_msg(char msg[], int msg_length) {
    if (client_data.server_sockfd < 0)
    {
        printf(RED_BOLD "Error:" RED" Not connected to server.\n" RESET);
        return 1;
    }
    if (client_data.in_session == 0)
    {
        printf(RED_BOLD "Error:" RED " Not in a session '%s'\n" RESET, client_data.curr_session);
        return 1;
    }

    // compile and send message to server
    char buf[MAX_MSG_SIZE + 1];
    struct message send_msg;
    send_msg.type = MESSAGE;
    send_msg.size = msg_length;
    strcpy((char *)send_msg.source, client_data.user_name);
    strcpy((char *)send_msg.data, msg);

    compile_message(buf, &send_msg);

    if (send(client_data.server_sockfd, buf, strlen(buf), 0) == -1)
    {
        perror("send");
        return 1;
    }
    return 0;
}

// send message to the user
int send_private_msg(char msg[], int msg_length, char* recipient) {
    if (client_data.server_sockfd < 0)
    {
        printf(RED_BOLD "Error:" RED" Not connected to server.\n" RESET);
        return 1;
    }
    if (strcmp(client_data.user_name, recipient) == 0) {
        printf(RED_BOLD "Error:" RED" Cannot send message to self.\n" RESET);
        return 1;

    }

    // compile and send message to server
    char buf[MAX_MSG_SIZE + 1];
    struct message send_msg;
    send_msg.type = PRIVATE_MESSAGE;
    strcpy((char *)send_msg.source, client_data.user_name);
    strcpy((char*)send_msg.data, recipient);
    strcat((char*)send_msg.data, ";");
    strcat((char *)send_msg.data, msg);
    send_msg.size = strlen(send_msg.data);
    compile_message(buf, &send_msg);
    if (send(client_data.server_sockfd, buf, strlen(buf), 0) == -1)
    {
        perror("send");
        return 1;
    }
    return 0;
}


int register_user(char *client_name, char *password, char *server_ip, char *server_port)
{
    if (client_data.server_sockfd > 0) {
        printf(RED_BOLD "Error:" RED" Already logged in\n" RESET);
        return 1; //already logged in
    }
    client_data.server_sockfd = establish_talker(server_ip, server_port);

    char buf[MAX_MSG_SIZE+1];
    int num_bytes;

    // send login message
    struct message msg;
    msg.type = REGISTER;
    msg.size = strlen(password);
    strcpy((char*)msg.source, client_name);
    strcpy((char*)msg.data, password);
    compile_message(buf, &msg);

    strcpy(client_data.user_name, client_name);
  
    if (send(client_data.server_sockfd, buf, strlen(buf), 0) == -1)
    {
        perror("send");
        client_data.server_sockfd = -1;
       
        return 1;
    }

    struct message rcv_msg;
    char rcv_buf[MAX_MSG_SIZE+1];
    if ((num_bytes = recv(client_data.server_sockfd, rcv_buf, MAX_MSG_SIZE, 0)) == -1)
    {
        perror("recv");
        exit(1);
    }
    rcv_buf[num_bytes] = '\0';
   
    parse_message(rcv_buf, num_bytes, &rcv_msg);
    if (rcv_msg.type == REG_ACK) {
        printf(BLUE_BOLD "Registration to " GREEN_BOLD "%s:%s" BLUE_BOLD" successful\n" RESET, server_ip,server_port);
        return 0;
    }
    else if (rcv_msg.type == REG_NAK)
    {
        printf(RED_BOLD "Registration to " GREEN_BOLD"%s:%s" RED_BOLD" failed:\n" RESET, server_ip, server_port);
        printf(YELLOW"%s\n" RESET, rcv_msg.data);
        if (close(client_data.server_sockfd) == -1)
        {
            perror("close");
        }
        client_data.server_sockfd = -1;
        return 1;
    }
    else {
        printf(RED_BOLD "Registration to " GREEN_BOLD"%s:%s" RED_BOLD" failed:\n" RESET, server_ip, server_port);
        printf(YELLOW "Received invalid message type\n" RESET);
        if (close(client_data.server_sockfd) == -1)
        {
            perror("close");
        }
        client_data.server_sockfd = -1;
        return 1;
    }
    return 0;
}



// passive function, gets called on its own 
// in a thread
void rcv_msg() {

    if (client_data.server_sockfd < 0) {
        return; // do nothing
    }
    int num_bytes = -1;
    char rcv_buf[MAX_MSG_SIZE+1];

     struct pollfd pfds;
    pfds.fd = client_data.server_sockfd;
    pfds.events = POLLIN;
    poll(&pfds, 1, 0); // poll for input
    if (pfds.revents & POLLIN) {// process input if there is any 
        num_bytes = recv(client_data.server_sockfd, rcv_buf, MAX_MSG_SIZE, MSG_DONTWAIT);
    }
    else  return;

    if (num_bytes == -1) {
        return;// shouldn't happen, but just in case
    }
    if (num_bytes == 0) { // connection was closed 
        close(client_data.server_sockfd); // no need to check for errors, it might have failed here
        printf("\b\b\b" RED_BOLD "Logged out - Server closed connection\n" RESET">> ");
        fflush(stdout);
        client_data.server_sockfd = -1;
        return;
    }
    rcv_buf[num_bytes] = '\0';
    // printf("received: %s\n", rcv_buf);
    struct message rcv_msg;
    parse_message(rcv_buf, num_bytes, &rcv_msg);
    if (rcv_msg.type == PRIVATE_MESSAGE) {
        printf("\b\b\b" RED_BOLD "(pm) " YELLOW_BOLD  "%s: " RESET  "%s>> ",rcv_msg.source,rcv_msg.data);

    }
    else if (rcv_msg.type == P_NAK) {
        printf("\b\b\b" RED_BOLD "Error:" RED" %s\n" RESET">> ",rcv_msg.data);
    }
    else {
        printf("\b\b\b" YELLOW_BOLD  "%s: " RESET  "%s>> ",rcv_msg.source,rcv_msg.data);
    }
    fflush(stdout);

    return;
}




// parses command given by user into individual arguments.
// Error occurs if: user inputs more than maximum possible arguments (5), or
// if user inputs an argument larger than MAX_ARG_LENGTH
int parse_command(char buffer[INPUT_BUFFER_SIZE], char user_args[MAX_ARGS][MAX_ARG_LENGTH], char msg[]) {
    int curr_idx = 0;
    int curr_arg = 0;
    int first_quote = 0;
    int start_quote = 0;
    char open_quote;
    for (int i = 0; i < strlen(buffer); i++, curr_idx++)
    {
        if (buffer[i] == '"' || buffer[i] == '\'') { // start/end processing quote
           if (first_quote == 0) {
            first_quote = 1;
            open_quote = buffer[i]; // make sure closing quote matches opening quote
            }
           else if (buffer[i] == open_quote){ // end the message
            first_quote = 0;
            msg[start_quote] = '\n';
            msg[start_quote+1] = '\0'; 
            curr_idx = -1;
            continue;
           }
           else if (buffer[i] != open_quote) {
                 msg[start_quote] = buffer[i];
              start_quote++;
           }
        }
        else if (first_quote == 1) {
              msg[start_quote] = buffer[i];
              start_quote++;

        }
        else if (isspace(buffer[i])) // quoted text can contain spaces
        {
            user_args[curr_arg][curr_idx] = '\0';
            if (buffer[i] == '\n') return curr_arg + 1;
            curr_idx = -1;
            curr_arg++;
            continue;

        }
        if (curr_idx >= MAX_ARG_LENGTH && first_quote == 0)
            return -2;
        if (curr_arg >= MAX_ARGS) return -1;
        user_args[curr_arg][curr_idx] = buffer[i];
    }
    return curr_arg;
}


// handle user specific commands
void handle_command(char input_buf[INPUT_BUFFER_SIZE]) {
    char user_args[MAX_ARGS][MAX_ARG_LENGTH];
    char msg[MAX_MSG_SIZE];
    msg[0] = '\0';
    int num_args = parse_command(input_buf, user_args, msg);
    if (num_args == -1 || num_args == -2)
    {
        printf(RED_BOLD"Error:"RED" Invalid arguments.\n" RESET);

        return;
    }

    if (strcmp("/login", user_args[0]) == 0 && num_args == 5) {
        login(user_args[1], user_args[2], user_args[3], user_args[4]);
    }
    else if (strcmp("/register", user_args[0]) == 0 && num_args == 5)
    {
        register_user(user_args[1], user_args[2], user_args[3], user_args[4]);
    }
    else if (strcmp("/logout", user_args[0]) == 0 && num_args == 1)
    {
        logout();
    }
    else if (strcmp("/joinsession", user_args[0]) == 0 && num_args == 2)
    {
        joinSession(user_args[1]);
    }
    else if (strcmp("/leavesession", user_args[0]) == 0 && num_args == 1)
    {
        leaveSession();
    }
    else if (strcmp("/createsession", user_args[0]) == 0 && num_args == 2)
    {
        createSession(user_args[1]);
    }
    else if (strcmp("/list", user_args[0]) == 0 && num_args == 1)
    {
        list();
    }
    else if (strcmp("/dm", user_args[0]) == 0 && num_args == 3 && strlen(msg) != 0)
    {
        send_private_msg(msg, strlen(msg),user_args[1]);
    }
    else if (strcmp("/quit", user_args[0]) == 0 && num_args == 1)
    {
        quit();
    }
    else {
        printf(RED_BOLD"Error:"RED" Invalid arguments.\n" RESET);
    }
    
}


// thread function for handling user commands
void handle_input(char input_buf[])
{
    // handle the command
    if (input_buf[0] == '/')
    {
        handle_command(input_buf);
    }
    else
    {
        send_msg(input_buf, strlen(input_buf));
    }
    printf(">> ");
    fflush(stdout);
}



int main() {
    init_client_data();

    struct pollfd pfds;
    pfds.fd = STDIN_FILENO;
    pfds.events = POLLIN;
    char input_buf[MAX_MSG_SIZE+1];
    printf(">> ");
    fflush(stdout);
    while (1)
    {
        poll(&pfds, 1, 0); // poll for input
        if (pfds.revents & POLLIN) // process input if there is any
        {
            fgets(input_buf, MAX_MSG_SIZE, stdin);
            handle_input(input_buf);
        }

        rcv_msg(); // receive message if any
    }
    return 0;
 
}