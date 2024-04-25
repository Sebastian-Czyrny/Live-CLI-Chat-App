#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <math.h>
#include <time.h>
#define _GNU_SOURCE
#define BACKLOG 100
#define MAX_NAME 100
#define MAX_DATA 1000
#define MAX_MSG_SIZE 1200
#define IP_LENGTH 17


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

enum
{
    SUCCESS = 0,
    SYS_ERROR,          // anywhere
    SESSION_EXISTS,     // create session
    ALREADY_IN_SESSION, // create session, join session
    INVALID_SESSION_ID, // join session
    INVALID_PASSWORD,   // login
    TOO_LONG,           // login
    USER_NOT_FOUND,     // login
    USER_ONLINE,        // login
    NOT_IN_SESSION,     // leave session, send message
    SERVER_ERROR,        // server messed up
    USER_EXISTS,
    BAD_PASSWORD
};

struct session_info;
struct session_node;
struct session_list;
struct connection_info;
struct connection_node;
struct connection_list;

struct sockfd_node {
    int sockfd;
    struct sockfd_node* next;
};

// holds info about the particular session,
struct session_info {
    int sid; // easier way to identify sessions (and faster)
    char session_id[MAX_DATA];
    struct sockfd_node* session_users; // users are stored by their sockfds
};
// holds a list of all sessions that exist.
// use a pointer to a session_info struct
struct session_node
{ // previous session_list
    struct session_info session;
    struct session_node *next;
};

struct session_list
{
    struct session_node *head;
    int num_sessions;
    int next_sid;
};

struct connection_info
{ // previously con_info
    int sockfd;
    char user_id[MAX_NAME];
    char ip[IP_LENGTH];
    int port_num;
    int sid;
};


struct connection_node // previously ll_node
{
    struct connection_info connection;
    struct connection_node *next;
};

struct connection_list // previously linkedlist
{
    int num_connections;
    struct connection_node *head;
};

// global variable holding all the user connection info and the session they belong to (only one session)
struct connection_list user_connections;

// holds a list of sessions that currently exist, links with the session info objects under each user in user_connections
struct session_list sessions;

// SUCCESS = 0,
// SYS_ERROR,          // anywhere
// SESSION_EXISTS,     // create session
// ALREADY_IN_SESSION, // create session, join session
// INVALID_SESSION_ID, // join session
// INVALID_PASSWORD,   // login
// TOO_LONG,           // login
// USER_NOT_FOUND,     // login
// USER_ONLINE,        // login
// NOT_IN_SESSION,     // leave session, send message
// SERVER_ERROR        // server messed up
void error_check(int status_code, char error_buffer[]) {
    switch (status_code) {
    case SYS_ERROR:
        strcpy(error_buffer, "Oops. Something went wrong, please try again.");
        break;
    case SESSION_EXISTS:
        strcpy(error_buffer, "Session by that name already exists.");
        break;
    case ALREADY_IN_SESSION:
        strcpy(error_buffer, "Cannot join/create a session while already in a session.");
        break;
    case INVALID_SESSION_ID:
        strcpy(error_buffer, "A session does not exist by that name.");
        break;
    case INVALID_PASSWORD:
        strcpy(error_buffer, "Invalid password.");
        break;
    case TOO_LONG:
        strcpy(error_buffer, "Username/password too long.");
        break;
    case USER_NOT_FOUND:
        strcpy(error_buffer, "User not found.");
        break;
    case USER_ONLINE:
        strcpy(error_buffer, "A user by that name is already online.");
        break;
    case NOT_IN_SESSION:
        strcpy(error_buffer, "Not currently in a session.");
        break;
    case SERVER_ERROR:
        strcpy(error_buffer, "Oops. Something went wrong, please try again.");
        break;
    case USER_EXISTS:
        strcpy(error_buffer, "A user already exists by that name.");
        break;
    case BAD_PASSWORD:
        strcpy(error_buffer, "Password failed to meet requirements:\n");
        strcat(error_buffer, "-\tminimum 10 characters\n");
        strcat(error_buffer, "-\tat least 1 capital\n");
        strcat(error_buffer, "-\tat least 1 lowercase\n");
        strcat(error_buffer, "-\tat least 1 digit\n");
        strcat(error_buffer, "-\tat least 1 non-alphanumeric character");
    }

}

// ================================================================
// =================== Helper Functions [START] ===================
// ================================================================
// the below functions are purely for session and user management, 
// no network calls are being make with them, but they can close 
// sockets

void print_sockfd_list(struct sockfd_node* node) {
    if (node == NULL) return;
    printf("sockfds: \t[ ");
    struct sockfd_node *temp = node;
    while (temp->next != NULL)
    {
        printf("%d, ", temp->sockfd);
        temp = temp->next;
    }
    printf("%d ]\n", temp->sockfd);
}

void print_session_info(struct session_info* session) {
    printf("sid: \t\t%d\n", session->sid);
    printf("session_id: \t%s\n", session->session_id);
    print_sockfd_list(session->session_users);
}

void print_session_node(struct session_node* node) {
    printf("== Printing Sessions ==\n\n");
    struct session_node *temp = node;
    while (temp != NULL)
    {
        print_session_info(&temp->session);
        printf("\n");
        temp = temp->next;
    }

    printf("== DONE Printing Sessions ==\n");
} 

void print_sessions() {
    printf("=== Printing Session List ===\n");

    printf("\nnum_sessions: %d\n", sessions.num_sessions);
    printf("\nnext_sid: %d\n", sessions.next_sid);

    print_session_node(sessions.head);

    printf("\n=== DONE Printing Session List ===\n");
}


void print_connection_info(struct connection_info* connection) {
    printf("sockfd: \t%d\n", connection->sockfd);
    printf("sid: \t\t%d\n", connection->sid);
    printf("user_id: \t%s\n", connection->user_id);
}

void print_connection_node(struct connection_node* node) {
    printf("== Printing users ==\n\n");
    struct connection_node* temp = node;
    while (temp!=NULL) {
        print_connection_info(&temp->connection);
        printf("\n");
        temp = temp->next;
    }

    printf("== DONE Printing users ==\n");
}

void print_user_connections() {
    printf("=== Printing User Connections ===\n");

    printf("\nnum_connections: %d\n", user_connections.num_connections);

    print_connection_node(user_connections.head);

    printf("\n=== DONE Printing User Connections ===\n");
}

// taken from Beej's guide to network programming
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}
uint16_t get_in_port(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return ((struct sockaddr_in *)sa)->sin_port;
    }
    return ((struct sockaddr_in6 *)sa)->sin6_port;
}

// initialize user_connections and sessions global variables
void init_connections() {
    user_connections.head = NULL;
    user_connections.num_connections = 0;

    sessions.head = NULL;
    sessions.num_sessions = 0;
    sessions.next_sid = 0;
}

// does exactly what it says, inserts the values as a new node into list containing head
struct connection_node *insert_cn(struct connection_node *head, char *user_id, int sockfd)
{
    // create the new node
    struct connection_node *new_n = (struct connection_node *)malloc(sizeof(struct connection_node));

    // initialize its data
    new_n->connection.sockfd = sockfd;
    strcpy(new_n->connection.user_id, user_id);
    new_n->connection.sid = -1;
    new_n->next = NULL;

    // get ip and portnum from sockfd
    struct sockaddr_storage their_addr;
    socklen_t addr_size = sizeof(their_addr);
    int res = getpeername(sockfd, (struct sockaddr *)&their_addr, &addr_size);
    
    inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), new_n->connection.ip, IP_LENGTH);
    new_n->connection.port_num = htons(get_in_port((struct sockaddr *)&their_addr));
    printf("server: got connection from %s:%d\n", new_n->connection.ip, new_n->connection.port_num);

    // add it to user connections obj
    if (head == NULL)
        head = new_n;
    else
    {
        struct connection_node *temp = head;
        while (temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = new_n;
    }
    return head;
}

// inserts new sockfd_node into list pointed to by head
struct sockfd_node *insert_sfn(struct sockfd_node *head, int sockfd)
{
    struct sockfd_node *new_n = (struct sockfd_node *)malloc(sizeof(struct sockfd_node));
    new_n->sockfd = sockfd;
    new_n->next = NULL;
    if (head == NULL)
        head = new_n;
    else
    {
        struct sockfd_node *temp = head;
        while (temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = new_n;
    }
    return head;
}

struct sockfd_node *remove_sfn(struct sockfd_node *head, int sockfd) {
    if (head == NULL) return head;
    struct sockfd_node* temp = head;
    if (head->sockfd == sockfd) {
        head = head->next;
        free(temp);
        return head;
    }
    while (temp->next != NULL && temp->next->sockfd != sockfd) {
        temp = temp->next;
    }

    struct sockfd_node* temp2 = temp->next;
    temp->next = temp->next->next;
    free(temp2);
    return head;
}

// inserts new session node into list pointed to by head
struct session_node* insert_sn(struct session_node* head, int sid, char* session_id) {
    struct session_node* new_n = (struct session_node*) malloc(sizeof(struct session_node));
    new_n->session.sid = sid;
    strcpy(new_n->session.session_id, session_id);
    new_n->session.session_users = NULL;
    new_n->next = NULL;

    // insert into head
    if (head == NULL)
        head = new_n;
    else
    {
        struct session_node *temp = head;
        while (temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = new_n;
    }
    return head;
}

// Add a connection to global user_connections variable.
// Returns 0 on success, 1 on incorrect password, 2 when user
// already online, 3 on username/password too long, 4 when user not found
int add_connection(const char *input_id, const char* input_password, int sockfd)
{
    if (strlen(input_id) > MAX_NAME || strlen(input_password) > MAX_NAME) return TOO_LONG;

    // check the client list db
    int filefd = open("clientList.csv", O_RDWR);
    if (filefd == -1) {
        perror("open");
        return SYS_ERROR;
    }

    const int file_buffer_size = 4096;
    char buffer[file_buffer_size];

    // read from database file, store information in id, name.
    int num_bytes;
    int found = 0;
    int incorrect_pswd = 0;
    char user_id[MAX_NAME+1];
    while ((num_bytes = read(filefd, buffer, file_buffer_size)) > 0)
    {
        int start_comma = 0;

        int arg_type = 0; // 0 -> user_id, 2 -> password
        for (int i = 0; i < num_bytes; i++) {

            if (buffer[i] == '\0') {

                break;
            }
            if (buffer[i] == ',' || buffer[i] == '\n') {
                char next_arg[MAX_NAME+1];
                int arg_size = i - start_comma;
            
                strncpy(next_arg, buffer + start_comma, arg_size);
                next_arg[arg_size] = '\0';
                start_comma =  i + 1;
                if (arg_type == 0) {
                    strcpy(user_id, next_arg);
                    arg_type = 1;
                }
                else if (arg_type == 1) {
                    if (strcmp(input_id,user_id) == 0 ) {
                        // get out of here
                        if (strcmp(input_password, next_arg) == 0) {
                            found = 1;
                        } else {
                            incorrect_pswd = 1;
                        }
                        break;
                    }
                    arg_type = 0;
                }
               

            }
        }
        if (found || incorrect_pswd)
            break;
    }

    // if found but incorrect password, get out of here
    if (incorrect_pswd)
    {
        if (close(filefd) == -1)
        {
            perror("close");
            return SYS_ERROR;
        }
        return INVALID_PASSWORD;
    }

    // check to make sure existing user isn't already logged in
    if (found) {
        struct connection_node* temp = user_connections.head;
        while (temp != NULL && strcmp(temp->connection.user_id,user_id) != 0) {
            temp = temp->next;
        }
        if (temp != NULL)  { // should be NULL
            if (close(filefd) == -1)
            {
                perror("close");
            }
            return USER_ONLINE; // user found but already is online
        }
    }

    /* IMPLEMENT USER REGISTRATION FEATURE HERE!!! */
    // not found, write it to the file 
    if (!found)
    {
       /*  char write_buffer[MAX_NAME * 3];
        sprintf(write_buffer, "%d,%s,%s\n",id+1, input_name, input_password);
        if (write(filefd, write_buffer, strlen(write_buffer)) <= 0) {
            perror("write");
        }
        strcpy(name, input_name);
        id = id+1; */
        if (close(filefd) == -1)
        {
            perror("close");
            return SYS_ERROR;
        }
        return USER_NOT_FOUND; // user not found
    }


    // add the open connection,
    user_connections.head = insert_cn(user_connections.head, user_id, sockfd);
    user_connections.num_connections++;

    if (close(filefd) == -1) {
        perror("close");
        return SYS_ERROR;
    } 
    return SUCCESS;
}


// register a connection and add it to global user_connections variable.
// Returns 0 on success, 1 on incorrect password, 2 when user
// already online, 3 on username/password too long, 4 when user not found
int register_connection(const char *input_id, const char* input_password, int sockfd)
{
    if (strlen(input_id) > MAX_NAME || strlen(input_password) > MAX_NAME) return TOO_LONG;

    // check the client list db
    int filefd = open("clientList.csv", O_RDWR);
    if (filefd == -1) {
        perror("open");
        return SYS_ERROR;
    }

    const int file_buffer_size = 4096;
    char buffer[file_buffer_size];

    // read from database file, store information in id, name.
    int num_bytes;
    int found = 0;
    int incorrect_pswd = 0;
    char user_id[MAX_NAME+1];
    while ((num_bytes = read(filefd, buffer, file_buffer_size)) > 0)
    {
        int start_comma = 0;

        int arg_type = 0; // 0 -> user_id, 2 -> password
        for (int i = 0; i < num_bytes; i++) {

            if (buffer[i] == '\0') {

                break;
            }
            if (buffer[i] == ',' || buffer[i] == '\n') {
                char next_arg[MAX_NAME+1];
                int arg_size = i - start_comma;
            
                strncpy(next_arg, buffer + start_comma, arg_size);
                next_arg[arg_size] = '\0';
                start_comma =  i + 1;
                if (arg_type == 0) {
                    strcpy(user_id, next_arg);
                    arg_type = 1;
                }
                else if (arg_type == 1) {
                    if (strcmp(input_id,user_id) == 0 ) {
                        // get out of here
                        found = 1;
                        break;
                    }
                    arg_type = 0;
                }
               

            }
        }
        if (found)
            break;
    }

    // if found get out of here, user cannot possiblt register
    if (found)
    {
        if (close(filefd) == -1)
        {
            perror("close");
            return SYS_ERROR;
        }
        return USER_EXISTS;
    }

    // got to here, means that username is atleast valid, now check the password requirements
    int min_pass_length = 10;
    if (strlen(input_password) < min_pass_length) {
        if (close(filefd) == -1)
        {
            perror("close");
        }
        return BAD_PASSWORD;
    }
    int found_capital = 0;
    int found_lower = 0;
    int found_nonalpha = 0;
    int found_digit = 0;
    for (int i = 0; i < strlen(input_password); i++) {
        if (input_password[i] >= 'A' && input_password[i] <= 'Z') found_capital = 1;
        if (input_password[i] >= 'a' && input_password[i] <= 'z') found_lower = 1;
        if (input_password[i] >= '0' && input_password[i] <= '9') found_digit = 1;
        else found_nonalpha = 1;
    }

    if (!(found_capital && found_lower && found_digit && found_nonalpha)) {
        if (close(filefd) == -1)
        {
            perror("close");
        }
        return BAD_PASSWORD;
    }

    // done checking password, its okay, add it file
    char write_buffer[MAX_NAME * 3];
    sprintf(write_buffer, "%s,%s\n",input_id, input_password);
    if (write(filefd, write_buffer, strlen(write_buffer)) <= 0) {
        perror("write");
    }
    strcpy(user_id, input_id);
    if (close(filefd) == -1)
    {
        perror("close");
    }

    // add the open connection
    user_connections.head = insert_cn(user_connections.head, user_id, sockfd);
    user_connections.num_connections++;

   
    return SUCCESS;
}


// remove session from list of sessions
void remove_session(int sid) {
    struct session_node* temp = sessions.head;
    if (temp == NULL) { // list is empty
        return;
    }

    if (temp->session.sid == sid) { // at front of list
        sessions.head = sessions.head->next;
        free(temp);
        sessions.num_sessions--;
        return;
    }

    // search through list of session
    while (temp->next != NULL && temp->next->session.sid != sid) {
        temp = temp->next;
    }

    if (temp == NULL) return; // not found in list

    // remove session
    struct session_node* temp2 = temp->next;
    temp->next = temp->next->next;
    free(temp2);
    sessions.num_sessions--;
}

char* get_user_id(int sockfd) {
    struct connection_node* temp = user_connections.head;
    while (temp != NULL && temp->connection.sockfd != sockfd) {
        temp = temp->next;
    }
    if (temp == NULL) return "";
    return temp->connection.user_id;
}

// return the sid associated with session_id. 
// if session_id does not exist, return -1
int sessionid_to_sid(char *session_id) {
    
    
    // search sessions

    struct session_node* temp = sessions.head;
    while (temp!= NULL && strcmp(temp->session.session_id, session_id) != 0) {
        temp = temp->next;
    }

    if (temp == NULL) return -1; // invalid sid 
        
    
    return temp->session.sid;
}

// same as above but other way around. Just used for printing.
char* sid_to_sessionid(int sid)
{
    // search sessions
    struct session_node *temp = sessions.head;
    while (temp != NULL && temp->session.sid != sid)
    {
        temp = temp->next;
    }

    if (temp == NULL)
        return ""; 

    return temp->session.session_id;
}

// internal method to update sid user belongs to.
int update_user_sid(int sockfd, int new_sid) {
    struct connection_node* temp = user_connections.head;
    while (temp != NULL && temp->connection.sockfd != sockfd) {
        temp = temp->next;

    }
    if (temp == NULL) return 1; //user not found
    temp->connection.sid = new_sid;
    return 0;
}

// returns -2 on failure, the sid on success
int get_user_sid(int sockfd) {
    struct connection_node* temp = user_connections.head;
    while (temp!= NULL && temp->connection.sockfd != sockfd) {
        temp = temp->next;
    }
    if (temp == NULL) return -2;
    return temp->connection.sid;
}

// remove user from a session, closing the session if necessary
void remove_user_from_session(int sockfd, int sid) {
    // search through the sessions object, find the session
    struct session_node* temp = sessions.head;
    while(temp != NULL && temp->session.sid != sid) { 
        temp = temp->next;
    }
    if (temp == NULL) return;// incorrect session id was given because session was not found
    // found session, now remove user from it
    temp->session.session_users = remove_sfn(temp->session.session_users, sockfd);
    // now check if this was the last user in session, if so, remove session entirely
    if (temp->session.session_users == NULL) {
        remove_session(sid);
    }
}

// remove connection from the user_connections variable
struct connection_node* remove_connection(int sockfd, struct connection_node* head)
{
    // already empty, shouldn't happen but include just for fun
    if (head == NULL) return head;


    // at the front

    struct connection_node *temp = head;
    if (temp->connection.sockfd == sockfd) {
        int sid = head->connection.sid;
        if (sid >= 0) { // user had an active session
            remove_user_from_session(sockfd, sid);
        }
        printf("%s logged out.\n", head->connection.user_id);
        head = head->next;
        free(temp);
        return head;
    }

    // search list
    while (temp->next != NULL && temp->next->connection.sockfd != sockfd)
    {
        temp = temp->next;
    }
    if (temp->next == NULL) return head; // wasn't found in list, shouldn't happen but include for fun

    struct connection_node* temp2 = temp->next;
    int sid = temp2->connection.sid;
    if (sid >= 0) { // user had an active session
        remove_user_from_session(sockfd, sid);
    }
    temp->next = temp->next->next;
    printf("%s logged out.\n", temp2->connection.user_id);

    free(temp2);
    return head;
}

// can only be called on the user_connections object to close the sockfd.
// Essentially a wrapper around the remove_connection function
void close_connection(int sockfd) {
    user_connections.num_connections--;
    user_connections.head = remove_connection(sockfd ,user_connections.head);

}


// add a specific user to the session
int add_user_to_session(int sockfd, int sid) {
    
    // find correct session and add user info to the session's connections
    struct session_node* temp = sessions.head;
    while (temp != NULL && temp->session.sid != sid) {
        temp = temp->next;
    }
    // temp should now point to the correct session
    if (temp == NULL)
    {
        return 1; // should not happen
    }
    // insert into sockfd list
    temp->session.session_users = insert_sfn(temp->session.session_users, sockfd);
    
    return 0;
}


// creates a new session
int create_session(int sockfd, char* session_id) {
    // check if session_id isn't already taken
    struct session_node* temp = sessions.head;
    while (temp != NULL && strcmp(temp->session.session_id, session_id) != 0) {
        temp = temp->next;
    }
    if (temp!= NULL) return -1; //session already taken


    sessions.num_sessions++;
    int new_sid = sessions.next_sid;
    sessions.next_sid++;
    
    // create the new session
    sessions.head = insert_sn(sessions.head, new_sid, session_id);

    // add user to newly created session
    add_user_to_session(sockfd, new_sid); 
    return new_sid;
}

// turns the struct message into a string to be sent
int compile_message(char buffer[], struct message *msg)
{
    sprintf(buffer, "%d;%d;%s;%s", msg->type, msg->size, (char*)msg->source, (char*)msg->data);
    return 0;
}

// turns rcv into message object.
// size is the size, in bytes, of data that was received
int parse_message(char rcv[], int size, struct message *msg)
{
    int arg_num = 1;
    int start_colon = 0;
    int arg_size;
    for (int i = 0; i < size; i++)
    {
        if (rcv[i] != ';')
        {
            continue;
        }
        arg_size = i - start_colon;
        char next_arg[arg_size + 1];
        strncpy(next_arg, rcv + start_colon, arg_size);
        next_arg[arg_size] = '\0';
       
        start_colon = i + 1;

        if (arg_num == 1)
        {
            msg->type = atoi(next_arg);
            arg_num = 2;
        }
        else if (arg_num == 2)
        {
            msg->size = atoi(next_arg);
            arg_num = 3;
        }
        else if (arg_num == 3)
        {
            strcpy((char*)msg->source, next_arg);
            // rest of message is assumed to be data
            strncpy((char *)msg->data, rcv + start_colon, msg->size);
            msg->data[msg->size] = '\0';
            
            return 0;
        }
    }
    return 0;
}

// ================================================================
// =================== Helper Functions [END] ===================
// ================================================================

// Complete function for user logging in, if log in fails, socket is closed.
// Returns SYS_ERROR is a system call error occurs.
// Returns INVALID_PASSWORD is an invalid password resulted in the failure.
// Returns USER_ONLINE if input_id corresponds to active user.
// Returns USER_NOT_FOUND if user not in registry.
// Returns TOO_LONG is input_id or password are too long.
// Returns SUCCESS on success.
int login_user(int sockfd, const char *input_id, const char *password)
{

    int status = add_connection(input_id, password, sockfd);
    if (status != SUCCESS)
    {      
        return status;
    }

    // send message informing user of successful login
    struct message msg;
    msg.type = LO_ACK;
    msg.size = 0;
    strcpy((char*)msg.source, "server");
    strcpy((char*)msg.data, "");
    char buffer[MAX_MSG_SIZE+1];
    compile_message(buffer, &msg);
    if (send(sockfd, buffer, strlen(buffer),MSG_CONFIRM) == -1) {
        perror("send");
        
    }
    return SUCCESS;
}



// Complete function for logging out the user.
// Returns SYS_ERROR if failed to close socket.
// Returns SUCCESS on success.
int logout_user(int sockfd)
{

    if (close(sockfd) == -1)
    {
        perror("close");
        return SYS_ERROR;
    }
    close_connection(sockfd);
    return SUCCESS;
}

// Complete function for user joining session
// Returns INVALID_SESSION_ID if session does not exists.
// Returns SUCCESS on success.
int join_session(int sockfd, char *session_id)
{
    int sid = sessionid_to_sid(session_id);
    if (sid == -1)
        return INVALID_SESSION_ID; // session does not exist
    update_user_sid(sockfd,sid);

    // update session socks
    struct session_node* temp = sessions.head;
    while (temp != NULL && temp->session.sid != sid) {
        temp = temp->next;
    }
    if (temp == NULL) return INVALID_SESSION_ID;
    temp->session.session_users = insert_sfn(temp->session.session_users, sockfd);

    struct message msg;
    msg.type = JN_ACK;
    msg.size = strlen(session_id);
    strcpy((char *)msg.source, "server");
    strcpy((char *)msg.data, session_id);
    char buffer[MAX_MSG_SIZE + 1];
    compile_message(buffer, &msg);
    send(sockfd, buffer, strlen(buffer), 0);

    return SUCCESS;
}

// Complete function for removing user from session
// Returns NOT_IN_SESSION if user tries to leave a session they are not in.
// Returns SUCCESS on success.
int leave_session(int sockfd)
{

    int sid = get_user_sid(sockfd);
    if (sid == -1)
        return NOT_IN_SESSION; // session does not exist
    remove_user_from_session(sockfd, sid);
    update_user_sid(sockfd, -1);
    return SUCCESS;
}

// Complete function for creating a session, also updates users sid.
// Returns ALREADY_IN_SESSION is user is already in a session.
// Returns SESSION_EXISTS if session already exists.
// Returns SUCCESS on success.
int create_session_complete(int sockfd, char *session_id)
{

    int status = get_user_sid(sockfd);
    if (status >0)
    {
        return ALREADY_IN_SESSION; // user already in a session, can't create one
    }

    int new_sid = create_session(sockfd, session_id);
    if (new_sid == -1)
    {
        return SESSION_EXISTS; // session already exists
    }
    update_user_sid(sockfd, new_sid);

    struct message msg;
    msg.type = NS_ACK;
    msg.size = 0;
    strcpy((char *)msg.source, "server");
    strcpy((char *)msg.data, "");
    char buffer[MAX_MSG_SIZE + 1];
    compile_message(buffer, &msg);

    send(sockfd, buffer, strlen(buffer), 0);
    return SUCCESS;
}



// Complete function for listing all currently connected clients and sessions
// will always succeed
int list_user_session(int sockfd) {

    char response[MAX_DATA+1];
    char temp[50];
    char *newLine = "\n";
    // deal with users first
    sprintf(temp, "Number of active users: %d\n", user_connections.num_connections);
    strcpy(response, temp);
    struct connection_node* c_temp = user_connections.head;
    while (c_temp != NULL) {
        strncat(response, c_temp->connection.user_id, strlen(c_temp->connection.user_id));
        strncat(response, newLine, 1);
        c_temp = c_temp->next;
    }

    // now deal with active sessions
    sprintf(temp, "\nNumber of sessions: %d\n", sessions.num_sessions);
    strncat(response, temp, strlen(temp));
    struct session_node *s_temp = sessions.head;
    while (s_temp != NULL)
    {
        strncat(response, s_temp->session.session_id, strlen(s_temp->session.session_id));
        strncat(response, newLine, 1);
        s_temp = s_temp->next;
    }


    struct connection_node* user = user_connections.head;
    while (user != NULL && user->connection.sockfd != sockfd) {
        user = user->next;
    }
    if (user != NULL) {
        int sid = user->connection.sid;
        if (sid != -1) {
            // find session
            char *session_id = sid_to_sessionid(sid);
            sprintf(temp, "\nCurrently active session: %s\n", session_id);
            strncat(response, temp, strlen(temp));
            struct session_node* s_temp2 = sessions.head;
            while (s_temp2 != NULL && s_temp2->session.sid != sid) {
                s_temp2 = s_temp2->next;
            }
            struct sockfd_node* sfn_temp = s_temp2->session.session_users;
            while (sfn_temp != NULL) {
                char* user_id = get_user_id(sfn_temp->sockfd);
                strncat(response, user_id, strlen(user_id));
                strncat(response, newLine, 1);

                sfn_temp = sfn_temp->next;
            }
        }
    }
    


    strncat(response, "\0", 1);

    struct message msg;
    msg.type = QUERY;
    msg.size = strlen(response);
    strcpy((char *)msg.source, "server");
    strcpy((char *)msg.data, response);
    char buffer[MAX_MSG_SIZE + 1];
    compile_message(buffer, &msg);
    

    send(sockfd, buffer, strlen(buffer), 0);
    return SUCCESS;
}




// Complete function for sending a message to all users in a session
// sockfd is the sockfd where the message originated from.
// This function is essentially a pass through. 
// It receives the message, and then sends it to all users in sockfd's session.
// It fails if user tried to send a message but not in any sessions.
// Returns NOT_IN_SESSION if not in session
// Returns SERVER_ERROR if server messed up
// Returns SUCCESS on success
int send_session_message(int sockfd, char rcv[], int msg_size) {
    // print_sessions();
    int sid = get_user_sid(sockfd);
    if (sid == -1) {
        return NOT_IN_SESSION;
    }

    struct session_node* session = sessions.head;
    while (session != NULL && session->session.sid !=sid) {
        session = session->next;
    }
    // got to here, it is impossible for session to be NULL,
    // else above return would have been invoked. Still server might have screwed up.
    if (session == NULL) {
        return SERVER_ERROR;
    }
    // now we can finally send it off
    struct sockfd_node* sock_node = session->session.session_users;
    while (sock_node != NULL ) {
        if (sock_node->sockfd == sockfd) {
            sock_node = sock_node->next;
            continue;
        } // don't want to send msg back to user
        int num_bytes = send(sock_node->sockfd, rcv, msg_size, 0);
        sock_node = sock_node->next;
    }

    return SUCCESS;
}


// send private message to user. The data argument contains the name of the user
// the private message is sent ot, separated by a ';' from the actual data
int send_private_message(int sockfd, struct message* msg) {
    // need to extract the recipient from the msg->data field
    
    char recipient[MAX_NAME];
    int i;
    for (i = 0; i < msg->size; i++) {
        if (msg->data[i] != ';') {
            continue;
        }
        // got to here, found the comma
        strncpy(recipient, msg->data, i);
        recipient[i] = '\0';
        break;
    }

    // find the recipients fd
    struct connection_node* user = user_connections.head;
    while (user!= NULL && strcmp(user->connection.user_id,recipient) != 0) {
        user = user->next;
    }
    if (user == NULL) {
        return USER_NOT_FOUND;
    } 

    // compile the message
    struct message send_msg;
    strcpy((char*)send_msg.data, (char*)msg->data + i+1); // remove recipient from data field
    strcpy((char*) send_msg.source, (char*)msg->source);
    send_msg.type = PRIVATE_MESSAGE;
    send_msg.size = msg->size - i - 1;
    char send_buf[MAX_MSG_SIZE+1];
    compile_message(send_buf, &send_msg);
    printf("%s sent a dm to %s\n", msg->source, recipient);
    // now we can finally send it off
    int num_bytes = send(user->connection.sockfd, send_buf, strlen(send_buf), 0);

    return SUCCESS;
}

// process user registration request
int register_user(int sockfd, const char *input_id, const char *password)
{

    int status = register_connection(input_id, password, sockfd);
    if (status != SUCCESS)
    {      
        return status;
    }

    // send message informing user of successful login
    struct message msg;
    msg.type = REG_ACK;
    msg.size = 0;
    strcpy((char*)msg.source, "server");
    strcpy((char*)msg.data, "");
    char buffer[MAX_MSG_SIZE+1];
    compile_message(buffer, &msg);
    if (send(sockfd, buffer, strlen(buffer),MSG_CONFIRM) == -1) {
        perror("send");
        
    }
    return SUCCESS;
}


// prints what server sees
// session arg is what user passed in, if anything, 
// session id is the session the user was in before they did anything
void print_res(int type, char* user_id, char* error_msg, char* session_arg, char* session_id) {
    
    switch (type) {
        case LO_ACK:
            printf("%s logged in.\n", user_id);
            break;
        case LO_NAK:
            printf("Failed log in attempt from %s\n", user_id);
            break;
        case REG_ACK:
            printf("%s registered.\n", user_id);
            break;
        case REG_NAK:
            printf("Failed registration attempt from %s\n", user_id);
            break;
        case JN_ACK:
            printf("%s joined %s.\n", user_id, session_arg);
            break;
        case JN_NAK:
            printf("%s attempted to join %s, failed: %s\n", user_id, session_arg, error_msg);
            break;
        case NS_ACK:
            printf("%s created %s.\n", user_id, session_arg);
            break;
        case NS_NAK:
            printf("%s attempted to create %s, failed: %s\n", user_id, session_arg, error_msg);
            break;
        case LEAVE_SESS: 
            printf("%s left %s.\n", user_id, session_arg);
            break;
        case QUERY: 
            printf("%s sent a QUERY.\n", user_id);
            break;
        case MESSAGE:
            printf("%s sent a message to %s.\n", user_id, session_id);
            break;
        case P_NAK:
            printf("%s failed to send a direct message.\n", user_id);
            break;
    }
}

// routing function that processes and manages requests
// sockfd -- user that sent the message rcv of size msg_size.
// Unless the status of the message is an error, the function does not send anything
void process_message(int sockfd, char rcv[], int msg_size) {
    int sid = get_user_sid(sockfd);
    char *session_id;
    if (sid != -1)
        session_id = sid_to_sessionid(sid);
    struct message msg;
    int status;
    int ret_type = MESSAGE; // optional, might not be used but just in case it is needed, it saves the packet type on failure
    parse_message(rcv, msg_size, &msg);
    char user_id[MAX_NAME]; 
    strcpy(user_id,msg.source);
    switch (msg.type) {
        case LOGIN:
            status = login_user(sockfd, (char *)msg.source, (char *)msg.data);
            if (status == SUCCESS)   ret_type = LO_ACK;
            else ret_type = LO_NAK;
            break;
        case REGISTER:
            status = register_user(sockfd, (char *)msg.source, (char *)msg.data);
            if (status == SUCCESS)   ret_type = REG_ACK;
            else ret_type = REG_NAK;
            break;
        case EXIT: 
            logout_user(sockfd);
            status = SUCCESS;
            ret_type = EXIT;
            break;
        case JOIN:
            status = join_session(sockfd, (char *)msg.data);
            if (status == SUCCESS) ret_type = JN_ACK;
            else ret_type = JN_NAK;
            break;
        case LEAVE_SESS:
            leave_session(sockfd); // status doesn't matter
            status = SUCCESS;
            ret_type = LEAVE_SESS;
            break;
        case NEW_SESS:
            status = create_session_complete(sockfd, (char *)msg.data);
             if (status == SUCCESS) ret_type = NS_ACK;
            else ret_type = NS_NAK;
            
            break;
        case QUERY:
            list_user_session(sockfd);
            status = SUCCESS;
            ret_type = QUERY;
            break;
        case MESSAGE:
            send_session_message(sockfd, rcv, msg_size);
            status = SUCCESS;
            ret_type = MESSAGE;
            break;
        case PRIVATE_MESSAGE:
            status = send_private_message(sockfd, &msg);
            if (status != SUCCESS) {
                ret_type = P_NAK;
            }
            else ret_type = -1; // don't print anything for the server, done in the function
            break;
    }
    if (status == SUCCESS) {
        print_res(ret_type, user_id, NULL, msg.data, session_id);
        return;
    }

    // got to here, there was an error in user input, need to send a 
    struct message send_msg;
    send_msg.type = ret_type;
    error_check(status, (char *)send_msg.data);
    send_msg.size = strlen((char *)send_msg.data);
    strcpy((char *)send_msg.source, "server");
    char buffer[MAX_MSG_SIZE+1];
    compile_message(buffer, &send_msg);

    print_res(ret_type, user_id, send_msg.data, msg.data, session_id);

    //some printing for server
    send(sockfd, buffer, strlen(buffer),0);

    if (ret_type == LO_NAK) {
          if (close(sockfd) == -1)
        {
            perror("close");
            return;
        }
    }
    
}


// establishes a socket on this computer with port_num.
// returns the file descriptor of the socket
/************************************************
 * The majority of the below code was taken from:
 * Beej's Guide to Network Programming,
 * Using Internet Sockets
 *
 * By "Beej Jorgensen" Hall
 *
 * v3.1.5, Copyright © November 20,2020
 ***********************************************/
int establish_listener(char *port_num)
{

    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // set to AF_INET to use IPv4
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((getaddrinfo(NULL, port_num, &hints, &servinfo)) != 0)
    {
        perror("getaddrinfo");
        return -1;
    }

    // loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1)
        {
            perror("listener: socket");
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("listener: bind");
            continue;
        }
        fcntl(sockfd, F_SETFL, O_NONBLOCK);
        break;
    }

    if (p == NULL)
    {
        fprintf(stderr, "listener: failed to bind socket\n");
        return -1;
    }
    freeaddrinfo(servinfo);

    return sockfd;
}



// monitor all clients, check if they sent any messages
struct sockfd_node* monitor_clients(int server_sockfd, struct sockfd_node* wait_list) {
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    sin_size = sizeof(their_addr);
    // first check if there are any new pending connections
    int new_fd = accept(server_sockfd, (struct sockaddr *)&their_addr, &sin_size);
    if (new_fd != -1) {
        // add it to the wait_list
        wait_list = insert_sfn(wait_list, new_fd);
        
    }


    // check if received anything from the wait list (should receive a login)
    struct sockfd_node* wait_sock = wait_list;
    while (wait_sock != NULL) {
        char rcv[MAX_MSG_SIZE + 1];
        int num_bytes = recv(wait_sock->sockfd, rcv, MAX_MSG_SIZE, 0);
        if (num_bytes > 0)
        {
            rcv[num_bytes] = '\0';
            process_message(wait_sock->sockfd, rcv, num_bytes);
            wait_list = remove_sfn(wait_list, wait_sock->sockfd);
            // print_user_connections();

        }
        if (num_bytes == 0) { // client closed connection without sending a message, close connection
            if (close(wait_sock->sockfd) == -1) {
                perror("close");
            }
        }
        wait_sock = wait_sock->next;
    }

    // now check if any of the users has sent anything
    struct connection_node* user = user_connections.head;
    while (user!= NULL) {
        char rcv[MAX_MSG_SIZE+1];
        int num_bytes = recv(user->connection.sockfd, rcv, MAX_MSG_SIZE, MSG_DONTWAIT);
        if (num_bytes > 0) {
            rcv[num_bytes] = '\0';
            process_message(user->connection.sockfd, rcv, num_bytes);
            // print_user_connections();
        }
        if (num_bytes == 0)
        { // client closed connection without sending a message, close connection
            close_connection(user->connection.sockfd);
        }
        user = user->next;
    } 

    return wait_list;
}



int main(int argc, char *argv[])
{
    // initiate connection
    if (argc != 2) {
        printf("Error: Expected 1 argument but got %d\n", argc-1);
        return EINVAL;
    }

    
    // get socket file descriptor
    int sockfd = establish_listener(argv[1]);


    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }


    printf("server: waiting for connections...\n");

    struct sockfd_node *wait_list = NULL;
    while (1)
    {
        monitor_clients(sockfd, wait_list);
    }

    return 0;
}