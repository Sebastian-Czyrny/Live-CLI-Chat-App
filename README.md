# Live-CLI-Chat-App
A CLI Chat Application built using UNIX Sockets


## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)

## Installation
To install:

1. Clone the repository: 
```git clone https://github.com/Sebastian-Czyrny/Live-CLI-Chat-App.git```

### Run the Client

1. Navigate to the client directory: `cd client`

2. Build the client: `make`

3. Run the client application using: `./client`. No command line arguments are accepted.

### Run the Server

1. Navigate to the client directory: `cd server`

2. Build the server: `make`

3. Run the server application using: `./server <port>`. Replace `<port>` with the port number to run the server on. 


## Usage
To use the application, both the client and server applications must be running. See [Installation](Installation) for details on how to run both the server and the client.

The server is a passive listener. As such, it does not accept any commands, but listens to any client applications.

The client has the following commands available to it:

- `/login <username> <password> <server address> <server port>`
    
    - Login to the server 

- `/register <username> <password> <server address> <server port>` 

    - Register a new user with the server

- `/logout`

    - Logout from the server
- `/joinsession <session name>`

    - Join a new session with name `<session name>`

- `/leavesession`

    - Leave the session you are currently in.

- `/createsession <session name>`

    - Create and join a new session with name `<session name>`

- `/list`

    - List all users in the current session

- `/dm <username> <message>`

    - Direct message a user in the same session.

- `/quit`

    - Close the client application.

- `<message>`

    - Send a message to everyone in the session (must be in a session).



## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.