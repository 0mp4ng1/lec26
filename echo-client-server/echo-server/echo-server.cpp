#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <iostream>
#include <thread>
#include <vector>
#include <algorithm>

using namespace std;

vector<int> cli_sd;

void usage() {
	cout << "syntax : echo-server <port> [-e[-b]]\n";
	cout << "sample : echo-server 1234 -e -b\n";
}

struct Param {
	uint16_t port{0};
	bool echo{false};
    bool broad{false};

	bool parse(int argc, char* argv[]) {
        port = stoi(argv[1]);
		for (int i = 1; i < argc; i++) {
			if (strcmp(argv[i], "-e") == 0) {
				echo = true;
				continue;
			}
            if (strcmp(argv[i], "-b") == 0) {
				broad = true;
				continue;
			}			
		}
		return port != 0;
	}
} param;

void recvThread(int sd) {
	printf("clinet %d : ",sd);
	cout << "connected\n";
	static const int BUFSIZE = 65536;
	char buf[BUFSIZE];
	while (true) {
		ssize_t res = recv(sd, buf, BUFSIZE - 1, 0);
		if (res == 0 || res == -1) {
			cerr << "recv return " << res;
			perror(" ");
			break;
		}
		buf[res] = '\0';
		cout << buf;
		cout.flush();
		if (param.echo) {
			res = send(sd, buf, res, 0);
			if (res == 0 || res == -1) {
				cerr << "send return " << res;
				perror(" ");
				break;
			}
		}
        if(param.broad) {
            for(auto i_sd:cli_sd){
				if(i_sd==sd)
					continue;
                res = send(i_sd, buf, res, 0);
                if (res == 0 || res == -1) {
                    cerr << "send return " << res;
                    perror(" ");
                    break;
                }
            }
        }
	}
	auto this_sd = find(cli_sd.begin(), cli_sd.end(), sd);
	cli_sd.erase(this_sd);
	printf("clinet %d : ",sd);
	cout << "disconnected\n";
	close(sd);
}

int main(int argc, char* argv[]) {
	if (!param.parse(argc, argv)) {
		usage();
		return -1;
	}

	int sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd == -1) {
		perror("socket");
		return -1;
	}

	int res;
	int optval = 1;
	res = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (res == -1) {
		perror("setsockopt");
		return -1;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(param.port);

	ssize_t res2 = ::bind(sd, (struct sockaddr *)&addr, sizeof(addr));
	if (res2 == -1) {
		perror("bind");
		return -1;
	}

	res = listen(sd, 5);
	if (res == -1) {
		perror("listen");
		return -1;
	}

	while (true) {
		struct sockaddr_in cli_addr;
		socklen_t len = sizeof(cli_addr);
		int this_sd = accept(sd, (struct sockaddr *)&cli_addr, &len);
		if (this_sd == -1) {
			perror("accept");
			break;
		}
		cli_sd.push_back(this_sd);
		thread* t = new thread(recvThread, this_sd);
		t->detach();
	}
	close(sd);
}
