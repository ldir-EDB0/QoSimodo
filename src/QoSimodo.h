#include <stdio.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <json-c/json.h>

#define SV_SOCK_PATH "/tmp/run/netifyd/netifyd.sock"
#define BUFFER_SIZE 4096

struct jump_table {
	char	*type;
	void	(*handler)(json_object *jobj);
};

struct protocol_table {
	char		*tag;
	unsigned int	dscp;
};

struct flow_struct {
	const char *srcip;
	const char *dstip;
	unsigned int srcport;
	unsigned int dstport;
	unsigned int ipversion;
};

int find_conntrack_entry(struct flow_struct *flow);
