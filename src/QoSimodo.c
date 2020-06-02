#include "QoSimodo.h"

struct protocol_table prot[1024] = {};

void dump_json_object(json_object *jobj)
{
	json_object_object_foreach(jobj, k, v) {
		printf("key = %s value = %s\n",k, json_object_get_string(v));
	}
}

int get_json_int(json_object *jobj, char *key)
{
	json_object *tmpobj;
	char *str;
	int i;

	if (!json_object_object_get_ex(jobj, key, &tmpobj))
		return(0);
	i = json_object_get_int(tmpobj);
	return(i);
}

/* string values will have been malloc'd by json-c
 * in theory for the lifetime of the json object
 * unless we either use json_put to claim ownership
 * or we cop out like I do here by malloc'ing our
 * own space and copy
 */
char *get_json_str(json_object *jobj, char *key)
{
	json_object *tmpobj;
	const char *tmpstr;
	char *str;
	int len;

	if (!json_object_object_get_ex(jobj, key, &tmpobj))
		return(NULL);
	tmpstr = json_object_get_string(tmpobj);
	if (!tmpstr)
		return(NULL);

	len = strlen(tmpstr);
	str = malloc(len);
	strcpy(str, tmpstr);
	return(str);
}

void handle_protocols(json_object *jobj)
{
	json_object *prot_array, *prot_array_obj;
	unsigned int arraylen, i, id;
	char *tag;

	printf("In handle protocols\n");
	if (!json_object_object_get_ex(jobj, "protocols", &prot_array)) {
		printf("B0rk!\n");
		return;
	}
	arraylen = json_object_array_length(prot_array);

	for (i = 0; i < arraylen; i++) {
		/* get the i-th object in prot_array */
		prot_array_obj = json_object_array_get_idx(prot_array, i);

		id =  get_json_int(prot_array_obj, "id");
		tag = get_json_str(prot_array_obj, "tag");

		/* now in theory our i index and the id should match */
		if (i != id)
			printf("id and index don't match - hmmm \n");

		prot[i].tag = tag;
		prot[i].dscp = 0;
/* FIXME: somehow we need to populate the required DSCP values sensibly,
 * for now, just initialise them to zero
 * Thinking out loud: probably another routine that goes through the table
 * and updates, probably from a text or json (shudder) based file.
 */
		printf("id=%d tag=%s dscp=%d\n", i, prot[i].tag, prot[i].dscp);
	}
}

void handle_agent_hello(json_object *jobj)
{
	char *key, *val;

	printf("In handle agent_hello\n");
	dump_json_object(jobj);
}

void handle_agent_status(json_object *jobj)
{
	char *key, *val;

	printf("In handle agent_status\n");
	dump_json_object(jobj);
}

void handle_flow(json_object *jobj, struct my_nl_socket *mynl)
{
	json_object *tmpobj, *flowobj;
	struct flow_struct flow;

/*	printf("In handle flow\n"); */

	if (!json_object_object_get_ex(jobj, "internal", &tmpobj))
		return;
	if (!strcmp("true", json_object_get_string(tmpobj)))
		return;

	if (!json_object_object_get_ex(jobj, "flow", &flowobj))
		return;

	if (!json_object_object_get_ex(flowobj, "ip_version", &tmpobj))
		return;
	flow.ipversion = json_object_get_int(tmpobj);

	if (!json_object_object_get_ex(flowobj, "ip_protocol", &tmpobj))
		return;
	flow.ipprotocol = json_object_get_int(tmpobj);

	if (!json_object_object_get_ex(flowobj, "local_ip", &tmpobj))
		return;
	flow.srcip = json_object_get_string(tmpobj);

	if (!json_object_object_get_ex(flowobj, "other_ip", &tmpobj))
		return;
	flow.dstip = json_object_get_string(tmpobj);

	if (!json_object_object_get_ex(flowobj, "local_port", &tmpobj))
		return;
	flow.srcport = json_object_get_int(tmpobj);

	if (!json_object_object_get_ex(flowobj, "other_port", &tmpobj))
		return;
	flow.dstport = json_object_get_int(tmpobj);

	if (0xff != find_conntrack_entry(&flow, mynl)) {
		dump_json_object(jobj);
		printf("%u\n", flow.mark);
	}
}

json_object *get_json_from_socket(char *bufptr, json_tokener *tok, int sfd, unsigned int *cnt)
{
	static char *buf;
	static ssize_t len = 0;
	json_object *jobj = NULL;
	enum json_tokener_error jerr;
	*cnt = 0;

	while (1) {
		while (len > 0) {
			jobj = json_tokener_parse_ex(tok, buf, len);

			*cnt+=tok->char_offset;

			jerr = json_tokener_get_error(tok);
			if (jerr == json_tokener_continue)
				break;

			buf+=tok->char_offset;
			len-=tok->char_offset;

			if (jerr == json_tokener_success) {
				return(jobj);
			} else {
				printf("Error: %s\n", json_tokener_error_desc(jerr));
				buf++;
				len--;
				json_tokener_reset(tok);
			}
		}
		buf = bufptr;
		do {
			len = read(sfd, buf, BUFFER_SIZE);
		} while (len == -1 && errno == EINTR);
	}
}

int main(int argc, char *argv[])
{
/* socket foo */
	struct sockaddr_un addr;
	int sfd;

/* netlink socket foo */
	struct my_nl_socket mynl;

/* json foo */
	enum json_tokener_error jerr;
	json_tokener *tok = NULL;
	json_object *jobj = NULL;
	json_object *jval = NULL;

	char *buf;
	const char *str;

	enum statem{NONSYNC, LENGTH};
	enum statem state;

	unsigned int length, chklen, i;

	buf=malloc(BUFFER_SIZE);
	if (!buf) {
		printf("Yikes! Can't give you memory %d", BUFFER_SIZE);
		exit(128);
	}

	/* Please may I have a socket file descriptor? */
	if ((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) <= 0) {
		printf("socket b0rken\n");
		exit(127);
	}

	/* and now I want to connect the end point to my socket */
	/* which should provide lots of json */
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SV_SOCK_PATH, sizeof(addr.sun_path)-1);

	if (connect(sfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) == -1){
		printf("connection unsuccessful\n");
		exit(126);
	}

	create_conntrack_socket(&mynl);

	tok=json_tokener_new();

	state=NONSYNC;

	while (1) {
		jobj = get_json_from_socket(buf, tok, sfd, &chklen);
		if (json_object_is_type(jobj, json_type_object)) {
			switch (state) {
			case NONSYNC:
				jval = json_object_object_get(jobj, "length");
				if (jval) {
					state=LENGTH;
					length=json_object_get_int(jval);
/*					printf("Got length: %d\n", length); */

				}
				break;
				;;
			case LENGTH:
				state=NONSYNC;
				if (length != chklen) {
					printf("Length check failed %d %d\n", length, chklen);
					dump_json_object(jobj);
					break;
				}

				jval = json_object_object_get(jobj, "type");
				if (!jval) {
					printf("No type!\n");
					break;
				}

				/* variable number of arguments was more than my smart arse jump table
				 * and my brain could cope with - traditional if/else tree coming up
				 */
				str = json_object_get_string(jval);
				if (!strcmp("flow", str))
					handle_flow(jobj, &mynl);
				else if (!strcmp("agent_status", str))
					handle_agent_status(jobj);
				else if (!strcmp("protocols", str))
					handle_protocols(jobj);
				else if (!strcmp("agent_hello", str))
					handle_agent_hello(jobj);

				break;
				;;
			default:
				state=NONSYNC;
				printf("Unknown state! %d", state);
				;;
			}
		}
		if (!json_object_put(jobj))
			printf("*********************didn't free obj************************\n");

		json_tokener_reset(tok);
	}

	close_conntrack_socket(&mynl);
}
