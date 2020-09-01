/* librist. Copyright 2020 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#include <librist/librist.h>
#include <librist/udpsocket.h>
#include "librist/version.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "getopt-shim.h"
#include <stdbool.h>
#include <signal.h>
#include "risturlhelp.h"
#include "yamlparse.h"

#if defined(_WIN32) || defined(_WIN64)
# define strtok_r strtok_s
#endif

#define RISTRECEIVER_VERSION "2"

#define MAX_INPUT_COUNT 10
#define MAX_OUTPUT_COUNT 10

static int signalReceived = 0;
static struct rist_logging_settings *logging_settings;
enum rist_profile profile = RIST_PROFILE_MAIN;

static struct option long_options[] = {
{ "file",      required_argument, NULL, 'f' },
{ "inputurl",        required_argument, NULL, 'i' },
{ "outputurl",       required_argument, NULL, 'o' },
{ "buffer",          required_argument, NULL, 'b' },
{ "secret",          required_argument, NULL, 's' },
{ "encryption-type", required_argument, NULL, 'e' },
{ "profile",         required_argument, NULL, 'p' },
{ "tun",             required_argument, NULL, 't' },
{ "stats",           required_argument, NULL, 'S' },
{ "verbose-level",   required_argument, NULL, 'v' },
{ "help",            no_argument,       NULL, 'h' },
{ "help-url",        no_argument,       NULL, 'u' },
{ 0, 0, 0, 0 },
};

const char help_str[] = "Usage: %s [OPTIONS] \nWhere OPTIONS are:\n"
"       -f | --file name.yaml                   * | YAML config file                                         |\n"
"       -i | --inputurl  rist://...             * | Comma separated list of input rist URLs                  |\n"
"       -o | --outputurl udp://... or rtp://... * | Comma separated list of output udp or rtp URLs           |\n"
"       -b | --buffer value                       | Default buffer size for packet retransmissions           |\n"
"       -s | --secret PWD                         | Default pre-shared encryption secret                     |\n"
"       -e | --encryption-type TYPE               | Default Encryption type (0, 128 = AES-128, 256 = AES-256)|\n"
"       -p | --profile number                     | Rist profile (0 = simple, 1 = main, 2 = advanced)        |\n"
"       -S | --statsinterval value (ms)           | Interval at which stats get printed, 0 to disable        |\n"
"       -v | --verbose-level value                | To disable logging: -1, log levels match syslog levels   |\n"
"       -h | --help                               | Show this help                                           |\n"
"       -u | --help-url                           | Show all the possible url options                        |\n"
"   * == mandatory value \n"
"Default values: %s \n"
"       --profile 1               \\\n"
"       --stats 1000              \\\n"
"       --verbose-level 6         \n";

static void usage(char *cmd)
{
	rist_log(logging_settings, RIST_LOG_INFO, "%s%s version %d.%d.%d.%s\n", help_str, cmd, LIBRIST_API_VERSION_MAJOR,
		LIBRIST_API_VERSION_MINOR, LIBRIST_API_VERSION_PATCH, RISTRECEIVER_VERSION);
	exit(1);
}

struct rist_callback_object {
	int mpeg[MAX_OUTPUT_COUNT];
	const struct rist_udp_config *udp_config[MAX_OUTPUT_COUNT];
	uint16_t i_seqnum[MAX_OUTPUT_COUNT];
};

static inline void risttools_rtp_set_hdr(uint8_t *p_rtp, uint8_t i_type, uint16_t i_seqnum, uint32_t i_timestamp, uint32_t i_ssrc)
{
	p_rtp[0] = 0x80;
	p_rtp[1] = i_type & 0x7f;
	p_rtp[2] = i_seqnum >> 8;
	p_rtp[3] = i_seqnum & 0xff;
    p_rtp[4] = (i_timestamp >> 24) & 0xff;
    p_rtp[5] = (i_timestamp >> 16) & 0xff;
    p_rtp[6] = (i_timestamp >> 8) & 0xff;
    p_rtp[7] = i_timestamp & 0xff;
	p_rtp[8] = (i_ssrc >> 24) & 0xff;
	p_rtp[9] = (i_ssrc >> 16) & 0xff;
	p_rtp[10] = (i_ssrc >> 8) & 0xff;
	p_rtp[11] = i_ssrc & 0xff;
}

static uint32_t risttools_convertNTPtoRTP(uint64_t i_ntp)
{
	i_ntp *= 90000;
	i_ntp = i_ntp >> 32;
	return (uint32_t)i_ntp;
}

static int cb_recv(void *arg, const struct rist_data_block *b)
{
	struct rist_callback_object *callback_object = (void *) arg;

	int found = 0;
	int i = 0;
	for (i = 0; i < MAX_OUTPUT_COUNT; i++) {
		if (!callback_object->udp_config[i])
			continue;
		const struct rist_udp_config *udp_config = callback_object->udp_config[i];
		// The stream-id on the udp url gets translated into the virtual source port of the GRE tunnel
		uint16_t virt_src_port = udp_config->stream_id;
		// look for the correct mapping of source port to output
		if (profile == RIST_PROFILE_SIMPLE ||  virt_src_port == 0 || (virt_src_port == b->virt_src_port)) {
			if (callback_object->mpeg[i] > 0) {
				uint8_t *payload = NULL;
				size_t payload_len = 0;
				if (udp_config->rtp) {
					payload = malloc(12 + b->payload_len);
					payload_len = 12 + b->payload_len;
					// Transfer payload
					memcpy(payload + 12, b->payload, b->payload_len);
					// Set RTP header (mpegts)
					uint16_t i_seqnum = udp_config->rtp_sequence ? (uint16_t)b->seq : callback_object->i_seqnum[i]++;
					uint32_t i_timestamp = risttools_convertNTPtoRTP(b->ts_ntp);
					risttools_rtp_set_hdr(payload, 0x21, i_seqnum, i_timestamp, b->flow_id);
				}
				else {
					payload = (uint8_t *)b->payload;
					payload_len = b->payload_len;
				}
				int ret = udpsocket_send(callback_object->mpeg[i], payload, payload_len);
				if (udp_config->rtp)
					free(payload);
				if (ret <= 0 && errno != ECONNREFUSED)
					rist_log(logging_settings, RIST_LOG_ERROR, "Error %d sending udp packet to socket %d\n", errno, callback_object->mpeg[i]);
				found = 1;
			}
		}
	}

	if (found == 0)
	{
		rist_log(logging_settings, RIST_LOG_ERROR, "Source port mismatch, no output found for %d\n", b->virt_src_port);
		return -1;
	}

	return 0;
}

static void intHandler(int signal) {
	rist_log(logging_settings, RIST_LOG_INFO, "Signal %d received\n", signal);
	signalReceived = signal;
}

static int cb_auth_connect(void *arg, const char* connecting_ip, uint16_t connecting_port, const char* local_ip, uint16_t local_port, struct rist_peer *peer)
{
	(void)peer;
	struct rist_ctx *ctx = (struct rist_ctx *)arg;
	char message[500];
	int ret = snprintf(message, 500, "auth,%s:%d,%s:%d", connecting_ip, connecting_port, local_ip, local_port);
	rist_log(logging_settings, RIST_LOG_INFO,"Peer has been authenticated, sending auth message: %s\n", message);
	struct rist_oob_block oob_block;
	oob_block.peer = peer;
	oob_block.payload = message;
	oob_block.payload_len = ret;
	rist_oob_write(ctx, &oob_block);
	return 0;
}

static int cb_auth_disconnect(void *arg, struct rist_peer *peer)
{
	(void)peer;
	struct rist_ctx *ctx = (struct rist_ctx *)arg;
	(void)ctx;
	return 0;
}

static int cb_recv_oob(void *arg, const struct rist_oob_block *oob_block)
{
	struct rist_ctx *ctx = (struct rist_ctx *)arg;
	(void)ctx;
	if (oob_block->payload_len > 4 && strncmp((char*)oob_block->payload, "auth,", 5) == 0) {
		rist_log(logging_settings, RIST_LOG_INFO,"Out-of-band data received: %.*s\n", (int)oob_block->payload_len, (char *)oob_block->payload);
	}
	return 0;
}

static int cb_stats(void *arg, const struct rist_stats *stats_container) {
	(void)arg;
	rist_log(logging_settings, RIST_LOG_INFO, "%s\n\n",  stats_container->stats_json);
	rist_stats_free(stats_container);
	return 0;
}

int main(int argc, char *argv[])
{
	int option_index;
	int c;
	int enable_data_callback = 1;
	const struct rist_peer_config *peer_input_config[MAX_INPUT_COUNT];
	char *inputurl = NULL;
	char *outputurl = NULL;
	char *oobtun = NULL;
	char *shared_secret = NULL;
	char *yamlfile = NULL;
	int buffer = 0;
	int encryption_type = 0;
	struct rist_callback_object callback_object;
	enum rist_log_level loglevel = RIST_LOG_INFO;
	int statsinterval = 1000;
	rist_tools_config_object * yaml_config = malloc(sizeof(rist_tools_config_object));

	for (size_t i = 0; i < MAX_OUTPUT_COUNT; i++)
	{
		callback_object.mpeg[i] = 0;
		callback_object.udp_config[i] = NULL;
	}

#ifdef _WIN32
#define STDERR_FILENO 2
    signal(SIGINT, intHandler);
    signal(SIGTERM, intHandler);
    signal(SIGABRT, intHandler);
#else
	struct sigaction act = { {0} };
	act.sa_handler = intHandler;
	sigaction(SIGINT, &act, NULL);
#endif

	if (rist_logging_set(&logging_settings, loglevel, NULL, NULL, NULL, stderr) != 0) {
		fprintf(stderr,"Failed to setup logging!\n");
		exit(1);
	}

	rist_log(logging_settings, RIST_LOG_INFO, "Starting ristreceiver version: %d.%d.%d.%s\n", LIBRIST_API_VERSION_MAJOR,
			LIBRIST_API_VERSION_MINOR, LIBRIST_API_VERSION_PATCH, RISTRECEIVER_VERSION);

	while ((c = (char)getopt_long(argc, argv, "f:i:o:b:s:e:t:p:S:v:h:u", long_options, &option_index)) != -1) {
		switch (c) {
		case 'f':
			yamlfile = strdup(optarg);
			if (!parse_yaml(yamlfile,yaml_config)){
				fprintf(stderr,"Could not import yaml file %s\n",yamlfile);
				exit(1);
			}
			inputurl = yaml_config->input_url;
			outputurl = yaml_config->output_url;
			buffer = yaml_config->buffer;
			shared_secret = yaml_config->secret;
			encryption_type = yaml_config->encryption_type;
			oobtun = yaml_config->tunnel_interface;
			profile = yaml_config->profile;
			statsinterval = yaml_config->stats_interval;
		break;
		case 'i':
			inputurl = strdup(optarg);
		break;
		case 'o':
			outputurl = strdup(optarg);
		break;
		case 'b':
			buffer = atoi(optarg);
		break;
		case 's':
			shared_secret = strdup(optarg);
		break;
		case 'e':
			encryption_type = atoi(optarg);
		break;
		case 't':
			oobtun = strdup(optarg);
		break;
		case 'p':
			profile = atoi(optarg);
		break;
		case 'S':
			statsinterval = atoi(optarg);
		break;
		case 'v':
			loglevel = atoi(optarg);
			if (rist_logging_set(&logging_settings, loglevel, NULL, NULL, NULL, stderr) != 0) {
				fprintf(stderr,"Failed to setup logging!\n");
				exit(1);
			}
		break;
		case 'u':
			rist_log(logging_settings, RIST_LOG_INFO, "%s", help_urlstr);
			exit(1);
		break;
		case 'h':
			/* Fall through */
		default:
			usage(argv[0]);
		break;
		}
	}

	if (inputurl == NULL || outputurl == NULL) {
		usage(argv[0]);
	}

	if (argc < 2) {
		usage(argv[0]);
	}

	/* rist side */

	struct rist_ctx *ctx;
	if (rist_receiver_create(&ctx, profile, logging_settings) != 0) {
		rist_log(logging_settings, RIST_LOG_ERROR, "Could not create rist receiver context\n");
		exit(1);
	}

	if (rist_auth_handler_set(ctx, cb_auth_connect, cb_auth_disconnect, ctx) != 0) {
		rist_log(logging_settings, RIST_LOG_ERROR, "Could not init rist auth handler\n");
		exit(1);
	}

	if (profile != RIST_PROFILE_SIMPLE) {
		if (rist_oob_callback_set(ctx, cb_recv_oob, ctx) == -1) {
			rist_log(logging_settings, RIST_LOG_ERROR, "Could not add enable out-of-band data\n");
			exit(1);
		}
	}

	if (rist_stats_callback_set(ctx, statsinterval, cb_stats, NULL) == -1) {
		rist_log(logging_settings, RIST_LOG_ERROR, "Could not enable stats callback\n");
		exit(1);
	}

	char *saveptr1;
	char *inputtoken = strtok_r(inputurl, ",", &saveptr1);
	for (size_t i = 0; i < MAX_INPUT_COUNT; i++) {
		if (!inputtoken)
			break;

		// Rely on the library to parse the url
		const struct rist_peer_config *peer_config = NULL;
		if (rist_parse_address(inputtoken, (void *)&peer_config))
		{
			rist_log(logging_settings, RIST_LOG_ERROR, "Could not parse peer options for receiver #%d\n", (int)(i + 1));
			exit(1);
		}

		/* Process overrides */
		struct rist_peer_config *overrides_peer_config = (void *)peer_config;
		if (shared_secret && peer_config->secret[0] == 0) {
			strncpy(overrides_peer_config->secret, shared_secret, RIST_MAX_STRING_SHORT -1);
			if (encryption_type)
				overrides_peer_config->key_size = encryption_type;
			else if (!overrides_peer_config->key_size)
				overrides_peer_config->key_size = 128;
		}
		if (buffer) {
			overrides_peer_config->recovery_length_min = buffer;
			overrides_peer_config->recovery_length_max = buffer;
		}

		/* Print config */
		rist_log(logging_settings, RIST_LOG_INFO, "Link configured with maxrate=%d bufmin=%d bufmax=%d reorder=%d rttmin=%d rttmax=%d congestion_control=%d min_retries=%d max_retries=%d\n",
			peer_config->recovery_maxbitrate, peer_config->recovery_length_min, peer_config->recovery_length_max, 
			peer_config->recovery_reorder_buffer, peer_config->recovery_rtt_min,peer_config->recovery_rtt_max,
			peer_config->congestion_control_mode, peer_config->min_retries, peer_config->max_retries);

		peer_input_config[i] = peer_config;

		struct rist_peer *peer;
		if (rist_peer_create(ctx, &peer, peer_input_config[i]) == -1) {
			rist_log(logging_settings, RIST_LOG_ERROR, "Could not add peer connector to receiver #%i\n", (int)(i + 1));
			exit(1);
		}

		free((void *)peer_config);
		inputtoken = strtok_r(NULL, ",", &saveptr1);
	}

	/* Mpeg side */
	bool atleast_one_socket_opened = false;
	char *saveptr2;
	char *outputtoken = strtok_r(outputurl, ",", &saveptr2);
	for (size_t i = 0; i < MAX_OUTPUT_COUNT; i++) {

		if (!outputtoken)
			break;

		// First parse extra parameters (?miface=lo&stream-id=1971) and separate the address
		// We are using the rist_parse_address function to create a config object that does not really
		// belong to the udp output. We do this only to avoid writing another parser for the two url
		// parameters available to the udp input/output url
		const struct rist_udp_config *udp_config = NULL;
		if (rist_parse_udp_address(outputtoken, &udp_config)) {
			rist_log(logging_settings, RIST_LOG_ERROR, "Could not parse outputurl %s\n", outputtoken);
			goto next;
		}

		// Now parse the address 127.0.0.1:5000
		char hostname[200] = {0};
		int outputlisten;
		uint16_t outputport;
		if (udpsocket_parse_url((void *)udp_config->address, hostname, 200, &outputport, &outputlisten) || !outputport || strlen(hostname) == 0) {
			rist_log(logging_settings, RIST_LOG_ERROR, "Could not parse output url %s\n", outputtoken);
			goto next;
		}
		rist_log(logging_settings, RIST_LOG_INFO, "URL parsed successfully: Host %s, Port %d\n", (char *) hostname, outputport);

		// Open the output socket
		callback_object.mpeg[i] = udpsocket_open_connect(hostname, outputport, udp_config->miface);
		if (callback_object.mpeg[i] <= 0) {
			rist_log(logging_settings, RIST_LOG_ERROR, "Could not connect to: Host %s, Port %d\n", (char *) hostname, outputport);
			goto next;
		} else {
			udpsocket_set_nonblocking(callback_object.mpeg[i]);
			rist_log(logging_settings, RIST_LOG_INFO, "Output socket is open and bound %s:%d\n", (char *) hostname, outputport);
			atleast_one_socket_opened = true;
		}
		callback_object.udp_config[i] = udp_config;

next:
		outputtoken = strtok_r(NULL, ",", &saveptr2);
	}

	if (!atleast_one_socket_opened) {
		exit(1);
	}

	// callback is best unless you are using the timestamps passed with the buffer
	enable_data_callback = 1;

	if (enable_data_callback == 1) {
		if (rist_receiver_data_callback_set(ctx, cb_recv, &callback_object))
		{
			rist_log(logging_settings, RIST_LOG_ERROR, "Could not set data_callback pointer");
			exit(1);
		}
	}

	if (rist_start(ctx)) {
		rist_log(logging_settings, RIST_LOG_ERROR, "Could not start rist receiver\n");
		exit(1);
	}
	/* Start the rist protocol thread */
	if (enable_data_callback == 1) {
#ifdef _WIN32
		system("pause");
#else
		pause();
#endif
	}
	else {
		// Master loop
		while (!signalReceived)
		{
			const struct rist_data_block *b;
			int queue_size = rist_receiver_data_read(ctx, &b, 5);
			if (queue_size && queue_size % 10 == 0)
				rist_log(logging_settings, RIST_LOG_WARN, "Falling behind on rist_receiver_data_read: %d\n", queue_size);
			if (b && b->payload) cb_recv(&callback_object, b);
		}
	}

	rist_destroy(ctx);

	for (size_t i = 0; i < MAX_OUTPUT_COUNT; i++) {
		// Free udp_config object
		if ((void *)callback_object.udp_config[i])
			free((void *)(callback_object.udp_config[i]));
	}

	if (inputurl)
		free(inputurl);
	if (outputurl)
		free(outputurl);
	if (oobtun)
		free(oobtun);
	if (shared_secret)
		free(shared_secret);
	free(logging_settings);
	free(yaml_config);

	return 0;
}
