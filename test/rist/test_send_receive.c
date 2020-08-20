#include "librist/librist.h"
#include "src/rist-private.h"
#include <stdatomic.h>

atomic_ulong failed;
atomic_ulong stop;

struct rist_logging_settings *logging_settings;

int log_callback(void *arg, int level, const char *msg) {
    RIST_MARK_UNUSED(arg);
    //if (level <= RIST_LOG_NOTICE)
        fprintf(stderr, "%s", msg);
    if (level <= RIST_LOG_ERROR) {
        atomic_store(&failed, 1);
        atomic_store(&stop, 1);
    }
    return 0;
}

struct rist_ctx *setup_rist_receiver(int profile, const char *url) {
    struct rist_ctx *ctx;
	if (rist_receiver_create(&ctx, profile, logging_settings) != 0) {
		rist_log(logging_settings, RIST_LOG_ERROR, "Could not create rist receiver context\n");
		exit(1);
	}
    // Rely on the library to parse the url
    const struct rist_peer_config *peer_config = NULL;
    if (rist_parse_address(url, (void *)&peer_config))
    {
        rist_log(logging_settings, RIST_LOG_ERROR, "Could not parse peer options for receiver\n");
        exit(1);
    }
    struct rist_peer *peer;
    if (rist_peer_create(ctx, &peer, peer_config) == -1) {
        rist_log(logging_settings, RIST_LOG_ERROR, "Could not add peer connector to receiver\n");
        exit(1);
    }
    free((void *)peer_config);
	if (rist_start(ctx) == -1) {
		rist_log(logging_settings, RIST_LOG_ERROR, "Could not start rist sender\n");
		exit(1);
	}
    return ctx;

}

struct rist_ctx *setup_rist_sender(int profile, const char *url) {
    struct rist_ctx *ctx;
    if (rist_sender_create(&ctx, profile, 0, logging_settings) != 0) {
		rist_log(logging_settings, RIST_LOG_ERROR, "Could not create rist sender context\n");
		exit(1);
	}

    const struct rist_peer_config *peer_config_link = NULL;
    if (rist_parse_address(url, (void *)&peer_config_link))
    {
        rist_log(logging_settings, RIST_LOG_ERROR, "Could not parse peer options for sender\n");
        exit(1);
    }

    struct rist_peer *peer;
    if (rist_peer_create(ctx, &peer, peer_config_link) == -1) {
        rist_log(logging_settings, RIST_LOG_ERROR, "Could not add peer connector to sender\n");
        exit(1);
    }
	if (rist_start(ctx) == -1) {
		rist_log(logging_settings, RIST_LOG_ERROR, "Could not start rist sender\n");
		exit(1);
	}
    return ctx;
}

static PTHREAD_START_FUNC(send_data, arg) {
    struct rist_ctx *rist_sender = arg;
    int send_counter = 0;
    char buffer[1316];
    struct rist_data_block data;
    /* we just try to send some string at ~20mbs for ~8 seconds */
    while (send_counter < 16000) {
        if (atomic_load(&stop))
            break;
        sprintf(buffer, "DEADBEAF TEST PACKET #%i", send_counter);
        data.payload = &buffer;
        data.payload_len = 1316;
        if (rist_sender_data_write(rist_sender, &data) != 0) {
            fprintf(stderr, "Failed to send test packet!\n");
            atomic_store(&failed, 1);
            atomic_store(&stop, 1);
            break;
        }
        send_counter++;
        usleep(500);

    }
    usleep(1500);
    atomic_store(&stop, 1);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        exit(1);
    }
    int profile = atoi(argv[1]);
    char *url1 = strdup(argv[2]);
    char *url2 = strdup(argv[3]);
    int losspercent = atoi(argv[4]);

    struct rist_ctx *receiver_ctx;
    struct rist_ctx *sender_ctx;

    atomic_init(&failed, 0);
    atomic_init(&stop, 0);


    fprintf(stderr, "Testing profile %i with receiver url %s and sender url %s and losspercentage: %i\n", profile, url1, url2, losspercent);

    if (rist_logging_set(&logging_settings, RIST_LOG_DEBUG, log_callback, NULL, NULL, stderr) != 0) {
		fprintf(stderr,"Failed to setup logging!\n");
		exit(1);
	}

    receiver_ctx = setup_rist_receiver(profile, url1);
    sender_ctx = setup_rist_sender(profile, url2);
    if (losspercent > 0) {
        receiver_ctx->receiver_ctx->simulate_loss = true;
        receiver_ctx->receiver_ctx->loss_percentage = losspercent;
        sender_ctx->sender_ctx->simulate_loss = true;
        sender_ctx->sender_ctx->loss_percentage = losspercent;
    }
    pthread_t send_loop;
    if (pthread_create(&send_loop, NULL, send_data, (void *)sender_ctx) != 0)
    {
        fprintf(stderr, "Could not start send data thread\n");
        exit(1);
    }

    const struct rist_data_block *b;
    char rcompare[1316];
    int receive_count = 1;
    bool got_first = false;
    while (receive_count < 16000) {
        if (atomic_load(&stop))
            break;
        int queue_length = rist_receiver_data_read(receiver_ctx, &b, 5);
        if (queue_length) {
            if (!got_first) {
                receive_count = (int)b->seq;
				got_first = true;
			}
            sprintf(rcompare, "DEADBEAF TEST PACKET #%i", receive_count);
            if (strcmp(rcompare, b->payload)) {
                fprintf(stderr, "Packet contents not as expected!\n");
                fprintf(stderr, "Got : %s\n", (char*)b->payload);
                fprintf(stderr, "Expected : %s\n", (char*)rcompare);
                atomic_store(&failed, 1);
                atomic_store(&stop, 1);
                break;
            }
            receive_count++;
        }
    }
	if (!got_first || receive_count < 12500)
		failed = true;
    if (atomic_load(&failed))
		return -1;

	fprintf(stderr, "OK\n");
    return 0;
}
