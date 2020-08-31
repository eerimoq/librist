
typedef struct rist_tools_config_object {
        int buffer;
        int encryption_type;
        int profile;
        int stats_interval;
        char * tunnel_interface;
        char * secret;
        char * input_url;
        char * output_url;
} rist_tools_config_object;

void strapp(char * original, char * newstr);
bool parse_yaml(char * file, rist_tools_config_object * config);
