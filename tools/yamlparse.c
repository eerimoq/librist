#include <stdio.h>
#include <stdbool.h>
#include <yaml.h>
#include <yamlparse.h>

void strapp(char ** original, char * newstr){
	if (*original){
		char * appended = malloc((strlen(newstr)+strlen(*original)+1)*sizeof(char));
		strcpy(appended,*original);
		strcat(appended,newstr);
		free(*original);
		*original = appended;
	} else {
		*original = strdup(newstr);
	}
}


// Function to parse yaml config into a rist_tools_config_object
bool parse_yaml(char * file, rist_tools_config_object * config){

	bool on_value = false;		// Tracker bool if we've already found a key and are now coming up on a value
	bool on_input_url = false;	// Tracker bool if we're parsing the array for the input_url array
	bool on_output_url = false;	// Tracker bool if we're parsing the array for the output_url array
	char * current_key = NULL;		// Placeholder string to hold any yaml keys

	// Initialize rist_tools_config_object
	config->input_url = NULL;
	config->output_url = NULL;
	config->tunnel_interface = NULL;
	config->secret = NULL;
	config->buffer = 0;
	config->encryption_type = 0;
	config->profile = 0;
	config->stats_interval = 1000;

	// Initialize yaml parser
	yaml_parser_t * parser = malloc(sizeof(yaml_parser_t));
	yaml_event_t * event = malloc(sizeof(yaml_event_t));
	yaml_parser_initialize(parser);

	// Open yaml file
	FILE *f = fopen(file,"r");
	if (f == NULL) return false;
	yaml_parser_set_input_file(parser,f);


	// Iterate over yaml document
	do {
		if (!yaml_parser_parse(parser,event)) {
			fprintf(stderr,"Parser error %d\n", parser->error);
			return false;
		}
		switch(event->type){

			case YAML_SCALAR_EVENT:

				// Process the url array elements if our tracker bools are set
				if (on_input_url) {
					strapp(&config->input_url,(char *) event->data.scalar.value);
					strapp(&config->input_url,",");
					printf("Input Pre: %s\n",config->input_url);
				}
				else if (on_output_url){
					strapp(&config->output_url,(char *) event->data.scalar.value);
					strapp(&config->output_url,",");
					printf("Output Pre: %s\n",config->output_url);
				}

				// Process any keys/values, tracking the keys as we go along
				else if (on_value){
					if (strcmp(current_key,"buffer") == 0) config->buffer=atoi((char *) event->data.scalar.value);
					else if (strcmp(current_key,"encryption_type") == 0) config->encryption_type=atoi((char *) event->data.scalar.value);
					else if (strcmp(current_key,"stats_interval") == 0) config->stats_interval=atoi((char *) event->data.scalar.value);
					else if (strcmp(current_key,"profile") == 0) {
						if (strcmp((char *) event->data.scalar.value,"main") == 0) config->profile=1;
						else if (strcmp((char *) event->data.scalar.value,"advanced") == 0) config->profile=2;
						else config->profile=0;
					}
					else if (strcmp(current_key,"tunnel_interface") == 0) strapp(&config->tunnel_interface,(char *) event->data.scalar.value);
					else if (strcmp(current_key,"secret") == 0) strapp(&config->secret,(char *) event->data.scalar.value);
					on_value = false;
				} else {
					current_key = strdup((char *) event->data.scalar.value);
					on_value = true;
				}
				break;

			// If we are on a url array, set our tracker bools
			case YAML_SEQUENCE_START_EVENT:
				if (on_value){
					if (strcmp(current_key,"input_url") == 0) on_input_url = true;
					else if (strcmp(current_key,"output_url") == 0) on_output_url = true;
					on_value = false;
				}
				break;

			// If array is over, reset our tracker bools
			case YAML_SEQUENCE_END_EVENT:
				on_input_url = false;
				on_output_url = false;
				break;

			// Remaining yaml event types to suppress switch statement warnings, but are not necessary for our formatting
			case YAML_NO_EVENT: break;
			case YAML_STREAM_START_EVENT: break;
			case YAML_STREAM_END_EVENT: break;
			case YAML_DOCUMENT_START_EVENT: break;
			case YAML_DOCUMENT_END_EVENT: break;
			case YAML_ALIAS_EVENT: break;
			case YAML_MAPPING_START_EVENT: break;
			case YAML_MAPPING_END_EVENT: break;
		}
		if(event->type != YAML_STREAM_END_EVENT) yaml_event_delete(event);
	} while (event->type != YAML_STREAM_END_EVENT);

	// Remove trailing commas from aggregate URLs
	if (strlen(config->input_url) > 0) config->input_url[strlen(config->input_url)-1]=0;
	if (strlen(config->output_url) > 0) config->output_url[strlen(config->output_url)-1]=0;


	yaml_parser_delete(parser);
	free(parser);
	free(event);
	fclose(f);
	
	return true;
}
