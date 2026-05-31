#include "config.h"
#include "permut2048.h"
#include <sodium.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#include "gui.h"
#include "utils.h"

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    
    /* Disable core dumps for security */
    prctl(PR_SET_DUMPABLE, 0);
    struct rlimit limit = { .rlim_cur = 0, .rlim_max = 0 };
    setrlimit(RLIMIT_CORE, &limit);
    
    /* Initialize libsodium */
    if (sodium_init() < 0) {
        fprintf(stderr, "Error: Failed to initialize libsodium\n");
        return 1;
    }
    
    /* Initialize Tsuki-2048 round constants */
    init_rc_vectors();
    
    printf("%s v%s - %s\n", APP_NAME, APP_VERSION, APP_TITLE);
    
    /* Check for unencrypted swap and warn user */
    if (check_swap_security()) {
        printf("WARNING: Unencrypted swap detected! This may compromise security.\n");
        printf("Consider encrypting swap with LUKS or disabling swap entirely.\n");
        printf("Continuing anyway...\n");
    }
    
    printf("Starting GUI application...\n");
    /* Create and run GUI */
    int status = create_gui(argc, argv);
    
    return status;
}
