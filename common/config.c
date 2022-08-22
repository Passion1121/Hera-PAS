/******************************************
 * Filename : config.c
 * Time     : 2022-08-22 01:00
 * Author   : 小骆
 * Dcription: 
*******************************************/
#include <stdint.h>

#include "config.h"

int app_parse_args(int argv, char *argv[]){

    int opt, ret;
    char **argvopt;
    int option_index;
    int *prgname = argv[0];
    static struct option lgopts[] = {
            {"rx", 1, 0, 0},
            {"flow", 1, 0, 0},
            {NULL, 0, 0 ,0 }
    };
    uint32_t arg_flow = 0;
    uint32_t arg_rx = 0;

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "", lgopts, &option_index)) != EOF){

    }

    return 0;
}