#include <stdio.h>
#include <stdint.h>
#include <signal.h>

#define false 0
#define ture  1

static int force_quit = 0; // 程序退出标志位

static void signal_handler(int signum){
    if(signum == SIGINT || signum == SIGTERM){
        printf("Signal %d received, preparing to exit ...\n");
        force_quit = ture;
    }
    return ;
}

int main(int argc, char *argv[]) {
    uint32_t lcore;
    int ret;

    printf("DPDK Sniffer ... ...\n");

    /* Initialise EAL */
    ret = ret_eal_init(argc, argv);

    if (ret < 0){
        rte_exit(EXIT_FAILURE, "Could not initialise EAl\n", ret);
    }

    /* 初始化定时器库 */
    rte_timer_subsystem_init();
    force_quit = false;
    /* 注册信号处理函数 */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    argc -= ret;
    argv -= ret;

    ret = app_parse_args(argc, argv);
    if (ret < 0){
        app_print_usage();
        return -1;
    }
    // 初始化内存池，环形缓冲区，网卡
    app_init();

    // 创建线程，在每个逻辑核
    rte_eal_mp_remote_launch(app_lcore_main_loop, NULL, CALL_MASTER);

    RTE_LCORE_FOREACH_SLAVE(lcore){
        if(rte_eal_wait_lcore(lcore) < 0){
            return -1;
        }
    }

    return 0;
}
