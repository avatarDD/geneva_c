/*
 * geneva — C port of Geneva (Genetic Evasion).
 * Multi-call binary: "geneva <command> [options]".
 */
#include <stdio.h>
#include <string.h>

#include "args.h"
#include "geneva.h"
#include "json.h"
#include "log.h"
#include "plat.h"
#include "util.h"

typedef struct {
    const char *name;
    int (*fn)(int argc, char **argv);
    const char *summary;
} command;

static const command commands[] = {
    {"apply", cmd_apply, "run a strategy over a pcap file offline"},
    {"check", cmd_check, "parse, validate and print strategies"},
    {"version", cmd_version, "print version and build features"},
};

static void usage(FILE *f)
{
    fprintf(f, "geneva %s - genetic censorship evasion (C port of Geneva)\n\n"
               "Usage: geneva <command> [options]\n\nCommands:\n",
            GENEVA_VERSION);
    for (size_t i = 0; i < ARRAY_LEN(commands); i++)
        fprintf(f, "  %-10s %s\n", commands[i].name, commands[i].summary);
    fprintf(f, "\nRun \"geneva <command> --help\" for command options.\n");
}

int cmd_version(int argc, char **argv)
{
    static const optdef defs[] = {
        {"json", 0, 0, NULL, "machine-readable output"},
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    args_t a;
    char err[128];
    if (args_parse(&a, argc, argv, defs, err, sizeof(err)) < 0) {
        fprintf(stderr, "geneva version: %s\n", err);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva version [--json]", defs);
        args_free(&a);
        return EXIT_OK;
    }
    if (arg_has(&a, "json")) {
        sbuf sb;
        jw w;
        sb_init(&sb);
        jw_init(&w, &sb);
        jw_obj(&w);
        jw_kstr(&w, "version", GENEVA_VERSION);
        jw_kint(&w, "proto", GENEVA_PROTO_VERSION);
        jw_kstr(&w, "os", plat_os_name());
        jw_kstr(&w, "arch", plat_arch_name());
        jw_key(&w, "features");
        jw_arr(&w);
#ifdef PLAT_LINUX
        jw_str(&w, "nfqueue");
#endif
#ifdef _WIN32
        jw_str(&w, "windivert");
#endif
        jw_str(&w, "ipv6");
        jw_str(&w, "pcap");
        jw_str(&w, "control");
        jw_arr_end(&w);
        jw_obj_end(&w);
        printf("%s\n", sb.data);
        sb_free(&sb);
    } else {
        printf("geneva %s (%s/%s)\n", GENEVA_VERSION, plat_os_name(), plat_arch_name());
    }
    args_free(&a);
    return EXIT_OK;
}

int main(int argc, char **argv)
{
    const char *cmd;
    log_init();
    if (plat_net_init() < 0) {
        fprintf(stderr, "geneva: network initialization failed\n");
        return EXIT_FAIL;
    }
    if (argc < 2) {
        usage(stderr);
        return EXIT_USAGE;
    }
    cmd = argv[1];
    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "help") == 0) {
        usage(stdout);
        return EXIT_OK;
    }
    if (strcmp(cmd, "-V") == 0 || strcmp(cmd, "--version") == 0)
        return cmd_version(0, NULL);
    for (size_t i = 0; i < ARRAY_LEN(commands); i++)
        if (strcmp(cmd, commands[i].name) == 0)
            return commands[i].fn(argc - 2, argv + 2);
    fprintf(stderr, "geneva: unknown command \"%s\"\n\n", cmd);
    usage(stderr);
    return EXIT_USAGE;
}
