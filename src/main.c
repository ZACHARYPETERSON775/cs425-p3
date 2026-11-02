#define _POSIX_C_SOURCE 200809L
#include "lab.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST
#define main main_exclude
#endif

static void print_usage(FILE *stream)
{
    fputs("Usage: myapp info <address>/<prefix>\n"
          "       myapp split <network>/<prefix> <count>\n"
          "       myapp lookup <table-file> <address>...\n",
          stream);
}

static bool parse_count(const char *text, uint32_t *count)
{
    if (text == NULL || *text == '\0') {
        return false;
    }

    uint32_t parsed = 0;
    for (const char *cursor = text; *cursor != '\0'; cursor++) {
        // Accept decimal digits only and detect overflow before multiplication.
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
        uint32_t digit = (uint32_t)(*cursor - '0');
        if (parsed > UINT32_MAX / 10 ||
            (parsed == UINT32_MAX / 10 && digit > UINT32_MAX % 10)) {
            return false;
        }
        parsed = parsed * 10 + digit;
    }

    *count = parsed;
    return true;
}

static void format_address(uint32_t address, char formatted[IP_STR_LEN])
{
    ip_format(address, formatted);
}

static int command_info(const char *text)
{
    cidr_t block;
    if (!cidr_parse(text, &block)) {
        fprintf(stderr, "myapp: '%s' is not a valid address/prefix\n", text);
        return 1;
    }

    char address[IP_STR_LEN];
    char netmask[IP_STR_LEN];
    char network[IP_STR_LEN];
    char broadcast[IP_STR_LEN];
    char first_host[IP_STR_LEN];
    char last_host[IP_STR_LEN];
    format_address(block.addr, address);
    // Derive all displayed subnet values from the parsed address and prefix.
    format_address(cidr_mask(block.prefix), netmask);
    format_address(cidr_network(block), network);
    format_address(cidr_broadcast(block), broadcast);
    format_address(cidr_first_host(block), first_host);
    format_address(cidr_last_host(block), last_host);

    printf("address    %s\n"
           "prefix     /%u\n"
           "netmask    %s\n"
           "network    %s\n"
           "broadcast  %s\n"
           "first host %s\n"
           "last host  %s\n"
           "hosts      %" PRIu64 "\n",
           address, (unsigned int)block.prefix, netmask, network, broadcast,
           first_host, last_host, cidr_host_count(block));
    return 0;
}

static int command_split(const char *text, const char *count_text)
{
    cidr_t block;
    uint32_t count;
    if (!cidr_parse(text, &block)) {
        fprintf(stderr, "myapp: '%s' is not a valid network/prefix\n", text);
        return 1;
    }
    if (!parse_count(count_text, &count) || count == 0) {
        fprintf(stderr, "myapp: '%s' is not a valid subnet count\n", count_text);
        return 1;
    }
    if (!cidr_is_network(block)) {
        fprintf(stderr, "myapp: '%s' has host bits set; expected a network\n", text);
        return 1;
    }

    // Validate the split once before printing, so invalid requests produce no partial output.
    cidr_t subnet;
    if (!cidr_subnet(block, count, 0, &subnet)) {
        fprintf(stderr, "myapp: cannot split '%s' into %" PRIu32 " equal subnets\n",
                text, count);
        return 1;
    }

    for (uint32_t index = 0; index < count; index++) {
        if (!cidr_subnet(block, count, index, &subnet)) {
            fprintf(stderr, "myapp: failed to calculate subnet %" PRIu32 "\n", index);
            return 1;
        }
        char formatted[CIDR_STR_LEN];
        cidr_format(subnet, formatted);
        puts(formatted);
    }
    return 0;
}

static int command_lookup(const char *path, int address_count, char *addresses[])
{
    FILE *input = fopen(path, "r");
    if (input == NULL) {
        fprintf(stderr, "myapp: cannot open %s: %s\n", path, strerror(errno));
        return 2;
    }

    fwd_table_t *table = table_create();
    if (table == NULL) {
        fprintf(stderr, "myapp: cannot create forwarding table\n");
        fclose(input);
        return 2;
    }

    size_t bad_line;
    if (!table_load(table, input, &bad_line)) {
        if (bad_line != 0) {
            fprintf(stderr, "myapp: %s:%zu: not a valid route\n", path, bad_line);
        } else {
            fprintf(stderr, "myapp: could not read %s\n", path);
        }
        table_destroy(table);
        fclose(input);
        return 2;
    }
    fclose(input);

    // Continue through every argument; malformed addresses take precedence over unreachable ones.
    bool malformed = false;
    bool unreachable = false;
    for (int index = 0; index < address_count; index++) {
        uint32_t address;
        if (!ip_parse(addresses[index], &address)) {
            fprintf(stderr, "myapp: '%s' is not a valid IPv4 address\n",
                    addresses[index]);
            malformed = true;
            continue;
        }

        char formatted[IP_STR_LEN];
        format_address(address, formatted);
        const route_t *route = table_lookup(table, address);
        if (route == NULL) {
            printf("%s unreachable\n", formatted);
            unreachable = true;
        } else if (route->gateway != 0) {
            char gateway[IP_STR_LEN];
            format_address(route->gateway, gateway);
            printf("%s via %s dev %s\n", formatted, gateway, route->dev);
        } else {
            printf("%s dev %s\n", formatted, route->dev);
        }
    }

    table_destroy(table);
    if (malformed) {
        return 1;
    }
    return unreachable ? 3 : 0;
}

int main(int argc, char *argv[])
{
    // The no-argument invocation is a successful usage path (used by make leak).
    if (argc == 1) {
        print_usage(stdout);
        return 0;
    }

    if (strcmp(argv[1], "info") == 0) {
        if (argc != 3) {
            print_usage(stderr);
            return 1;
        }
        return command_info(argv[2]);
    }

    if (strcmp(argv[1], "split") == 0) {
        if (argc != 4) {
            print_usage(stderr);
            return 1;
        }
        return command_split(argv[2], argv[3]);
    }

    if (strcmp(argv[1], "lookup") == 0) {
        if (argc < 4) {
            print_usage(stderr);
            return 1;
        }
        return command_lookup(argv[2], argc - 3, &argv[3]);
    }

    fprintf(stderr, "myapp: unknown command '%s'\n", argv[1]);
    print_usage(stderr);
    return 1;
}
