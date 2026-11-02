#define _POSIX_C_SOURCE 200809L
#include "lab.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fwd_table {
    route_t *routes;
    size_t count;
    size_t capacity;
};

static void skip_whitespace(const char **text)
{
    while (isspace((unsigned char)**text)) {
        (*text)++;
    }
}

static bool read_token(const char **text, char *token, size_t token_size)
{
    const char *cursor = *text;
    size_t length = 0;

    skip_whitespace(&cursor);
    if (*cursor == '\0') {
        return false;
    }

    while (*cursor != '\0' && !isspace((unsigned char)*cursor)) {
        if (length + 1 >= token_size) {
            return false;
        }
        token[length++] = *cursor++;
    }
    token[length] = '\0';
    *text = cursor;
    return true;
}

bool route_parse(const char *line, route_t *route)
{
    if (line == NULL || route == NULL) {
        return false;
    }

    char destination[CIDR_STR_LEN];
    char gateway[IP_STR_LEN];
    route_t parsed = { 0 };
    const char *cursor = line;

    // Read exactly three fields; comments are stripped by table_load().
    if (!read_token(&cursor, destination, sizeof(destination)) ||
        !read_token(&cursor, gateway, sizeof(gateway)) ||
        !read_token(&cursor, parsed.dev, sizeof(parsed.dev))) {
        return false;
    }
    skip_whitespace(&cursor);
    if (*cursor != '\0') {
        return false;
    }

    if (strcmp(destination, "default") == 0) {
        parsed.dest = (cidr_t){ 0, 0 };
    } else if (!cidr_parse(destination, &parsed.dest) ||
               !cidr_is_network(parsed.dest)) {
        return false;
    }

    if (strcmp(gateway, "direct") != 0 &&
        !ip_parse(gateway, &parsed.gateway)) {
        return false;
    }

    *route = parsed;
    return true;
}

fwd_table_t *table_create(void)
{
    return calloc(1, sizeof(fwd_table_t));
}

void table_destroy(fwd_table_t *table)
{
    if (table != NULL) {
        free(table->routes);
        free(table);
    }
}

size_t table_count(const fwd_table_t *table)
{
    return table == NULL ? 0 : table->count;
}

bool table_add(fwd_table_t *table, const route_t *route)
{
    if (table == NULL || route == NULL ||
        route->dest.prefix > 32 || !cidr_is_network(route->dest) ||
        memchr(route->dev, '\0', sizeof(route->dev)) == NULL ||
        route->dev[0] == '\0') {
        return false;
    }

    // A destination/prefix pair may appear only once in the table.
    for (size_t index = 0; index < table->count; index++) {
        const cidr_t existing = table->routes[index].dest;
        if (existing.addr == route->dest.addr &&
            existing.prefix == route->dest.prefix) {
            return false;
        }
    }

    if (table->count == table->capacity) {
        // Grow geometrically, keeping the old allocation intact if realloc fails.
        size_t new_capacity = table->capacity == 0 ? 4 : table->capacity * 2;
        if (new_capacity < table->capacity ||
            new_capacity > SIZE_MAX / sizeof(*table->routes)) {
            return false;
        }
        route_t *new_routes = realloc(table->routes,
                                      new_capacity * sizeof(*table->routes));
        if (new_routes == NULL) {
            return false;
        }
        table->routes = new_routes;
        table->capacity = new_capacity;
    }

    table->routes[table->count++] = *route;
    return true;
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line)
{
    if (bad_line != NULL) {
        *bad_line = 0;
    }
    if (table == NULL || in == NULL) {
        return false;
    }

    char *line = NULL;
    size_t capacity = 0;
    size_t line_number = 0;
    ssize_t length;
    while ((length = getline(&line, &capacity, in)) >= 0) {
        (void)length;
        line_number++;

        // Remove inline comments before deciding whether this line is blank or a route.
        char *comment = strchr(line, '#');
        if (comment != NULL) {
            *comment = '\0';
        }
        const char *cursor = line;
        skip_whitespace(&cursor);
        if (*cursor == '\0') {
            continue;
        }

        route_t route;
        if (!route_parse(cursor, &route) || !table_add(table, &route)) {
            if (bad_line != NULL) {
                *bad_line = line_number;
            }
            free(line);
            return false;
        }
    }

    bool read_error = ferror(in) != 0 || !feof(in);
    free(line);
    return !read_error;
}

const route_t *table_lookup(const fwd_table_t *table, uint32_t dest)
{
    if (table == NULL) {
        return NULL;
    }

    const route_t *best = NULL;
    for (size_t index = 0; index < table->count; index++) {
        const route_t *route = &table->routes[index];
        // Replacing best only for a longer prefix makes insertion order irrelevant.
        if (cidr_contains(route->dest, dest) &&
            (best == NULL || route->dest.prefix > best->dest.prefix)) {
            best = route;
        }
    }
    return best;
}

static bool parse_decimal(const char **text, uint32_t max, uint32_t *value)
{
    const char *cursor = *text;
    if (*cursor < '0' || *cursor > '9') {
        return false;
    }

    // Reject ambiguous octal-looking values such as "010".
    if (*cursor == '0' && cursor[1] >= '0' && cursor[1] <= '9') {
        return false;
    }

    uint32_t parsed = 0;
    do {
        uint32_t digit = (uint32_t)(*cursor - '0');
        // Check the next digit before multiplying, so oversized input cannot overflow.
        if (parsed > max / 10 ||
            (parsed == max / 10 && digit > max % 10)) {
            return false;
        }
        parsed = parsed * 10 + digit;
        cursor++;
    } while (*cursor >= '0' && *cursor <= '9');

    *text = cursor;
    *value = parsed;
    return true;
}

static bool parse_ipv4(const char **text, uint32_t *addr)
{
    const char *cursor = *text;
    uint32_t parsed = 0;

    // Parse exactly four bounded octets and pack them in network-style order.
    for (unsigned int octet_index = 0; octet_index < 4; octet_index++) {
        uint32_t octet;
        if (!parse_decimal(&cursor, UINT8_MAX, &octet)) {
            return false;
        }
        parsed = (parsed << 8) | octet;
        if (octet_index < 3) {
            if (*cursor != '.') {
                return false;
            }
            cursor++;
        }
    }

    *text = cursor;
    *addr = parsed;
    return true;
}

bool ip_parse(const char *text, uint32_t *addr)
{
    if (text == NULL || addr == NULL) {
        return false;
    }

    // Require the whole string to be consumed; only publish a result on success.
    const char *cursor = text;
    uint32_t parsed;
    if (!parse_ipv4(&cursor, &parsed) || *cursor != '\0') {
        return false;
    }

    *addr = parsed;
    return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN])
{
    // Extract the address's four octets from most to least significant.
    snprintf(out, IP_STR_LEN, "%u.%u.%u.%u",
        (unsigned int)((addr >> 24) & UINT32_C(0xff)),
        (unsigned int)((addr >> 16) & UINT32_C(0xff)),
        (unsigned int)((addr >> 8) & UINT32_C(0xff)),
        (unsigned int)(addr & UINT32_C(0xff)));
}

bool cidr_parse(const char *text, cidr_t *block) {
    if(text == NULL || block == NULL) {
        return false;
    }

    const char *cursor = text;
    cidr_t parsed;
    uint32_t prefix;
    // Parse an IPv4 address, then require a slash and a complete 0-32 prefix.
    if (!parse_ipv4(&cursor, &parsed.addr) || *cursor != '/') {
        return false;
    }
    cursor++;
    if (!parse_decimal(&cursor, 32, &prefix) || *cursor != '\0') {
        return false;
    }

    parsed.prefix = (uint8_t)prefix;
    *block = parsed;
    return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN]) {
    char address[IP_STR_LEN];
    ip_format(block.addr, address);
    // Keep formatting consistent with cidr_mask(), which treats larger prefixes as /32.
    unsigned int prefix = block.prefix > 32 ? 32U : block.prefix;
    snprintf(out, CIDR_STR_LEN, "%s/%u", address, prefix);
}

uint32_t cidr_mask(uint8_t prefix)
{
    if (prefix == 0) {
        return 0;
    }
    if (prefix >= 32) {
        return UINT32_MAX;
    }
    // Handle /0 above so the shift count is always between 0 and 31.
    return UINT32_MAX << (32 - prefix);
}

uint32_t cidr_network(cidr_t block)
{
    return block.addr & cidr_mask(block.prefix);
}

uint32_t cidr_broadcast(cidr_t block)
{
    return block.addr | ~cidr_mask(block.prefix);
}

uint32_t cidr_first_host(cidr_t block)
{
    uint32_t network = cidr_network(block);
    // /31 and /32 have no separate network address to skip.
    return block.prefix >= 31 ? network : network + 1;
}

uint32_t cidr_last_host(cidr_t block)
{
    uint32_t broadcast = cidr_broadcast(block);
    // /31 and /32 have no separate broadcast address to skip.
    return block.prefix >= 31 ? broadcast : broadcast - 1;
}

uint64_t cidr_host_count(cidr_t block)
{
    if (block.prefix >= 32) {
        return 1;
    }
    if (block.prefix == 31) {
        return 2;
    }
    // Use 64 bits so the /0 address count (2^32) is representable before subtracting.
    return (UINT64_C(1) << (32 - block.prefix)) - 2;
}

bool cidr_contains(cidr_t block, uint32_t addr)
{
    uint32_t mask = cidr_mask(block.prefix);
    return (addr & mask) == (block.addr & mask);
}

bool cidr_is_network(cidr_t block)
{
    return block.addr == cidr_network(block);
}

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out)
{
    if (out == NULL || block.prefix > 32 || !cidr_is_network(block) ||
        n == 0 || (n & (n - 1)) != 0 || i >= n) {
        return false;
    }

    // A power-of-two subnet count borrows log2(n) bits from the host portion.
    uint8_t subnet_bits = 0;
    for (uint32_t count = n; count > 1; count >>= 1) {
        subnet_bits++;
    }
    uint16_t new_prefix = (uint16_t)block.prefix + subnet_bits;
    if (new_prefix > 32) {
        return false;
    }

    // Keep /0's possible 2^32-address size representable during offset arithmetic.
    uint64_t subnet_size = UINT64_C(1) << (32 - new_prefix);
    uint64_t subnet_addr = (uint64_t)block.addr + subnet_size * i;
    cidr_t subnet = { (uint32_t)subnet_addr, (uint8_t)new_prefix };
    *out = subnet;
    return true;
}
