#include "lab.h"
#include <stdio.h>

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
