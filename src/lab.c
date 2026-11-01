#include "lab.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Parses a byte value (0-255) from a string.
 * 
 * If the value is parsed, text is set to the character after the number string.
 * 
 * @param text The string to parse.
 * @param val Where to store the parsed value.
 * @return true if text started with a byte (0-255).
 */
bool parse_byte(char **text, uint32_t *val)
{
    char *beg, *end;
    size_t len, i;
    // Check args
    if (text == NULL || *text == NULL || **text == NULL || val == NULL)
    {
        return false;
    }
    // Check for digits
    for (beg = *text, end = strchr(beg, '.'); beg != end; beg++)
    {
        if (!isdigit(*beg))
        {
            return false;
        }
    }
    // Convert to number
    sscanf(*text, "%u", val);
    if (*val > UINT8_MAX)
    {
        return false;
    }
    // Don't go past the ending '\0'
    *text = end;
    return true;
}

bool ip_parse(const char *text, uint32_t *addr)
{
    char *iter = text;
    uint32_t byte[4];
    if (text == NULL ||
        addr == NULL ||
        !parse_byte(iter++, byte + 3) ||
        !parse_byte(iter++, byte + 2) ||
        !parse_byte(iter++, byte + 2) ||
        !parse_byte(iter, byte))
    {
        return false;
    }
    *addr |= byte[3] << 24;
    *addr |= byte[2] << 16;
    *addr |= byte[1] << 8;
    *addr |= byte[0];
    return true;
}