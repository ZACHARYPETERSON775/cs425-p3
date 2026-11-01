#include "lab.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* @breif Compare the text string against an IP regex.
 *
 * Match against [0-999].[0-999].[0-999].[0-999] then conver
 *
 * @returns true if the text matches the IP regex.
*/
bool ip_regex(const char* text)
{
    int state = 0;
    size_t len = strlen(text);
    char s;
    for(size_t i = 0; i < len; i++) {
        s = text[i];
        switch(state) {
            case 0: // Start State
                state = s == '0' ? 3
                    : isdigit(s) ? 1
                    : -1;
                break;
            case 1:
                state = s == '.' ? 3
                    : isdigit(s) ? 1
                    : -1;
                break;
            case 2:
                state = s == '.' ? 4
                    : isdigit(s) ? 3
                    : -1;
                break;
            case 3:
                state = s == '.' ? 4 
                    : -1;
                break;
            case 4:
                state = s == '0' ? 7
                    : isdigit(s) ? 5 
                    : -1;
                break;
            case 5:
                state = s == '.' ? 8 
                    : isdigit(s) ? 6
                    : -1;
                break;
            case 6:
                state = s == '.' ? 8
                    : isdigit(s) ? 7 
                    : -1;
                break;
            case 7:
                state = s == '.' ? 8 
                    : -1;
                break;
            case 8:
                state = s == '0' ? 11 
                    : isdigit(s) ? 9
                    : -1;
                break;
            case 9:
                state = s == '.' ? 12
                    : isdigit(s) ? 10
                    : -1;
                break;
            case 10:
                state = s == '.' ? 12
                    : isdigit(s) ? 11
                    : -1;
                break;
            case 11:
                state = s == '.' ? 12
                    : -1;
                break;
            case 12:
                state = s == '0' ? 15
                    : isdigit(s) ? 13
                    : -1;
                break;
            case 13: // Accept State
                state = isdigit(s) ? 14
                    : -1;
                break;
            case 14: // Accept State
                state = isdigit(s) ? 15
                    : -1;
                break;
            case 15: // Accept State
                state = -1;
                break;
            default:
                return false;
        }
    }

    return state == 13 || state == 14 || state == 15;
}

bool ip_parse(const char *text, uint32_t *addr)
{
    if(text == NULL) {
        return false;
    }
    if (!ip_regex(text)) {
        return false;
    }
    uint32_t buff[4];
    sscanf(text, "%u.%u.%u.%u", buff, buff+1, buff+2, buff+3);
    if(buff[0] > UINT8_MAX || buff[1] > UINT8_MAX || buff[2] > UINT8_MAX || buff[3] > UINT8_MAX) {
        return false;
    }
    *addr |= buff[0] << 24;
    *addr |= buff[1] << 16;
    *addr |= buff[2] << 8;
    *addr |= buff[3];
    return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN])
{
    snprintf(out, IP_STR_LEN, "%u.%u.%u.%u",
        (addr & 0xFF000000) >> 24,
        (addr & 0x00FF0000) >> 16,
        (addr & 0x0000FF00) >> 8,
        (addr & 0x000000FF));
}

