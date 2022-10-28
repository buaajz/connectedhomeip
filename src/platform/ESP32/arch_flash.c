/*******************************************************************************
  Filename:       arch_flash.c
  Description:    This file contains the ESP flash API wrappers
*******************************************************************************/

#include "arch_flash.h"

char * strrstr_with_size(const char * s1, size_t s1_size, const char * s2)
{
    if (s1 && *s1 && s2 && *s2)
    {
        char * s1_r   = (char *) (s1 + s1_size - 1);
        size_t s2_len = strlen(s2);
        while (s1_r >= s1)
        {
            if (0 == strncmp(s1_r, s2, s2_len))
                return s1_r;
            s1_r--;
        }
    }

    return NULL;
}

int findCertBeginIndex(uint8_t * imageExtBuffer, size_t imageExtBufferSize, uint8_t ** cert_begin_index)
{
    uint8_t * cert_start = NULL;
    cert_start = (uint8_t *) strrstr_with_size((char *) imageExtBuffer, imageExtBufferSize, (char *) OTA_IMAGE_CERT_START);
    if (NULL != cert_start)
    {
        *cert_begin_index = cert_start;
        return MIIO_OK;
    }
    return MIIO_ERROR;
}

int findCertEndIndex(uint8_t * imageExtBuffer, size_t imageExtBufferSize, uint8_t ** cert_end_index, uint8_t ** sign_start_index)
{
    uint8_t * cert_end;
    cert_end = (uint8_t *) strrstr_with_size((char *) imageExtBuffer, imageExtBufferSize, (char *) OTA_IMAGE_CERT_END);
    if (NULL != cert_end)
    {
        cert_end += strlen(OTA_IMAGE_CERT_END);
    }
    else
    {
        return MIIO_ERROR;
    }

    if (*cert_end == ' ')
        cert_end++;
    if (*cert_end == '\r')
        cert_end++;
    if (*cert_end == '\n')
        cert_end++;

    uint8_t * start = imageExtBuffer + imageExtBufferSize + 1;
    while (start > cert_end)
    {
        *start = *(start - 1);
        start--;
    }
    *cert_end = '\0';

    *cert_end_index   = cert_end;
    *sign_start_index = cert_end + 1;

    return MIIO_OK;
}
