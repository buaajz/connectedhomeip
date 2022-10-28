
/*******************************************************************************
  Filename:       arch_flash.h
  Description:    This file contains the arch flash API definitions and prototypes.
*******************************************************************************/

#ifndef __ARCH_FLASH_H__
#define __ARCH_FLASH_H__

#include <stdlib.h>
#include <string.h>


#ifdef __cplusplus
extern "C" {
#endif

/*********************************************************************
 * INCLUDES
 */

/*********************************************************************
 * CONSTANTS
 */

#define OTA_IMAGE_CERT_START "-----BEGIN CERTIFICATE-----"
#define OTA_IMAGE_CERT_END "-----END CERTIFICATE-----"
#define MIIO_OK							0					/* There is no error 						*/
#define MIIO_ERROR						(-1)				/* A generic error happens                  */

// ---------------- Math -----------------
#ifndef MIN
#define MIN(a,b)						((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a,b)						((a) > (b) ? (a) : (b))
#endif

int findCertBeginIndex(uint8_t * imageExtBuffer, size_t imageExtBufferSize, uint8_t ** cert_begin_index);
int findCertEndIndex(uint8_t * imageExtBuffer, size_t imageExtBufferSize, uint8_t ** cert_end_index, uint8_t ** sign_start_index);

#ifdef __cplusplus
}
#endif

#endif /* __ARCH_FLASH_H__ */
