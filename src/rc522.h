/* Minimal MFRC522 driver: detect a Mifare card, read its 4-byte UID, halt it. NON-SECURE world. */
#ifndef RC522_H
#define RC522_H
#include <stdint.h>
#include <stdbool.h>
bool    rc522_init(void);          /* false if the chip does not answer on SPI */
uint8_t rc522_version(void);       /* VersionReg: 0x91/0x92 genuine, others are clones */
bool    rc522_alive(void);         /* chip answers and the antenna is still on (false after a supply glitch reset it) */
bool    rc522_wupa(void);          /* true if any card in the field answers (also wakes halted cards) */
bool    rc522_read_uid4(uint8_t uid[4]);   /* anticollision + select; false on error or 7/10-byte UID */
void    rc522_halt(void);
#endif
