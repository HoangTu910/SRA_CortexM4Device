//#define ASCON_PRINT_STATE
//
//#ifdef ASCON_PRINT_STATE
//
//#include "printstate.h"
//#include "ascon.h"
//
//#ifndef WORDTOU64
//#define WORDTOU64
//#endif
//
//#ifndef U64LE
//#define U64LE
//#endif
//
//// Print a string using PLAT_LOG_D
//void print(const char* text) {
//    PLAT_LOG_D("%s", text);
//}
//
//// Print bytes in hexadecimal format using PLAT_LOG_D
//void printbytes(const char* text, const uint8_t* b, uint64_t len) {
//    char buffer[256]; // Adjust size as needed
//    size_t offset = snprintf(buffer, sizeof(buffer), "%s[%" PRIu64 "]\t= {", text, len);
//    for (uint64_t i = 0; i < len && offset < sizeof(buffer) - 3; ++i) {
//        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "0x%02X%s", b[i], i < len - 1 ? ", " : "");
//    }
//    snprintf(buffer + offset, sizeof(buffer) - offset, "}");
//    PLAT_LOG_D("%s", buffer);
//}
//
//// Print a 64-bit word in hexadecimal format using PLAT_LOG_D
//void printword(const char* text, const uint64_t x) {
//    PLAT_LOG_D("%s=0x%016" PRIx64, text, U64LE(WORDTOU64(x)));
//}
//
//// Print the Ascon state using PLAT_LOG_D
//void printstate(const char* text, const ascon_state_t* s) {
//    char buffer[256]; // Adjust size as needed
//    size_t offset = snprintf(buffer, sizeof(buffer), "%s:", text);
//    for (int i = strlen(text); i < 17; ++i) {
//        offset += snprintf(buffer + offset, sizeof(buffer) - offset, " ");
//    }
//
//    // Print each state word
//    offset += snprintf(buffer + offset, sizeof(buffer) - offset, " x0=0x%016" PRIx64, U64LE(WORDTOU64(s->x[0])));
//    offset += snprintf(buffer + offset, sizeof(buffer) - offset, " x1=0x%016" PRIx64, U64LE(WORDTOU64(s->x[1])));
//    offset += snprintf(buffer + offset, sizeof(buffer) - offset, " x2=0x%016" PRIx64, U64LE(WORDTOU64(s->x[2])));
//    offset += snprintf(buffer + offset, sizeof(buffer) - offset, " x3=0x%016" PRIx64, U64LE(WORDTOU64(s->x[3])));
//    offset += snprintf(buffer + offset, sizeof(buffer) - offset, " x4=0x%016" PRIx64, U64LE(WORDTOU64(s->x[4])));
//
//#ifdef ASCON_PRINT_BI
//    // Print additional state information if needed
//    offset += snprintf(buffer + offset, sizeof(buffer) - offset, " x0=%08x_%08x", s->w[0][1], s->w[0][0]);
//    offset += snprintf(buffer + offset, sizeof(buffer) - offset, " x1=%08x_%08x", s->w[1][1], s->w[1][0]);
//    offset += snprintf(buffer + offset, sizeof(buffer) - offset, " x2=%08x_%08x", s->w[2][1], s->w[2][0]);
//    offset += snprintf(buffer + offset, sizeof(buffer) - offset, " x3=%08x_%08x", s->w[3][1], s->w[3][0]);
//    offset += snprintf(buffer + offset, sizeof(buffer) - offset, " x4=%08x_%08x", s->w[4][1], s->w[4][0]);
//#endif
//
//    PLAT_LOG_D("%s", buffer);
//}
//
//// Print bytes in hexadecimal format using PLAT_LOG_D
//void print_bytes(const char* label, const unsigned char* data, size_t len) {
//    char buffer[256]; // Adjust size as needed
//    size_t offset = snprintf(buffer, sizeof(buffer), "%s: ", label);
//    for (size_t i = 0; i < len && offset < sizeof(buffer) - 3; i++) {
//        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "%02X", data[i]);
//    }
//    PLAT_LOG_D("%s", buffer);
//}
//
//#endif
