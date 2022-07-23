/* Header for jnetpcap_utils utility methods */

#ifndef _Included_nio_jbuffer_h
#define _Included_nio_jbuffer_h
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif

#include "export.h"

#if defined(HPUX) || defined(SUNOS) || defined(SOLARIS)
#include <sys/param.h>
#endif

#include <jni.h>

#ifdef __linux__
#include <inttypes.h>
#endif

// Generic MACROS
#ifndef __BYTE_ORDER

// GNU MACROS
#ifdef __BYTE_ORDER__

#define __LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#define __BIG_ENDIAN __ORDER_BIG_ENDIAN__
#define __BYTE_ORDER __BYTE_ORDER__

#else

#define __LITTLE_ENDIAN 1
#define __BIG_ENDIAN 2
#define __BYTE_ORDER __LITTLE_ENDIAN

#endif
#endif

/****************************************************************
 * **************************************************************
 * 
 * JNI IDs
 * 
 * **************************************************************
 ****************************************************************/
extern jfieldID jbufferOrderFID;
extern jfieldID jbufferReadonlyFID;

/****************************************************************
 * **************************************************************
 * 
 * PTR CONVERSION MACROS
 *
 * **************************************************************
 ****************************************************************/

typedef uint64_t nio_uint_ptr;

#define TO_PTR(a)		((void *)((nio_uint_ptr) a))
#define TO_PTRV_VOID(a)	((void *)((nio_uint_ptr) a))

#define TO_PTR_UINT8(a)		((uint8_t *)((nio_uint_ptr) a))
#define TO_PTR_UINT16(a)	((uint16_t *)((nio_uint_ptr) a))
#define TO_PTR_UINT32(a)	((uint32_t *)((nio_uint_ptr) a))
#define TO_PTR_UINT64(a)	((uint64_t *)((nio_uint_ptr) a))

#define TO_PTR_INT8(a)	((int8_t *)((nio_uint_ptr) a))
#define TO_PTR_INT16(a)	((int16_t *)((nio_uint_ptr) a))
#define TO_PTR_INT32(a)	((int32_t *)((nio_uint_ptr) a))
#define TO_PTR_INT64(a)	((int64_t *)((nio_uint_ptr) a))

#define TO_LONG(p)	((uint64_t) p)

/****************************************************************
 * **************************************************************
 *
 * ENDIAN MACROS - swap bytes for proper endianess
 * 
 * **************************************************************
 ****************************************************************/

#define NIO_ALIGN	__attribute__((aligned(8)))
#define NIO_ALIGN8	__attribute__((aligned(1)))
#define NIO_ALIGN16	__attribute__((aligned(2)))
#define NIO_ALIGN32	__attribute__((aligned(4)))
#define NIO_ALIGN64	__attribute__((aligned(8)))
#define NIO_ALIGN_PTR	__attribute__((aligned(sizeof(void *))))

#ifndef offsetof
#define offsetof(t,m) __builtin_offsetof(t, m)
#endif

#define REF_TO_PTR(p) 		((uint8_t *)&(p))
#define REF_TO_LONG(p) 		TO_LONG(p)
#define REF2_TO_PTR(p,m) 	((uint8_t *)(TO_LONG(p) + __builtin_offsetof(typeof(*p), m)))
#define REF2_TO_LONG(p,m) 	(TO_LONG(p) + __builtin_offsetof(typeof(*p), m))

#define IS_INT8_ALIGNED(p)		(TRUE)
#define IS_INT16_ALIGNED(p)		((TO_LONG(p) & 0x0001) == 0)
#define IS_INT32_ALIGNED(p)		((TO_LONG(p) & 0x0003) == 0)
#define IS_INT64_ALIGNED(p)		((TO_LONG(p) & 0x0007) == 0)
#define IS_INT128_ALIGNED(p)	((TO_LONG(p) & 0x000F) == 0)
#define IS_INT256_ALIGNED(p)	((TO_LONG(p) & 0x001F) == 0)
#define IS_INT512_ALIGNED(p)	((TO_LONG(p) & 0x003F) == 0)
#define IS_INT1024_ALIGNED(p)	((TO_LONG(p) & 0x007F) == 0)
#define IS_INT2048_ALIGNED(p)	((TO_LONG(p) & 0x00FF) == 0)
#define IS_INT4096_ALIGNED(p)	((TO_LONG(p) & 0x01FF) == 0)
#define IS_INT9182_ALIGNED(p)	((TO_LONG(p) & 0x03FF) == 0)

#define IS_INT8_ALIGNED2(p,m)		(TRUE)
#define IS_INT16_ALIGNED2(p,m)		((TO_LONG(REF2_TO_PTR(p,m)) & 0x0001) == 0)
#define IS_INT32_ALIGNED2(p,m)		((TO_LONG(REF2_TO_PTR(p,m)) & 0x0003) == 0)
#define IS_INT64_ALIGNED2(p,m)		((TO_LONG(REF2_TO_PTR(p,m)) & 0x0007) == 0)

#define ALIGNMENT_OFFSET2(p,m)		(TO_LONG(REF2_TO_LONG(p,m)) & 0x0007)
#define ALIGNMENT_OFFSET(p)			(TO_LONG(REF_TO_LONG(p)) & 0x0007)

#ifdef __STRICT_ALIGNMENT

#define BIG_ENDIAN8_ALIGNED(p) 	BIG_ENDIAN8_REF(p)
#define BIG_ENDIAN16_ALIGNED(p)	BIG_ENDIAN16_REF(p)
#define BIG_ENDIAN32_ALIGNED(p)	BIG_ENDIAN32_REF(p)
#define BIG_ENDIAN64_ALIGNED(p)	BIG_ENDIAN64_REF(p)

#define LITTLE_ENDIAN8_ALIGNED(p)	LITTLE_ENDIAN8_REF(p)
#define LITTLE_ENDIAN16_ALIGNED(p) 	LITTLE_ENDIAN16_REF(p)
#define LITTLE_ENDIAN32_ALIGNED(p) 	LITTLE_ENDIAN32_REF(p)
#define LITTLE_ENDIAN64_ALIGNED(p) 	LITTLE_ENDIAN64_REF(p)

#else // !__STRICT_ALIGNMENT

#define BIG_ENDIAN8_ALIGNED(p) 	BIG_ENDIAN8(p)
#define BIG_ENDIAN16_ALIGNED(p)	BIG_ENDIAN16(p)
#define BIG_ENDIAN32_ALIGNED(p)	BIG_ENDIAN32(p)
#define BIG_ENDIAN64_ALIGNED(p)	BIG_ENDIAN64(p)

#define LITTLE_ENDIAN8_ALIGNED(p)	LITTLE_ENDIAN8(p)
#define LITTLE_ENDIAN16_ALIGNED(p) 	LITTLE_ENDIAN16(p)
#define LITTLE_ENDIAN32_ALIGNED(p) 	LITTLE_ENDIAN32(p)
#define LITTLE_ENDIAN64_ALIGNED(p) 	LITTLE_ENDIAN64(p)

#endif // __STRICT_ALIGNMENT

#define BIG_ENDIAN8_REF(p) 		BIG_ENDIAN8_GET(REF_TO_PTR(p))
#define BIG_ENDIAN16_REF(p) 	BIG_ENDIAN16_GET(REF_TO_PTR(p))
#define BIG_ENDIAN32_REF(p) 	BIG_ENDIAN32_GET(REF_TO_PTR(p))
#define BIG_ENDIAN64_REF(p) 	BIG_ENDIAN64_GET(REF_TO_PTR(p))

#define LITTLE_ENDIAN8_REF(p) 	LITTLE_ENDIAN8_GET(REF_TO_PTR(p))
#define LITTLE_ENDIAN16_REF(p) 	LITTLE_ENDIAN16_GET(REF_TO_PTR(p))
#define LITTLE_ENDIAN32_REF(p) 	LITTLE_ENDIAN32_GET(REF_TO_PTR(p))
#define LITTLE_ENDIAN64_REF(p)	LITTLE_ENDIAN64_GET(REF_TO_PTR(p))

#define BIG_ENDIAN8_REF2(p,m) 	BIG_ENDIAN8_GET(REF2_TO_PTR(p,m))
#define BIG_ENDIAN16_REF2(p,m) 	BIG_ENDIAN16_GET(REF2_TO_PTR(p,m))
#define BIG_ENDIAN32_REF2(p,m) 	BIG_ENDIAN32_GET(REF2_TO_PTR(p,m))
#define BIG_ENDIAN64_REF2(p,m) 	BIG_ENDIAN64_GET(REF2_TO_PTR(p,m))

#define LITTLE_ENDIAN8_REF2(p,m) 	LITTLE_ENDIAN8_GET(REF2_TO_PTR(p,m))
#define LITTLE_ENDIAN16_REF2(p,m) 	LITTLE_ENDIAN16_GET(REF2_TO_PTR(p,m))
#define LITTLE_ENDIAN32_REF2(p,m) 	LITTLE_ENDIAN32_GET(REF2_TO_PTR(p,m))
#define LITTLE_ENDIAN64_REF2(p,m)	LITTLE_ENDIAN64_GET(REF2_TO_PTR(p,m))

#define BIG_ENDIAN8_GET(p) \
	((uint8_t)((uint8_t *)p)[0])


#define BIG_ENDIAN16_GET(p) \
	(((uint16_t)((uint8_t *)p)[0]) << 8L) | \
	(((uint16_t)((uint8_t *)p)[1]) << 0L)


#define BIG_ENDIAN32_GET(p) \
	(((uint32_t)((uint8_t *)p)[0]) << 24L) | \
	(((uint32_t)((uint8_t *)p)[1]) << 16L) | \
	(((uint32_t)((uint8_t *)p)[2]) << 8L)  | \
	(((uint32_t)((uint8_t *)p)[3]) << 0L)


#define BIG_ENDIAN64_GET(p) \
	(((uint64_t)((uint8_t *)p)[0]) << 56L) | \
	(((uint64_t)((uint8_t *)p)[1]) << 48L) | \
	(((uint64_t)((uint8_t *)p)[2]) << 40L) | \
	(((uint64_t)((uint8_t *)p)[3]) << 32L) | \
	(((uint64_t)((uint8_t *)p)[4]) << 24L) | \
	(((uint64_t)((uint8_t *)p)[5]) << 16L) | \
	(((uint64_t)((uint8_t *)p)[6]) << 8L)  | \
	(((uint64_t)((uint8_t *)p)[7]) << 0L)

#define LITTLE_ENDIAN8_GET(p) \
	((uint8_t)((uint8_t *)p)[0])

#define LITTLE_ENDIAN16_GET(p) \
	(((uint16_t)((uint8_t *)p)[1]) << 8L) | \
	(((uint16_t)((uint8_t *)p)[0]) << 0L)

#define LITTLE_ENDIAN32_GET(p) \
	(((uint32_t)((uint8_t *)p)[3]) << 24L) | \
	(((uint32_t)((uint8_t *)p)[2]) << 16L) | \
	(((uint32_t)((uint8_t *)p)[1]) << 8L)  | \
	(((uint32_t)((uint8_t *)p)[0]) << 0L)

#define LITTLE_ENDIAN64_GET(p) \
	(((uint64_t)((uint8_t *)p)[7]) << 56L) | \
	(((uint64_t)((uint8_t *)p)[6]) << 48L) | \
	(((uint64_t)((uint8_t *)p)[5]) << 40L) | \
	(((uint64_t)((uint8_t *)p)[4]) << 32L) | \
	(((uint64_t)((uint8_t *)p)[3]) << 24L) | \
	(((uint64_t)((uint8_t *)p)[2]) << 16L) | \
	(((uint64_t)((uint8_t *)p)[1]) << 8L)  | \
	(((uint64_t)((uint8_t *)p)[0]) << 0L)

#if __BYTE_ORDER == __LITTLE_ENDIAN

#define NATIVE_ENDIAN8_GET(p)	LITTLE_ENDIAN8_GET(p)
#define NATIVE_ENDIAN16_GET(p)	LITTLE_ENDIAN16_GET(p)
#define NATIVE_ENDIAN32_GET(p)	LITTLE_ENDIAN32_GET(p)
#define NATIVE_ENDIAN64_GET(p)	LITTLE_ENDIAN64_GET(p)

#else

#define NATIVE_ENDIAN8_GET(p)	BIG_ENDIAN8_GET(p)
#define NATIVE_ENDIAN16_GET(p)	BIG_ENDIAN16_GET(p)
#define NATIVE_ENDIAN32_GET(p)	BIG_ENDIAN32_GET(p)
#define NATIVE_ENDIAN64_GET(p)	BIG_ENDIAN64_GET(p)

#endif

#define ENDIAN16_GET_UNALIGNED(big, p) \
	((big == JNI_TRUE) ? BIG_ENDIAN16_GET(p) : LITTLE_ENDIAN16_GET(p))

#define ENDIAN32_GET_UNALIGNED(big, p) \
	((big == JNI_TRUE) ? BIG_ENDIAN32_GET(p) : LITTLE_ENDIAN32_GET(p))

#define ENDIAN64_GET_UNALIGNED(big, p) \
		((big == JNI_TRUE) ? BIG_ENDIAN64_GET(p) : LITTLE_ENDIAN64_GET(p))


#define ENDIAN16_ATOM_SWAP(data) (\
	((((uint16_t)data) >> 8)  & 0x00FF) | ((((uint16_t)data) << 8) &  0xFF00))

#define ENDIAN32_ATOM_SWAP(data) (\
	( (((uint32_t)data) >> 24) & 0x000000FF) | ((((uint32_t)data) >> 8)   & 0x0000FF00) |\
	( (((uint32_t)data) << 8)  &  0x00FF0000) | ((((uint32_t)data) << 24) & 0xFF000000))

#define ENDIAN64_ATOM_SWAP(data) (\
	( (((uint64_t)data) >> 56) & 0x00000000000000FFLLU) | ((((uint64_t)data) >> 40) & 0x000000000000FF00LLU) |\
	( (((uint64_t)data) >> 24) & 0x0000000000FF0000LLU) | ((((uint64_t)data) >> 8)  & 0x00000000FF000000LLU) |\
	( (((uint64_t)data) << 8)  & 0x000000FF00000000LLU) | ((((uint64_t)data) << 24) & 0x0000FF0000000000LLU) |\
	( (((uint64_t)data) << 40) & 0x00FF000000000000LLU) | ((((uint64_t)data) << 56) & 0xFF00000000000000LLU) \
	)

#define ENDIAN16_PTR_SWAP(data) \
	((uint16_t)*(data + 0) << 8) | ((uint16_t)*(data + 1))

#define ENDIAN32_PTR_SWAP(data) \
	((uint32_t)*(data + 0) << 24) | ((uint32_t)*(data + 3)     ) |\
	((uint32_t)*(data + 1) << 16) | ((uint32_t)*(data + 2) << 8)

#define ENDIAN64_PTR_SWAP(data) \
	((uint64_t)*(data + 0) << 56) | ((uint64_t)*(data + 7)      ) |\
	((uint64_t)*(data + 1) << 48) | ((uint64_t)*(data + 6) <<  8) |\
	((uint64_t)*(data + 2) << 40) | ((uint64_t)*(data + 5) << 16) |\
	((uint64_t)*(data + 3) << 32) | ((uint64_t)*(data + 4) << 24)

/*
 * These macros test for requested BIG ENDIAN condition and appropriately define
 * the correct byte swap macro for various CPU ENDIAN platforms.
 * 
 * Usage - if cond is TRUE will ensure that BIG_ENDIAN is returned on both 
 * LITTLE AND BIG platforms. If cond is FALSE then LITTLE_ENDIAN will be 
 * returned.
 */
#if __BYTE_ORDER == __LITTLE_ENDIAN

#define BIG_ENDIAN16(data)	ENDIAN16_ATOM_SWAP(data)
#define BIG_ENDIAN32(data)	ENDIAN32_ATOM_SWAP(data)
#define BIG_ENDIAN64(data)	ENDIAN64_ATOM_SWAP(data)

#define LITTLE_ENDIAN16(data)	data
#define LITTLE_ENDIAN32(data)	data
#define LITTLE_ENDIAN64(data)	data

#define ENDIANESS_LABEL	"__LITTLE_ENDIAN"

#elif __BYTE_ORDER == __BIG_ENDIAN

#define BIG_ENDIAN16(data)	data
#define BIG_ENDIAN32(data)	data
#define BIG_ENDIAN64(data)	data

#define LITTLE_ENDIAN16(data)	ENDIAN16_ATOM_SWAP(data)
#define LITTLE_ENDIAN32(data)	ENDIAN32_ATOM_SWAP(data)
#define LITTLE_ENDIAN64(data)	ENDIAN64_ATOM_SWAP(data)

#define ENDIANESS_LABEL	"__BIG_ENDIAN"

#else
# error "ENDIAN MACROS NOT DEFINED :("
#endif

#define ENDIAN16_GET(big, data) \
	((big == JNI_TRUE)?BIG_ENDIAN16(data):LITTLE_ENDIAN16(data))

#define ENDIAN32_GET(big, data) \
	((big == JNI_TRUE)?BIG_ENDIAN32(data):LITTLE_ENDIAN32(data))

#define ENDIAN64_GET(big, data) \
	((big == JNI_TRUE)?BIG_ENDIAN64(data):LITTLE_ENDIAN64(data))


#ifdef __STRICT_ALIGNMENT

#define INT8_GET(p) (IS_INT8_ALIGNED(p) ? (*(int8_t *)p) : NATIVE_ENDIAN8_GET(p))
#define INT16_GET(p) (IS_INT16_ALIGNED(p) ? (*(int16_t *)p) : NATIVE_ENDIAN16_GET(p))
#define INT32_GET(p) (IS_INT32_ALIGNED(p) ? (*(int32_t *)p) : NATIVE_ENDIAN32_GET(p))
#define INT64_GET(p) (IS_INT64_ALIGNED(p) ? (*(int64_t *)p) : NATIVE_ENDIAN64_GET(p))

#define UINT8_GET(p) (IS_INT8_ALIGNED(p) ? (*(uint8_t *)p) : NATIVE_ENDIAN8_GET(p))
#define UINT16_GET(p) (IS_INT16_ALIGNED(p) ? (*(uint16_t *)p) : NATIVE_ENDIAN16_GET(p))
#define UINT32_GET(p) (IS_INT32_ALIGNED(p) ? (*(uint32_t *)p) : NATIVE_ENDIAN32_GET(p))
#define UINT64_GET(p) (IS_INT64_ALIGNED(p) ? (*(uint64_t *)p) : NATIVE_ENDIAN64_GET(p))

#define INT8_GETA(a) (IS_INT8_ALIGNED(a) ? (*TO_PTR_INT8(a)) : NATIVE_ENDIAN8_GET(TO_PTR(a)))
#define INT16_GETA(a) (IS_INT16_ALIGNED(a) ? (*TO_PTR_INT16(a)) : NATIVE_ENDIAN16_GET(TO_PTR(a)))
#define INT32_GETA(a) (IS_INT32_ALIGNED(a) ? (*TO_PTR_INT32(a)) : NATIVE_ENDIAN32_GET(TO_PTR(a)))
#define INT64_GETA(a) (IS_INT64_ALIGNED(a) ? (*TO_PTR_INT64(a)) : NATIVE_ENDIAN64_GET(TO_PTR(a)))

#define UINT8_GETA(a) (IS_INT8_ALIGNED(a) ? (*TO_PTR_UINT8(a)) : NATIVE_ENDIAN8_GET(TO_PTR(a)))
#define UINT16_GETA(a) (IS_INT16_ALIGNED(a) ? (*TO_PTR_UINT16(a)) : NATIVE_ENDIAN16_GET(TO_PTR(a)))
#define UINT32_GETA(a) (IS_INT32_ALIGNED(a) ? (*TO_PTR_UINT32(a)) : NATIVE_ENDIAN32_GET(TO_PTR(a)))
#define UINT64_GETA(a) (IS_INT64_ALIGNED(a) ? (*TO_PTR_UINT64(a)) : NATIVE_ENDIAN64_GET(TO_PTR(a)))

#else // !__STRICT_ALIGNMENT

#define INT8_GET(p) (*(int8_t *)p)
#define INT16_GET(p) (*(int16_t *)p)
#define INT32_GET(p) (*(int32_t *)p)
#define INT64_GET(p) (*(int64_t *)p)

#define UINT8_GET(p) (*(uint8_t *)p)
#define UINT16_GET(p) (*(uint16_t *)p)
#define UINT32_GET(p) (*(uint32_t *)p)
#define UINT64_GET(p) (*(uint64_t *)p)

#define INT8_GETA(a) (*TO_PTR_INT8(a))
#define INT16_GETA(a) (*TO_PTR_INT16(a))
#define INT32_GETA(a) (*TO_PTR_INT32(a))
#define INT64_GETA(a) (*TO_PTR_INT64(a))

#define UINT8_GETA(a) (*TO_PTR_UINT8(a))
#define UINT16_GETA(a) (*TO_PTR_UINT16(a))
#define UINT32_GETA(a) (*TO_PTR_UINT32(a))
#define UINT64_GETA(a) (*TO_PTR_UINT64(a))

#endif // __STRICT_ALIGNMENT


#ifdef __cplusplus
}
#endif
#endif
