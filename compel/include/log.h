#ifndef COMPEL_LOG_H__
#define COMPEL_LOG_H__

#include "uapi/compel/compel.h"
#include "uapi/compel/loglevels.h"
#include "../flog/include/flog.h"

#ifndef LOG_PREFIX
# define LOG_PREFIX
#endif


static inline int pr_quelled(unsigned int loglevel)
{
	return compel_log_get_loglevel() < loglevel
		&& loglevel != COMPEL_LOG_MSG;
}

extern void compel_print_on_level_msg(unsigned int loglevel,
		unsigned int nargs, const char *format, unsigned int mask, ...)
		__attribute__ ((__format__ (__printf__, 3, 5)));


#define pr_msg(fmt, ...)											\
	compel_print_on_level_msg(COMPEL_LOG_MSG,						\
						  FLOG_PP_NARG(VA_ARGS),					\
						  fmt, 										\
						  FLOG_GENMASK(flog_genbit, ##__VA_ARGS__),	\
						  ##__VA_ARGS__)

#define pr_info(fmt, ...)	 										\
	compel_print_on_level_msg(COMPEL_LOG_INFO,						\
						  FLOG_PP_NARG(VA_ARGS),					\
						  LOG_PREFIX fmt, 							\
						  FLOG_GENMASK(flog_genbit, ##__VA_ARGS__),	\
						  ##__VA_ARGS__)

#define pr_err(fmt, ...)											\
	compel_print_on_level_msg(COMPEL_LOG_ERROR,						\
						  FLOG_PP_NARG(VA_ARGS),					\
						  "Error (%s:%d): " LOG_PREFIX fmt,			\
						  FLOG_GENMASK(flog_genbit, ##__VA_ARGS__),	\
						  __FILE__,									\
						  __LINE__,									\
						  ##__VA_ARGS__)

#define pr_err_once(fmt, ...)										\
	do {															\
		static bool __printed;										\
		if (!__printed) {											\
			pr_err(fmt, ##__VA_ARGS__);								\
			__printed = 1;											\
		}															\
	} while (0)

#define pr_warn(fmt, ...)											\
	compel_print_on_level_msg(COMPEL_LOG_WARN,						\
						  FLOG_PP_NARG(VA_ARGS),					\
						  "Warn  (%s:%d): " LOG_PREFIX fmt,			\
						  FLOG_GENMASK(flog_genbit, ##__VA_ARGS__),	\
						  __FILE__,									\
						  __LINE__,									\
						  ##__VA_ARGS__)

#define pr_warn_once(fmt, ...)										\
	do {															\
		static bool __printed;										\
		if (!__printed) {											\
			pr_warn(fmt, ##__VA_ARGS__);							\
			__printed = 1;											\
		}															\
	} while (0)

#define pr_debug(fmt, ...)											\
	compel_print_on_level_msg(COMPEL_LOG_DEBUG,						\
						  FLOG_PP_NARG(VA_ARGS),					\
						  LOG_PREFIX fmt,							\
						  FLOG_GENMASK(flog_genbit, ##__VA_ARGS__),	\
						  ##__VA_ARGS__)

#define pr_perror(fmt, ...)											\
	pr_err(fmt ": %m\n", ##__VA_ARGS__)

#endif /* COMPEL_LOG_H__ */
