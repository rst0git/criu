/* Exercise production option parsing and hook timing without a GPU or ptrace. */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "criu-plugin.h"
#include "cuda_device_map.h"
#include "cuda_plugin.h"
#include "fault-injection.h"

enum faults fi_strategy = FI_PLUGIN_CUDA_FORCE_ENABLE;

static char *options[8];
static char log_text[8192];
static unsigned int clock_calls;
static bool clock_failed;
static int backend_result;
static int inventory_result;
static bool inventory_required;

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list args;
	size_t used = strlen(log_text);
	int written;

	(void)loglevel;
	va_start(args, format);
	written = vsnprintf(log_text + used, sizeof(log_text) - used, format, args);
	va_end(args);
	assert(written >= 0 && (size_t)written < sizeof(log_text) - used);
	errno = ECHILD;
}

int __wrap_clock_gettime(clockid_t clock, struct timespec *now)
{
	assert(clock == CLOCK_MONOTONIC);
	if (clock_failed) {
		errno = EIO;
		return -1;
	}
	now->tv_sec = 1;
	now->tv_nsec = ++clock_calls * 1000000;
	errno = EIO;
	return 0;
}

int criu_plugin_get_options(int *argc, char ***argv)
{
	for (*argc = 0; options[*argc]; (*argc)++)
		;
	*argv = options;
	return 0;
}

bool has_inventory_plugin(const char *name)
{
	(void)name;
	return inventory_required;
}

bool check_and_remove_inventory_plugin(const char *name)
{
	(void)name;
	return true;
}

int add_inventory_plugin(const char *name)
{
	(void)name;
	return 0;
}

void set_compel_interrupt_only_mode(void)
{
}

int cuda_device_map_validate(const char *value)
{
	(void)value;
	return 0;
}

int cuda_device_map_resolve(const char *value, struct cuda_device_map *map)
{
	(void)value;
	(void)map;
	return inventory_result;
}

void cuda_device_map_fini(struct cuda_device_map *map)
{
	(void)map;
}

int cuda_gpu_inventory_dump(void)
{
	return inventory_result;
}

int cuda_gpu_inventory_restore_init(void)
{
	return inventory_result;
}

void cuda_gpu_inventory_fini(void)
{
}

static int mock_probe(bool device_map_requested)
{
	(void)device_map_requested;
	return 0;
}

static int mock_operation(int value)
{
	(void)value;
	errno = EACCES;
	return backend_result;
}

static int mock_resume(int pid, const struct cuda_device_map *map)
{
	(void)map;
	return mock_operation(pid);
}

static void mock_fini(int stage, int ret)
{
	(void)stage;
	(void)ret;
}

#define MOCK_BACKEND(label)                           \
	{                                             \
		.name = label,                        \
		.probe = mock_probe,                  \
		.init = mock_operation,               \
		.pause_devices = mock_operation,      \
		.checkpoint_devices = mock_operation, \
		.resume_devices_late = mock_resume,   \
		.dump_finish = mock_operation,        \
		.fini = mock_fini,                    \
	}

const struct cuda_plugin_backend cuda_driver_backend = MOCK_BACKEND("Driver API");
const struct cuda_plugin_backend cuda_cli_backend = MOCK_BACKEND("cuda-checkpoint CLI");

#define CALL_HOOK(hook, ...) \
	((CR_PLUGIN_HOOK__##hook##_t *)CR_PLUGIN_DESC.hooks[CR_PLUGIN_HOOK__##hook])(__VA_ARGS__)

static void check_record(const char *backend, const char *phase, int pid, int ret)
{
	char expected[256];

	snprintf(expected, sizeof(expected),
		 "cuda_plugin: timing backend=%s phase=%s pid=%d ret=%d elapsed_us=1000\n",
		 backend, phase, pid, ret);
	assert(strstr(log_text, expected));
	log_text[0] = '\0';
}

static void test_disabled(char *option)
{
	options[1] = option;
	clock_calls = 0;
	log_text[0] = '\0';
	assert(CR_PLUGIN_DESC.init(CR_PLUGIN_STAGE__PRE_DUMP) == 0);
	assert(CALL_HOOK(PAUSE_DEVICES, 123) == -ENOTSUP);
	CR_PLUGIN_DESC.exit(CR_PLUGIN_STAGE__PRE_DUMP, 0);
	assert(!clock_calls);
	assert(!strstr(log_text, "timing backend="));
}

static void test_backend(char *option, const char *backend)
{
	options[1] = "--cuda_plugin.timings=true";
	options[2] = option;
	log_text[0] = '\0';
	assert(CR_PLUGIN_DESC.init(CR_PLUGIN_STAGE__DUMP) == 0);
	check_record(backend, "init", 0, 0);
	assert(cuda_plugin_add_inventory() == 0);
	backend_result = -ENOTSUP;
	assert(CALL_HOOK(PAUSE_DEVICES, 123) == -ENOTSUP);
	assert(errno == EACCES);
	check_record(backend, "pause_devices", 123, -ENOTSUP);
	backend_result = -EIO;
	assert(CALL_HOOK(CHECKPOINT_DEVICES, 123) == -EIO);
	assert(errno == EACCES);
	check_record(backend, "checkpoint_devices", 123, -EIO);
	backend_result = 0;
	assert(CALL_HOOK(RESUME_DEVICES_LATE, 123) == 0);
	check_record(backend, "resume_devices_late", 123, 0);
	clock_failed = true;
	backend_result = -EIO;
	assert(CALL_HOOK(CHECKPOINT_DEVICES, 123) == -EIO);
	assert(errno == EACCES);
	assert(strstr(log_text, "Unable to read CUDA plugin timing clock"));
	assert(!strstr(log_text, "timing backend="));
	clock_failed = false;
	backend_result = 0;
	log_text[0] = '\0';
	inventory_result = -ENOTSUP;
	assert(CALL_HOOK(DUMP_DEVICES_LATE, 123) == -EIO);
	check_record(backend, "dump_devices_late", 123, -EIO);
	assert(CALL_HOOK(RESTORE_INIT) == -EIO);
	check_record(backend, "restore_init", 0, -EIO);
	inventory_result = 0;
	assert(CALL_HOOK(DUMP_FINISH, 0) == 0);
	check_record(backend, "dump_finish", 0, 0);
	CR_PLUGIN_DESC.exit(CR_PLUGIN_STAGE__DUMP, -EIO);
	check_record(backend, "fini", 0, -EIO);
	options[2] = NULL;
}

int main(void)
{
	char *invalid[] = { "--cuda_plugin.timings", "--cuda_plugin.timings=", "--cuda_plugin.timings=1",
			    "--cuda_plugin.timings=True" };
	size_t i;

	options[0] = "cuda-plugin-test";
	test_disabled(NULL);
	test_disabled("--cuda_plugin.timings=false");
	test_disabled("--cuda_plugin.timing=true");
	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		options[1] = invalid[i];
		assert(CR_PLUGIN_DESC.init(CR_PLUGIN_STAGE__PRE_DUMP) == -EINVAL);
	}
	test_backend("--cuda_plugin.backend=driver-api", "driver-api");
	test_backend("--cuda_plugin.backend=cuda-checkpoint", "cuda-checkpoint");
	options[2] = "--cuda_plugin.backend=driver-api";
	backend_result = -EIO;
	assert(CR_PLUGIN_DESC.init(CR_PLUGIN_STAGE__DUMP) == -EIO);
	check_record("driver-api", "init", 0, -EIO);
	backend_result = 0;
	options[2] = "--cuda_plugin.timings=false";
	test_disabled("--cuda_plugin.timings=true");
	options[2] = NULL;
	options[1] = "--cuda_plugin.timings=true";
	assert(CR_PLUGIN_DESC.init(CR_PLUGIN_STAGE__RESTORE) == 0);
	check_record("none", "init", 0, 0);
	assert(CALL_HOOK(PAUSE_DEVICES, 123) == -ENOTSUP);
	check_record("none", "pause_devices", 123, -ENOTSUP);
	CR_PLUGIN_DESC.exit(CR_PLUGIN_STAGE__RESTORE, 0);
	check_record("none", "fini", 0, 0);
	test_disabled(NULL);
	puts("CUDA plugin timing regression tests PASS");
	return 0;
}
