CC ?= gcc

TARGETS = utc_ApplicationFW_aul_launch_init_func \
	  utc_ApplicationFW_aul_launch_argv_handler_func \
	  utc_ApplicationFW_aul_launch_app_func \
	  utc_ApplicationFW_aul_open_app_func \
	  utc_ApplicationFW_aul_resume_pid_func \
	  utc_ApplicationFW_aul_terminate_pid_func \
	  utc_ApplicationFW_aul_app_is_running_func \
	  utc_ApplicationFW_aul_app_get_running_app_info_func \
	  utc_ApplicationFW_aul_app_get_pkgname_bypid_func \
	  utc_ApplicationFW_aul_open_file_func \
	  utc_ApplicationFW_aul_open_file_with_mimetype_func \
	  utc_ApplicationFW_aul_open_content_func \
	  utc_ApplicationFW_aul_get_defapp_from_mime_func \
	  utc_ApplicationFW_aul_set_defapp_with_mime_func \
	  utc_ApplicationFW_aul_get_mime_from_file_func \
	  utc_ApplicationFW_aul_get_mime_from_content_func 

PKGS = aul ecore 

LDFLAGS = `pkg-config --libs $(PKGS)`
LDFLAGS += $(TET_ROOT)/lib/tet3/tcm_s.o
LDFLAGS += -L$(TET_ROOT)/lib/tet3 -ltcm_s
LDFLAGS += -L$(TET_ROOT)/lib/tet3 -lapi_s

CFLAGS = -I. `pkg-config --cflags $(PKGS)`
CFLAGS += -I$(TET_ROOT)/inc/tet3
CFLAGS += -Wall

all: $(TARGETS)

$(TARGETS): %: %.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(TARGETS)
