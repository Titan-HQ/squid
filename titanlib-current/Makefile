CCV := $(shell ${CC} --version | grep 'clang version' | awk -F'clang version' '{print $$2}' | awk '{ print $$1 }' )
CCVMJ := $(shell echo ${CCV} | cut -d "." -f1)
CCVMN := $(shell echo ${CCV} | cut -d "." -f2)

INCLUDE=-I. -I/usr/local/include -I/usr/local/include/postgresql -I/usr/local/include/postgresql/server -I/usr/local/include/glib-2.0/ -I/usr/local/lib/glib-2.0/include/

LIBRARIES = libtitan.a

OBJS = \
	global.o            \
	txal.o              \
	txip.o              \
	md5.o               \
	sha1.o              \
	txencodings.o       \
	txhash.o            \
	edgelib.o           \
	edgepq.o            \
	ctree.o             \
	sock_rw.o           \
	MulKwMap.o          \
	daemonize.o         \
	log.o               \
	titaxtime.o         \
	Extension.o         \
	Category.o          \
	Group.o             \
	Keyword.o           \
	Redirection.o       \
	TitaxConf.o         \
	TitaxUser.o         \
	titaxlib.o          \
	KeywordPolicy.o     \
	TitanUser.o         \
	ttn_tools.o         \
	ttn_groups.o        \
	db_pg.o             \
	tx_flog.o           \
	tx_slog.o           \
	tx_log.o            \
	tx_log_item.o       \
	RequestTask.o       \
	DbListener.o        \
	DbUserRequestTask.o \
	TitanScheduler.o    \
	TitanSynchronizer.o \
	TitanSchedulerAPI.o \
	ttn_cidr.o          \
	ttn_locations.o     \
	ttn_wada.o          \
	TAPE.o              \
	titan_instance_tracker.o

SRCS_C = $(shell ls  *.c *.h | grep -v autotest )

SRCS_CXX = $(shell ls *.cxx *.hxx | grep -v autotest )

.PHONY: clean install lib

libtitan.a: CXXFLAGS+= ${CAPPFLAGS} -std=c++11 -Wno-c++1y-extensions ${INCLUDE}
libtitan.a: CXXFLAGS+= -Wno-zero-length-array
libtitan.a: CFLAGS+= ${CAPPFLAGS} -std=c11 ${INCLUDE}
libtitan.a: $(OBJS)
	ar rcs $@ $^

#production
.HARD=-D_FORTIFY_SOURCE=0 -D_REENTRANT -fPIC -mpopcnt

ifeq ($(shell if [ "$(CCVMJ)" -eq 3 ]; then echo yes; fi),yes)
    #older compilers
    .HARD+= -Wno-thread-safety
endif

ifeq ($(shell if [ "$(CCVMJ)" -lt 6 ]; then echo yes; fi),yes)
    #older compilers
    .HARD+= -Wno-unknown-pragmas
endif

lib: CFLAGS += -O3 -g1 -std=c11 
lib: CFLAGS += -Wall -Werror 
lib: CFLAGS += ${.HARD}
lib: CXXFLAGS += -O3 -g1 -std=c++11 -Wno-c++1y-extensions
lib: CXXFLAGS += -Wall -Werror
lib: CXXFLAGS +=  ${.HARD}
lib: LDFLAGS= -O3 -g1 -D_REENTRANT
lib: ${LIBRARIES}

#if gmake dev is ran the build type will be clean dlib
#if gmake install is ran the build type will be clean lib
LOAD_TYPE := lib

install: all

all: lib
	@/bin/echo "Production build:  ${MAKE} clean $(LOAD_TYPE) <================"
	${MAKE} clean $(LOAD_TYPE)

clean:
	rm -f $(LIBRARIES) *.o $(OBJS)

# How to make an object from a C++ file
%.o: %.cxx
	${CXX} ${CXXFLAGS} -c $< -o $@

%.o: %.cpp
	${CXX} ${CXXFLAGS} -c $< -o $@

%.o: %.cc
	${CXX} ${CXXFLAGS} -c $< -o $@

# How to make an object from a C file
%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@
