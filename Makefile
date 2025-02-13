#
# Copyright (c) 2006-2025 Igor Popov <ipopovi@gmail.com>
#
# $Id$
#

NAME = jail
APACHE_MODULE = mod_jail.so
MODULE_LA = $(APACHE_MODULE:%.so=%.la)
APXS = apxs

SRCS = mod_jail.c
OBJS = mod_jail.o

RM = rm -f
LN = ln -sf
CP = cp -f

CFLAGS =  -Wc,-W -Wc,-Wall
#CFLAGS += -DNDEBUG
CFLAGS +=  -DDEBUG

LDFLAGS = 

default: all

all: $(APACHE_MODULE)

$(APACHE_MODULE): $(SRCS)
	$(APXS) -c $(CFLAGS) $(LDFLAGS) $(SRCS)

install: all
	$(APXS) -i -a -n $(NAME) $(MODULE_LA)

clean:
	$(RM) $(OBJS) $(APACHE_MODULE) $(MODULE_LA) mod_jail.lo mod_jail.slo
	$(RM) -r .libs/
