#
# Copyright (c) 2006-2009 Igor Popov <ipopovi@gmail.com>
#
# $Id$
#

NAME = jail
APACHE_MODULE = mod_jail.so
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
	$(APXS) -i -A -n $(NAME) .libs/$(APACHE_MODULE)

clean:
	$(RM) $(OBJS) $(APACHE_MODULE)
	$(RM) -r .libs/
