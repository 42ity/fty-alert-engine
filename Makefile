#!/bin/bash

SRC= \
  src/alert_agent.cc \
  src/metricinfo.h \
  src/metriclist.cc \
  src/rule.h \
  src/purealert.h \
  src/normalrule.h \
  src/thresholdrule.h \
  src/thresholdrulesimple.h \
  src/regexrule.h

alert-generator: $(SRC)
	g++  -std=c++11 -D_GNU_SOURCE -g -I./include $(SRC) -lbiosproto -lmlm -lczmq -llua -lcxxtools -o alert-generator
