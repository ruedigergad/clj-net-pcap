/***************************************************************************
 * Copyright (C) 2007, Sly Technologies, Inc                               *
 * Distributed under the Lesser GNU Public License  (LGPL)                 *
 ***************************************************************************/

/*
 * Utility file that provides various conversion methods for chaging objects
 * back and forth between C and Java JNI.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/******
 ** Temporarily backed out of C++
 *
#include <cstdarg> // C++ declares varargs here
 ******/

#ifndef WIN32
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#endif /*WIN32*/

#include "util_debug.h"

/*
 * Some debug functionality
 */
const char *indent_template = "                            ";
char indent_buffer[1024] = {'\0'};
int indent = 0;
char indent_char = DEFAULT_INDENT_CHAR;

int debug_level = DEFAULT_LEVEL;

int  debug_get_level() {
	return debug_level;
}

void debug_set_level(int level) {
	debug_level = level;
}

void debug_inc() {
//	printf("debug_inc() - index=%d buf=%s\n", indent, indent_buffer);
	if (indent < DEBUG_MAX_LEVEL) { // Safety check
		indent_buffer[indent] = indent_char;
		indent_buffer[++indent] = '\0';
	} else {
		indent_buffer[indent + 0] = '>'; // Indicates too many levels
		indent_buffer[indent + 1] = '\0';
	}
}

void debug_dec() {
//	printf("debug_dec) - index=%d buf=%s\n", indent, indent_buffer);
	if (indent > 0) { // Safety check
		indent_buffer[--indent] = '\0';
	} else {
		indent_buffer[indent + 0] = '<'; // Indicates below min level
		indent_buffer[indent + 1 ] = '\0';
		
	}
}

void debug_reset() {
	indent = 0;	
	indent_buffer[indent] = '\0';
	
}

char *debug_indent() {	
	return indent_buffer;
}

void debug_vmsg(const char *type, const char *msg, const char *fmt, va_list ap) {
	char buf[1024];
		
	vsprintf(buf, fmt, ap);
	printf("%s%-20s%s: "
			"%s"
			"\n",
			type, msg, debug_indent(),
			buf);
	
	fflush(stdout);
}

void debug_msg(const char *type, const char *msg, const char *fmt, ...) {
	
	va_list ap;
	va_start(ap, fmt);

	debug_vmsg("", msg, fmt, ap);

	va_end(ap);
}

void debug_trace(const char *msg, const char *fmt, ...) {
	if (debug_level < DEBUG_TRACE) {
		return;
	}
	
	va_list ap;
	va_start(ap, fmt);
	
	debug_vmsg("[TRACE]", msg, fmt, ap);
	
	va_end(ap);
}

void debug_warn(const char *msg, const char *fmt, ...) {
	if (debug_level < DEBUG_WARN) {
		return;
	}
	
	va_list ap;
	va_start(ap, fmt);
	
	debug_vmsg("[WARN ]", msg, fmt, ap);
	
	va_end(ap);
}

void debug_error(const char *msg, const char *fmt, ...) {
	if (debug_level < DEBUG_ERROR) {
		return;
	}
	
	va_list ap;
	va_start(ap, fmt);
	
	debug_vmsg("[ERROR]", msg, fmt, ap);
	
	va_end(ap);
}

void debug_info(const char *msg, const char *fmt, ...) {
	if (debug_level < DEBUG_INFO) {
		return;
	}
	
	va_list ap;
	va_start(ap, fmt);
	
	debug_vmsg("[INFO]", msg, fmt, ap);
	
	va_end(ap);
}

void debug_enter(const char *method) {
	debug_inc();
	debug_trace("enter", ">>> %s() >>>", method);
}

void debug_exit(const char *method) {
	debug_trace("exit", "<<< %s() <<<", method);
	debug_dec();
}



/******
 ** Temporarily backed out of C++
 *


Debug Debug::global_logger("global", ERR);
Debug Debug::null_logger("global", NONE);

Debug::Debug(const char *name, Level defaultLevel) {
	reset();
	indentChar = DEFAULT_INDENT_CHAR;
	level = defaultLevel;
	Debug::parent = NULL;
	
	strcpy(Debug::name, name);
}


Debug::Debug(const char *name, Debug *parent) {
	reset();
	indentChar = DEFAULT_INDENT_CHAR;
	level = UNDEFINED;
	Debug::parent = parent;
	
	strcpy(Debug::name, name);
}


Debug::Debug(const char *name) {
	reset();
	indentChar = DEFAULT_INDENT_CHAR;
	level = ERR;
	Debug::parent = &global_logger;
	strcpy(Debug::name, name);
}

void Debug::inc() {
	
	if (parent != NULL) {
		parent->inc();
		return;
	}
	
	if (indentation < DEBUG_MAX_LEVEL) { // Safety check
		indentBuffer[indentation] = indentChar;
		indentBuffer[++indentation] = '\0';
	} else {
		indentBuffer[indentation - 1] = '>'; // Indicates too many levels
		indentBuffer[indentation - 0] = '\0';
	}
}

void Debug::dec() {
	
	if (parent != NULL) {
		parent->dec();
		return;
	}

	if (indentation > 0) { // Safety check
		indentBuffer[--indentation] = '\0';
	} else {
		indentBuffer[indentation + 0] = '<'; // Indicates below min level
		indentBuffer[indentation + 1 ] = '\0';
	}
}

void Debug::reset() {
	if (parent != NULL) {
		parent->reset();
		return;
	}

	indentation = 0;	
	indentBuffer[indentation] = '\0';
}

Debug::Level Debug::getLevel() {
	if (level == UNDEFINED && parent != NULL) {
		return parent->getLevel();
	} else {
		return level;
	}
}

void Debug::setLevel(Level newLevel) {
	level = newLevel;
}

char *Debug::indent() {
	return indentBuffer;
}

char *Debug::levelNames[] = {
		"TRACE",
		"INFO",
		"WARN",
		"ERROR"
};

char *Debug::getLevelName(Level level) {
	return levelNames[level];
}

void Debug::msg(Level type, char *msg, char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);

	vmsg(type, msg, fmt, ap);

	va_end(ap);
}

void Debug::vmsg(Level type, char *msg, char *fmt, va_list ap) {
	char buf[1024];
		
	vsprintf(buf, fmt, ap);
	printf("[%-5s]%-20s%s: "
			"%s"
			"\n",
			getLevelName(type), msg, indent(),
			buf);
	
	fflush(stdout);
}

void Debug::trace(char *msg, char *fmt, ...) {
	if (getLevel() < TRACE) {
		return;
	}
	
	va_list ap;
	va_start(ap, fmt);
	
	vmsg(TRACE, msg, fmt, ap);
	
	va_end(ap);	
}

void Debug::info(char *msg, char *fmt, ...) {
	if (getLevel() < INFO) {
		return;
	}
	
	va_list ap;
	va_start(ap, fmt);
	
	vmsg(INFO, msg, fmt, ap);
	
	va_end(ap);	
}
void Debug::warn(char *msg, char *fmt, ...) {
	if (getLevel() < WARN) {
		return;
	}
	
	va_list ap;
	va_start(ap, fmt);
	
	vmsg(WARN, msg, fmt, ap);
	
	va_end(ap);	
}
void Debug::error(char *msg, char *fmt, ...) {
	if (getLevel() < ERR) {
		return;
	}
	
	va_list ap;
	va_start(ap, fmt);
	
	vmsg(ERR, msg, fmt, ap);
	
	va_end(ap);	
}

void Debug::enter(char *method) {
	inc();
	trace("enter", ">>> %s() >>>", method);
}

void Debug::exit(char *method) {
	trace("exit", "<<< %s() <<<", method);
	dec();
}


***********/
