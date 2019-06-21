/*  =========================================================================
    lua_evaluate - Lua evaluator decorator

    Copyright (C) 2019 - 2019 Eaton

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
*/

/*
@header
    lua_evaluate - Lua evaluator decorator
@discuss
@end
*/

#include <czmq.h>
#include <fty_log.h>
#include <algorithm>

extern "C" {
#include <lualib.h>
#include <lauxlib.h>
}

#include "fty_alert_engine_classes.h"

DecoratorLuaEvaluate::~DecoratorLuaEvaluate ()
{
   if (lstate_) lua_close (lstate_);
}

void DecoratorLuaEvaluate::setGlobalVariables (const DecoratorLuaEvaluate::VariableMap vars)
{
    global_variables_.clear ();
    global_variables_ = vars;
    setGlobalVariablesToLUAStack ();
}

void DecoratorLuaEvaluate::setCode (const std::string newCode)
{
    if (lstate_) lua_close (lstate_);
    valid_ = false;
    code_.clear ();

#if LUA_VERSION_NUM > 501
    lstate_ = luaL_newstate ();
#else
    lstate_ = lua_open ();
#endif
    if (! lstate_) {
        throw cant_initiate ();
    }
    luaL_openlibs (lstate_); // get functions like print ();

    // set global variables
    setGlobalVariablesToLUAStack ();

    // set code, try to compile it
    code_ = newCode;
    int error = luaL_dostring (lstate_, code_.c_str ());
    valid_ = (error == 0);
    if (! valid_) {
        throw invalid_code ();
    }

    // check wether there is main () function
    lua_getglobal (lstate_, "main");
    if (! lua_isfunction (lstate_, lua_gettop (lstate_))) {
        // main () missing
        valid_ = false;
        throw missing_main ();
    }
}

DecoratorLuaEvaluate::VectorStrings DecoratorLuaEvaluate::evaluate (const std::vector<std::string> &arguments)
{
    if (! valid_) { throw invalid_code (); }
    lua_settop (lstate_, 0);

    lua_getglobal (lstate_, "main");
    for (const auto x: arguments) {
        lua_pushstring (lstate_, x.c_str ());
    }
    if (lua_pcall (lstate_, arguments.size (), outcome_items_, 0) != 0) {
        log_error ("Lua reported evaluation error '%s'", lua_tostring (lstate_, -1));
        throw evaluation_failed ();
    }
    DecoratorLuaEvaluate::VectorStrings result;
    for (int i = outcome_items_; i > 0; --i) {
        if (!lua_isstring (lstate_, -1 * i)) {
            throw main_returns_nonstring ();
        }
        result.push_back (lua_tostring (lstate_, -1 * i));
    }
    lua_pop (lstate_, outcome_items_);
    return result;
}

void DecoratorLuaEvaluate::setGlobalVariablesToLUAStack ()
{
    if (lstate_ == NULL) return;
    for (const auto &it : global_variables_ ) {
        lua_pushstring (lstate_, it.second.c_str ());
        lua_setglobal (lstate_, it.first.c_str ());
    }
}

//  --------------------------------------------------------------------------
//  Self test of this class

// If your selftest reads SCMed fixture data, please keep it in
// src/selftest-ro; if your test creates filesystem objects, please
// do so under src/selftest-rw.
// The following pattern is suggested for C selftest code:
//    char *filename = NULL;
//    filename = zsys_sprintf ("%s/%s", SELFTEST_DIR_RO, "mytemplate.file");
//    assert (filename);
//    ... use the "filename" for I/O ...
//    zstr_free (&filename);
// This way the same "filename" variable can be reused for many subtests.
#define SELFTEST_DIR_RO "src/selftest-ro"
#define SELFTEST_DIR_RW "src/selftest-rw"

void
lua_evaluate_test (bool verbose)
{
    printf (" * lua_evaluate: ");

    //  @selftest
    //  Simple create/destroy test
    //  @end
    printf ("OK\n");
}
